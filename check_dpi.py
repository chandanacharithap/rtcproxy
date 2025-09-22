#!/usr/bin/env python3
"""
check_dpi.py — summarize RTC media + relay IPs from a pcap

What you get
------------
- Counts: STUN / RTP / RTCP / QUIC:443
- Top UDP/8801 peers (Zoom media) with packet counts
- Top QUIC/443 peers (if app used QUIC)
- Likely relay IPs (public peers on 8801 first, else QUIC)
- Enrichment via local lookupip.py (city/region/country/ISP/etc., if that script exists)
- Best-effort PoP location inference via traceroute rDNS hints + RTT buckets
"""

import argparse
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
from collections import Counter
from typing import Dict, List, Tuple, Optional

# ---------------- utils ----------------

CITY_HINTS = {
    # EU
    "ams": "Amsterdam", "adam": "Amsterdam", "nl-ams": "Amsterdam",
    "fra": "Frankfurt", "de-fra": "Frankfurt",
    "lhr": "London", "lon": "London", "uk-lon": "London",
    "cdg": "Paris", "par": "Paris",
    "mad": "Madrid", "waw": "Warsaw", "mil": "Milan",
    "vie": "Vienna", "bru": "Brussels", "cph": "Copenhagen",
    "arn": "Stockholm", "osl": "Oslo", "hel": "Helsinki",
    "zrh": "Zurich", "dub": "Dublin",
    # US / common cloud shorthand
    "sjc": "San Jose", "sfo": "San Francisco", "lax": "Los Angeles",
    "iad": "Ashburn", "dfw": "Dallas", "ord": "Chicago", "nyc": "New York",
}

def run(cmd, timeout: int = 30) -> str:
    p = subprocess.run(cmd if isinstance(cmd, list) else shlex.split(cmd),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError(
            f"cmd failed: {cmd}\nSTDERR:\n{p.stderr.decode(errors='ignore')}"
        )
    return p.stdout.decode(errors="ignore")

def run_ok(cmd, timeout: int = 30) -> Optional[str]:
    try:
        return run(cmd, timeout=timeout)
    except Exception:
        return None

def have(bin_name: str) -> bool:
    return subprocess.run(
        ["bash", "-lc", f"command -v {shlex.quote(bin_name)} >/dev/null 2>&1"]
    ).returncode == 0

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True

# ---------------- tshark helpers ----------------

def tshark_count(pcap: str, display_filter: str, extra_args: str = "") -> int:
    cmd = f'tshark -r {shlex.quote(pcap)} {extra_args} -Y {shlex.quote(display_filter)} -T fields -e frame.number'
    out = run_ok(cmd)
    if not out:
        return 0
    return len([ln for ln in out.splitlines() if ln.strip()])

def top_counts(pcap: str, display_filter: str, field: str = "ip.dst", limit: int = 15, extra_args: str = "") -> List[Tuple[str, int]]:
    cmd = f'tshark -r {shlex.quote(pcap)} {extra_args} -Y {shlex.quote(display_filter)} -T fields -e {field}'
    out = run_ok(cmd)
    if not out:
        return []
    c = Counter([x.strip() for x in out.splitlines() if x.strip()])
    return c.most_common(limit)

# ---------------- relay picking ----------------

def pick_relays_from_media(media_peers: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    return [(ip, n) for ip, n in media_peers if not is_private_ip(ip)]

def pick_relays_from_quic(quic_peers: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    return [(ip, n) for ip, n in quic_peers if not is_private_ip(ip)]

# ---------------- location inference ----------------

def _infer_from_rdns(ip: str, media_port: int) -> Optional[str]:
    if not have("traceroute"):
        return None
    out = run_ok(f"sudo traceroute -q 1 -U -p {media_port} {ip}", timeout=25)
    if not out:
        return None
    names: List[str] = []
    for line in out.splitlines():
        m = re.search(r"^\s*\d+\s+([^\s(]+)", line)
        if not m:
            continue
        host = m.group(1).lower()
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
            continue
        names.append(host)
    for host in names[-4:]:
        for key, city in CITY_HINTS.items():
            if key in host:
                return city
    return None

def _infer_from_rtt(ip: str, media_port: int) -> Optional[str]:
    if have("mtr"):
        out = run_ok(f"mtr -uz -P {media_port} -c 10 -r {ip}", timeout=25)
        if out:
            last = out.strip().splitlines()[-1]
            ms = re.findall(r"(\d+\.\d+|\d+)\s*ms", last)
            if ms:
                try:
                    r = float(ms[-1])
                    if r < 8:   return "Same-DC/Metro"
                    if r < 20:  return "Nearby EU (NL/DE/UK)"
                    if r < 35:  return "Regional EU"
                    if r < 70:  return "In-Europe (farther)"
                    return "Intercontinental?"
                except Exception:
                    pass
    out = run_ok(f"ping -n -c 4 {ip}", timeout=10)
    if out:
        m = re.search(r"rtt min/avg/max/[a-z]+ = .*?/(\d+\.\d+)/", out)
        if m:
            try:
                r = float(m.group(1))
                if r < 8:   return "Same-DC/Metro"
                if r < 20:  return "Nearby EU (NL/DE/UK)"
                if r < 35:  return "Regional EU"
                if r < 70:  return "In-Europe (farther)"
                return "Intercontinental?"
            except Exception:
                pass
    return None

def infer_location(ip: str, media_port: int = 8801) -> Optional[str]:
    city = _infer_from_rdns(ip, media_port)
    if city:
        return city
    return _infer_from_rtt(ip, media_port)

# ---------------- enrichment ----------------

def enrich_ip(ip: str) -> Dict[str, str]:
    here = os.path.dirname(os.path.abspath(__file__))
    script = os.path.join(here, "lookupip.py")
    if not os.path.isfile(script):
        return {}
    out = run_ok(f"python3 {shlex.quote(script)} {shlex.quote(ip)}", timeout=10)
    info: Dict[str, str] = {}
    if out:
        for line in out.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                info[k.strip().lower().replace(" ", "_")] = v.strip()
    return info

# ---------------- main ----------------

def main():
    ap = argparse.ArgumentParser(description="RTC media summary & relay inference")
    ap.add_argument("--pcap", required=True, help="Path to pcap/pcapng file")
    ap.add_argument("--json", help="Optional path to write JSON summary")
    ap.add_argument("--locate-port", type=int, default=8801, help="UDP port to probe in traceroute (Zoom=8801)")
    args = ap.parse_args()

    pcap = args.pcap
    if not os.path.isfile(pcap):
        print(f"File not found: {pcap}", file=sys.stderr)
        sys.exit(2)

    print(pcap)

    # 1) Counts with forced decode for Zoom port
    counts = {
        "stun": tshark_count(pcap, "stun", extra_args="-d udp.port==8801,stun"),
        "rtp":  tshark_count(pcap, "rtp",  extra_args="-d udp.port==8801,rtp"),
        "rtcp": tshark_count(pcap, "rtcp", extra_args="-d udp.port==8801,rtcp"),
        "quic": tshark_count(pcap, "quic && udp.port==443"),
    }
    print(f"Counts: STUN={counts['stun']}  RTP={counts['rtp']}  RTCP={counts['rtcp']}  QUIC443={counts['quic']}")

    # 2) Top peers
    media_peers = top_counts(pcap, "udp.port==8801", "ip.dst", 20)
    quic_peers  = top_counts(pcap, "quic && udp.port==443", "ip.dst", 15)

    print("\nTop UDP/8801 peers (dst):")
    if media_peers:
        for ip, hits in media_peers:
            print(f"  {ip:<15}  packets={hits}")
    else:
        print("  (none)")

    if quic_peers:
        print("\nTop QUIC/443 peers (dst):")
        for ip, hits in quic_peers:
            print(f"  {ip:<15}  packets={hits}")

    # 3) Relay list
    relays = pick_relays_from_media(media_peers)
    if not relays:
        relays = pick_relays_from_quic(quic_peers)

    print("\nRelay IPs (by hits):")
    if not relays:
        print("  (none found — ensure the capture covers active media and the app used 8801/QUIC)")
    else:
        for ip, hits in relays[:10]:
            parts = []
            info = enrich_ip(ip)
            for k in ("city", "region", "country", "asn", "isp"):
                if k in info and info[k]:
                    parts.append(info[k])
            inferred = infer_location(ip, args.locate_port)
            if inferred:
                parts.append(f"inferred={inferred}")
            label = " | ".join(parts) if parts else ""
            print(f"  {ip:<15}  hits={hits}  {label}")

        print("\nThe relay IP(s): " + ", ".join([ip for ip, _ in relays[:3]]))

    # 4) Optional JSON output
    if args.json:
        out = {
            "pcap": pcap,
            "counts": counts,
            "top_udp_8801": [{"ip": ip, "hits": n} for ip, n in media_peers],
            "top_quic_443": [{"ip": ip, "hits": n} for ip, n in quic_peers],
            "relays": [
                {
                    "ip": ip,
                    "hits": hits,
                    "enrich": enrich_ip(ip),
                    "inferred_location": infer_location(ip, args.locate_port),
                }
                for ip, hits in relays[:10]
            ],
        }
        os.makedirs(os.path.dirname(args.json), exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(out, f, indent=2)
        print(f"\nWrote JSON: {args.json}")

if __name__ == "__main__":
    main()
