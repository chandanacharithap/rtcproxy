#!/usr/bin/env python3
"""
check_dpi.py — single-pcap RTC analyzer (RTP/STUN/QUIC + relay IP + PoP hint)

What it does
------------
- Counts STUN/TURN, RTP (with Zoom 8801 forced decode), RTCP, QUIC(443).
- Lists RTP flows (src -> dst, packet counts).
- Picks likely relay IPs (TURN relay range, 3478 control, udp/8801, QUIC:443, or heavy UDP peers).
- Enriches IPs via local lookupip.py if present.
- Infers PoP (city/region) by traceroute rDNS hints and RTT buckets.

Usage
-----
python3 check_dpi.py --pcap /var/log/rtc/xyz.pcap
python3 check_dpi.py --latest
python3 check_dpi.py --pcap /var/log/rtc/xyz.pcap --json /tmp/out.json
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

# --------- knobs ---------
TURN_RELAY_RANGE = (49160, 49200)      # adjust if your coturn range differs
TURN_CTRL_PORT   = 3478
ZOOM_RTP_PORTS   = [8801]              # Zoom media port
RTP_HINTS        = [5004, 8000]        # generic RTP-ish ports to try

CITY_HINTS = {
    # EU (add as needed)
    "ams": "Amsterdam", "nl-ams": "Amsterdam", "adam": "Amsterdam",
    "fra": "Frankfurt", "de-fra": "Frankfurt",
    "lhr": "London", "lon": "London", "uk-lon": "London",
    "cdg": "Paris", "par": "Paris",
    "mad": "Madrid", "mil": "Milan", "vie": "Vienna", "bru": "Brussels",
    "cph": "Copenhagen", "arn": "Stockholm", "osl": "Oslo", "hel": "Helsinki",
    "zrh": "Zurich", "dub": "Dublin",
    # US (common codes)
    "sjc": "San Jose", "sfo": "San Francisco", "lax": "Los Angeles",
    "iad": "Ashburn", "dfw": "Dallas", "ord": "Chicago", "nyc": "New York",
}

# --------- shell helpers ---------
def run(cmd: str, timeout: int = 30) -> str:
    p = subprocess.run(
        cmd if isinstance(cmd, list) else shlex.split(cmd),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout
    )
    if p.returncode != 0:
        raise RuntimeError(f"cmd failed: {cmd}\nSTDERR:\n{p.stderr.decode(errors='ignore')}")
    return p.stdout.decode(errors='ignore')

def run_ok(cmd: str, timeout: int = 30) -> Optional[str]:
    try:
        return run(cmd, timeout=timeout)
    except Exception:
        return None

def have(tool: str) -> bool:
    return subprocess.run(["bash","-lc", f"command -v {shlex.quote(tool)} >/dev/null 2>&1"]).returncode == 0

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True

# --------- pcap helpers (tshark) ---------
def count_filter(pcap: str, disp: str) -> int:
    out = run_ok(f'tshark -r {shlex.quote(pcap)} -Y {shlex.quote(disp)} -T fields -e frame.number')
    if not out:
        return 0
    s = out.strip()
    return 0 if not s else len(s.splitlines())

def ip_pairs(pcap: str, disp: str) -> List[Tuple[str,str]]:
    out = run_ok(f'tshark -r {shlex.quote(pcap)} -Y {shlex.quote(disp)} -T fields -e ip.src -e ip.dst')
    if not out:
        return []
    pairs = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] and parts[1]:
            pairs.append((parts[0].strip(), parts[1].strip()))
    return pairs

def _decode_as_rtp_count(pcap: str, port: int) -> int:
    out = run_ok(f'tshark -r {shlex.quote(pcap)} -d udp.port=={port},rtp -Y rtp -T fields -e frame.number')
    if not out:
        return 0
    s = out.strip()
    return 0 if not s else len(s.splitlines())

def _decode_as_rtp_pairs(pcap: str, port: int) -> List[Tuple[str,str]]:
    out = run_ok(f'tshark -r {shlex.quote(pcap)} -d udp.port=={port},rtp -Y rtp -T fields -e ip.src -e ip.dst')
    if not out:
        return []
    pairs = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] and parts[1]:
            pairs.append((parts[0].strip(), parts[1].strip()))
    return pairs

def count_rtp_with_hints(pcap: str) -> int:
    n = count_filter(pcap, "rtp")
    if n > 0:
        return n
    for p in list(dict.fromkeys(ZOOM_RTP_PORTS + RTP_HINTS)):
        n = _decode_as_rtp_count(pcap, p)
        if n > 0:
            return n
    return 0

def rtp_pairs_with_hints(pcap: str) -> List[Tuple[str,str]]:
    pairs = ip_pairs(pcap, "rtp")
    if pairs:
        return pairs
    for p in list(dict.fromkeys(ZOOM_RTP_PORTS + RTP_HINTS)):
        pairs = _decode_as_rtp_pairs(pcap, p)
        if pairs:
            return pairs
    return []

def conv_table_udp_top_ips(pcap: str) -> List[Tuple[str,int]]:
    out = run_ok(f'tshark -r {shlex.quote(pcap)} -q -z conv,udp')
    if not out:
        return []
    frames_by_ip: Counter = Counter()
    for line in out.splitlines():
        if "<->" not in line or ":" not in line:
            continue
        try:
            left, right = line.split("<->")
            left = left.strip().split()[0]    # "IP:port"
            right = right.strip().split()[0]
            def ep_ip(ep: str) -> Optional[str]:
                m = re.match(r"(\d+\.\d+\.\d+\.\d+):\d+", ep)
                return m.group(1) if m else None
            a, b = ep_ip(left), ep_ip(right)
            m2 = re.findall(r"\s(\d+)\s+[0-9A-Za-z]+\s*$", line)
            frames = int(m2[-1][0]) if m2 else 0
            if frames <= 0 or not a or not b:
                continue
            # count non-private peer(s)
            for ip in (a,b):
                if not is_private_ip(ip):
                    frames_by_ip[ip] += frames
        except Exception:
            pass
    return [(ip, n) for ip, n in frames_by_ip.most_common()]

# --------- relay picking ---------
def pick_relays(pcap: str) -> Dict[str, int]:
    cand: Counter = Counter()

    # TURN relay UDP ports
    for s,d in ip_pairs(pcap, f"udp && udp.port>={TURN_RELAY_RANGE[0]} && udp.port<={TURN_RELAY_RANGE[1]}"):
        for ip in (s,d):
            if not is_private_ip(ip):
                cand[ip] += 10

    # TURN control (UDP/TCP 3478)
    for disp in (f"udp.port=={TURN_CTRL_PORT}", f"tcp.port=={TURN_CTRL_PORT}"):
        for s,d in ip_pairs(pcap, disp):
            for ip in (s,d):
                if not is_private_ip(ip):
                    cand[ip] += 5

    # Zoom media port (udp/8801) — strong signal
    for s,d in ip_pairs(pcap, "udp.port==8801"):
        for ip in (s,d):
            if not is_private_ip(ip):
                cand[ip] += 10

    if cand:
        return dict(cand)

    # QUIC 443
    for s,d in ip_pairs(pcap, "quic && udp.port==443"):
        for ip in (s,d):
            if not is_private_ip(ip):
                cand[ip] += 3

    if cand:
        return dict(cand)

    # Fallback: heavy UDP peers
    for ip, frames in conv_table_udp_top_ips(pcap):
        if ip in ("1.1.1.1","1.0.0.1","8.8.8.8"):
            continue
        cand[ip] += max(1, min(frames // 50, 5))

    return dict(cand)

# --------- location inference ---------
def _infer_from_rdns(ip: str, media_port: int) -> Optional[str]:
    if not have("traceroute"):
        return None
    # UDP traceroute to media port, allow rDNS (no -n)
    out = run_ok(f"sudo traceroute -q 1 -U -p {media_port} {ip}", timeout=30)
    if not out:
        return None
    names = []
    for line in out.splitlines():
        m = re.match(r"^\s*\d+\s+([^\s(]+)", line)
        if not m:
            continue
        host = m.group(1).lower()
        # ignore raw IP-only hopnames
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
        out = run_ok(f"mtr -uz -P {media_port} -c 10 -r {ip}", timeout=30)
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
                except:
                    pass
    out = run_ok(f"ping -n -c 4 {ip}", timeout=12)
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
            except:
                pass
    return None

def infer_location(ip: str, media_port: int = 8801) -> Optional[str]:
    city = _infer_from_rdns(ip, media_port)
    if city:
        return city
    return _infer_from_rtt(ip, media_port)

# --------- enrichment ---------
def enrich_ip(ip: str) -> Dict[str, str]:
    ret = {"ip": ip}
    here = os.path.dirname(os.path.abspath(__file__))
    script = os.path.join(here, "lookupip.py")
    if os.path.isfile(script):
        out = run_ok(f"python3 {shlex.quote(script)} {shlex.quote(ip)}", timeout=10)
        if out:
            for line in out.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    ret[k.strip().lower().replace(" ", "_")] = v.strip()
    return ret

# --------- latest helper ---------
def latest_pcap(default_dir: str = "/var/log/rtc") -> Optional[str]:
    out = run_ok(f'ls -t {shlex.quote(default_dir)}/rtc-*.pcap 2>/dev/null | head -n 1', timeout=5)
    if not out:
        return None
    return out.strip().splitlines()[0]

# --------- main ---------
def main():
    ap = argparse.ArgumentParser(description="Detect RTC relays, RTP, and infer relay location (PoP).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--pcap", help="Path to pcap file")
    g.add_argument("--latest", action="store_true", help="Analyze the newest /var/log/rtc/rtc-*.pcap")
    ap.add_argument("--json", help="Write JSON summary to this path")
    ap.add_argument("--locate-port", type=int, default=8801, help="UDP port to probe for PoP (Zoom=8801)")
    args = ap.parse_args()

    if not have("tshark"):
        print("ERROR: tshark is not installed (sudo apt-get install -y tshark)", file=sys.stderr)
        sys.exit(2)

    if args.latest:
        pcap = latest_pcap()
        if not pcap:
            print("No pcap files found in /var/log/rtc", file=sys.stderr)
            sys.exit(2)
    else:
        pcap = args.pcap

    if not os.path.isfile(pcap):
        print(f"File not found: {pcap}", file=sys.stderr)
        sys.exit(2)

    print(pcap)

    counts = {
        "stun": count_filter(pcap, "stun"),
        "rtp":  count_rtp_with_hints(pcap),
        "rtcp": count_filter(pcap, "rtcp"),
        "quic": count_filter(pcap, "quic && udp.port==443"),
    }
    print(f"Counts: STUN={counts['stun']}  RTP={counts['rtp']}  RTCP={counts['rtcp']}  QUIC443={counts['quic']}")

    # RTP flows
    rtp_pairs = rtp_pairs_with_hints(pcap)
    if rtp_pairs:
        print("\nRTP Flows (most->least):")
        c = Counter(rtp_pairs)
        for (s,d), n in c.most_common(20):
            print(f"  {s:<15} -> {d:<15}  packets={n}")
    else:
        print("\nRTP Flows (most->least):\n  (none)")

    # Relay picking
    relay_scores = pick_relays(pcap)
    relay_sorted = sorted(relay_scores.items(), key=lambda kv: kv[1], reverse=True)
    relay_ips = [ip for ip,_ in relay_sorted]

    print("\nRelay IPs (by score):")
    if not relay_ips:
        print("  (none found — try a longer capture on eth0 while the call is active)")
    else:
        for ip, score in relay_sorted[:10]:
            info = enrich_ip(ip)
            label = []
            for k in ("city","region","country","asn","isp"):
                if k in info and info[k]:
                    label.append(info[k])
            inferred = infer_location(ip, media_port=args.locate_port)
            if inferred:
                label.append(f"inferred={inferred}")
            label_str = " | ".join(label) if label else ""
            print(f"  {ip:<15}  score={score}  {label_str}")
        print("\nThe relay IP(s): " + ", ".join(relay_ips[:3]))

    if args.json:
        out = {
            "pcap": pcap,
            "counts": counts,
            "rtp_pairs_top": [{"src": s, "dst": d, "packets": n} for (s,d), n in Counter(rtp_pairs).most_common(50)],
            "relays": [
                {
                    "ip": ip,
                    "score": score,
                    "enrich": enrich_ip(ip),
                    "inferred_location": infer_location(ip, media_port=args.locate_port),
                }
                for ip,score in relay_sorted[:20]
            ],
        }
        os.makedirs(os.path.dirname(args.json), exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(out, f, indent=2)
        print(f"\nWrote JSON: {args.json}")

if __name__ == "__main__":
    main()
