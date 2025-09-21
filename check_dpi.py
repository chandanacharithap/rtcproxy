#!/usr/bin/env python3
"""
check_dpi.py — relay detector + (best-effort) location inference

What it does
------------
- Counts STUN/TURN, RTP, and QUIC traffic in the pcap.
- Picks likely relay IPs (TURN relay ports, TURN ctrl 3478, QUIC:443, or top UDP peers).
- Enriches IPs (if lookupip.py exists).
- NEW: infers the *actual* relay region via UDP traceroute rDNS and RTT heuristics.

Usage
-----
python3 check_dpi.py --pcap /var/log/rtc/zoom_all.pcap
python3 check_dpi.py --pcap /var/log/rtc/zoom_all.pcap --json /tmp/out.json
python3 check_dpi.py --pcap /var/log/rtc/zoom_all.pcap --locate-port 8801
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

# ---------- small utils ----------

def run(cmd: str, timeout: int = 20) -> str:
    p = subprocess.run(
        cmd if isinstance(cmd, list) else shlex.split(cmd),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout
    )
    if p.returncode != 0:
        raise RuntimeError(f"cmd failed: {cmd}\nSTDERR:\n{p.stderr.decode(errors='ignore')}")
    return p.stdout.decode(errors='ignore')

def run_ok(cmd: str, timeout: int = 20) -> Optional[str]:
    try:
        return run(cmd, timeout=timeout)
    except Exception:
        return None

def have(cmd: str) -> bool:
    return subprocess.run(["bash","-lc", f"command -v {shlex.quote(cmd)} >/dev/null 2>&1"]).returncode == 0

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True

def tshark_available() -> bool:
    return have("tshark")

def my_nic_ip() -> Optional[str]:
    for nic in ("eth0", "ens33", "ens160"):
        out = run_ok(f"ip -4 addr show {nic}")
        if not out:
            continue
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/", out)
        if m:
            return m.group(1)
    return None

# ---------- tshark helpers ----------

def count_filter(pcap: str, display_filter: str) -> int:
    out = run_ok(f'tshark -r {shlex.quote(pcap)} -Y {shlex.quote(display_filter)} -T fields -e frame.number')
    if not out:
        return 0
    s = out.strip()
    return 0 if not s else len(s.splitlines())

def ip_pairs(pcap: str, display_filter: str) -> List[Tuple[str,str]]:
    out = run_ok(f'tshark -r {shlex.quote(pcap)} -Y {shlex.quote(display_filter)} -T fields -e ip.src -e ip.dst')
    if not out:
        return []
    pairs = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] and parts[1]:
            pairs.append((parts[0].strip(), parts[1].strip()))
    return pairs

def conv_table_udp_top_ips(pcap: str) -> List[Tuple[str,int]]:
    out = run_ok(f'tshark -r {shlex.quote(pcap)} -q -z conv,udp')
    if not out:
        return []
    myip = my_nic_ip()
    frames_by_ip: Counter = Counter()
    for line in out.splitlines():
        if "<->" not in line or ":" not in line:
            continue
        try:
            left, right = line.split("<->")
            left = left.strip().split()[0]
            right = right.strip().split()[0]
            def ep_ip(ep: str) -> Optional[str]:
                m = re.match(r"(\d+\.\d+\.\d+\.\d+):\d+", ep)
                return m.group(1) if m else None
            a, b = ep_ip(left), ep_ip(right)
            m2 = re.findall(r"\s(\d+)\s+[0-9A-Za-z]+\s*$", line)
            frames = int(m2[-1][0]) if m2 else 0
            if frames <= 0 or not a or not b:
                continue
            if myip:
                other = b if a == myip else a if b == myip else None
            else:
                other = b if not is_private_ip(b) else a if not is_private_ip(a) else None
            if other and not is_private_ip(other):
                frames_by_ip[other] += frames
        except Exception:
            pass
    return [(ip, n) for ip, n in frames_by_ip.most_common()]

# ---------- relay picking ----------

TURN_RELAY_RANGE = (49160, 49200)
TURN_CTRL_PORT = 3478

def pick_relays(pcap: str) -> Dict[str, int]:
    cand: Counter = Counter()

    # 1) Known relay ports (TURN data)
    rel = ip_pairs(pcap, f"udp && udp.port>={TURN_RELAY_RANGE[0]} && udp.port<={TURN_RELAY_RANGE[1]}")
    for s,d in rel:
        for ip in (s,d):
            if not is_private_ip(ip):
                cand[ip] += 10

    # 2) TURN control 3478 (udp/tcp)
    for disp in (f"udp.port=={TURN_CTRL_PORT}", f"tcp.port=={TURN_CTRL_PORT}"):
        pairs = ip_pairs(pcap, disp)
        for s,d in pairs:
            for ip in (s,d):
                if not is_private_ip(ip):
                    cand[ip] += 5
    if cand:
        return dict(cand)

    # 3) QUIC:443
    for s,d in ip_pairs(pcap, "quic && udp.port==443"):
        for ip in (s,d):
            if not is_private_ip(ip):
                cand[ip] += 3
    if cand:
        return dict(cand)

    # 4) Fallback: heavy UDP peers
    for ip, frames in conv_table_udp_top_ips(pcap):
        if ip in ("1.1.1.1","1.0.0.1","8.8.8.8"):
            continue
        cand[ip] += max(1, min(frames // 50, 5))
    return dict(cand)

# ---------- location inference ----------

CITY_HINTS = {
    # EU (add more if you like)
    "ams": "Amsterdam", "adam": "Amsterdam", "nl-ams": "Amsterdam",
    "fra": "Frankfurt", "de-fra": "Frankfurt",
    "lhr": "London", "lon": "London", "uk-lon": "London",
    "cdg": "Paris", "par": "Paris",
    "waw": "Warsaw", "mad": "Madrid", "mil": "Milan",
    "vie": "Vienna", "bru": "Brussels", "cph": "Copenhagen",
    "arn": "Stockholm", "osl": "Oslo", "hel": "Helsinki",
    "zrh": "Zurich", "dub": "Dublin",
    # US (common Zoom/Cloud names)
    "sjc": "San Jose", "sfo": "San Francisco", "lax":"Los Angeles",
    "iad": "Ashburn", "dfw":"Dallas", "ord":"Chicago", "nyc":"New York",
}

def _infer_from_rdns(ip: str, media_port: int) -> Optional[str]:
    """
    Run UDP traceroute with rDNS and try to read city codes in the last 3 resolved hopnames.
    """
    if not have("traceroute"):
        return None
    # rDNS on (no -n), UDP to media port
    out = run_ok(f"sudo traceroute -q 1 -U -p {media_port} {ip}", timeout=25)
    if not out:
        return None
    names = []
    for line in out.splitlines():
        # example:  8  ae-1-350.ams10.core.example.net (203.0.113.1)  12.3 ms
        m = re.search(r"^\s*\d+\s+([^\s(]+)", line)
        if m:
            host = m.group(1).lower()
            # ignore pure IPs
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                continue
            names.append(host)
    for host in names[-4:]:  # last few hops near the target
        for key, city in CITY_HINTS.items():
            if key in host:
                return city
    return None

def _infer_from_rtt(ip: str, media_port: int) -> Optional[str]:
    """
    Use mtr or ping RTT as a rough region hint.
    """
    # mtr in report mode (no curses)
    if have("mtr"):
        out = run_ok(f"mtr -uz -P {media_port} -c 10 -r {ip}", timeout=25)
        if out:
            # find last hop avg or last line latency
            last = out.strip().splitlines()[-1]
            ms = re.findall(r"(\d+\.\d+|\d+)\s*ms", last)
            if ms:
                try:
                    r = float(ms[-1])
                    # very rough EU buckets (tweak for your AZ region)
                    if r < 8:   return "Same-DC/Metro"
                    if r < 20:  return "Nearby EU (NL/DE/UK)"
                    if r < 35:  return "Regional EU"
                    if r < 70:  return "In-Europe (farther)"
                    return "Intercontinental?"
                except:
                    pass
    # ping fallback
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
            except:
                pass
    return None

def infer_location(ip: str, media_port: int = 8801) -> Optional[str]:
    # 1) try hopnames
    city = _infer_from_rdns(ip, media_port)
    if city:
        return city
    # 2) try RTT buckets
    return _infer_from_rtt(ip, media_port)

# ---------- enrich ----------

def enrich_ip(ip: str) -> Dict[str, str]:
    ret = {"ip": ip}
    here = os.path.dirname(os.path.abspath(__file__))
    script = os.path.join(here, "lookupip.py")
    if os.path.isfile(script):
        out = run_ok(f"python3 {shlex.quote(script)} {shlex.quote(ip)}")
        if out:
            for line in out.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    ret[k.strip().lower().replace(" ", "_")] = v.strip()
    return ret

# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description="Detect RTC relays and infer their real location.")
    ap.add_argument("--pcap", required=True, help="Path to pcap file")
    ap.add_argument("--json", help="Optional path to write JSON summary")
    ap.add_argument("--locate-port", type=int, default=8801, help="UDP port to probe for location inference (Zoom=8801)")
    args = ap.parse_args()

    if not tshark_available():
        print("ERROR: tshark is not installed (apt-get install tshark)", file=sys.stderr)
        sys.exit(2)

    pcap = args.pcap
    if not os.path.isfile(pcap):
        print(f"File not found: {pcap}", file=sys.stderr)
        sys.exit(2)

    print(pcap)

    counts = {
        "stun": count_filter(pcap, "stun"),
        "rtp":  count_filter(pcap, "rtp"),
        "rtcp": count_filter(pcap, "rtcp"),
        "quic": count_filter(pcap, "quic && udp.port==443"),
    }
    print(f"Counts: STUN={counts['stun']}  RTP={counts['rtp']}  RTCP={counts['rtcp']}  QUIC443={counts['quic']}")

    rtp_pairs = ip_pairs(pcap, "rtp")
    rtp_counter: Counter = Counter()
    for s,d in rtp_pairs:
        rtp_counter[(s,d)] += 1
    if rtp_counter:
        print("\nRTP Flows (most->least):")
        for (s,d), n in rtp_counter.most_common(12):
            print(f"  {s:<15} -> {d:<15}  packets={n}")
    else:
        print("\nRTP Flows (most->least):\n  (none)")

    # Relay picking
    relay_scores = pick_relays(pcap)
    relay_sorted = sorted(relay_scores.items(), key=lambda kv: kv[1], reverse=True)
    relay_ips = [ip for ip,_ in relay_sorted]

    print("\nRelay IPs (by score):")
    if not relay_ips:
        print("  (none found — try longer capture, ensure both ends traverse your VPN/TURN)")
    else:
        for ip, score in relay_sorted[:10]:
            info = enrich_ip(ip)
            label = []
            for k in ("city","region","country","asn"):
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
            "rtp_pairs_top": [{"src": s, "dst": d, "packets": n} for (s,d), n in rtp_counter.most_common(20)],
            "relays": [
                {
                    "ip": ip,
                    "score": score,
                    "enrich": enrich_ip(ip),
                    "inferred_location": infer_location(ip, media_port=args.locate_port)
                }
                for ip,score in relay_sorted[:10]
            ],
        }
        os.makedirs(os.path.dirname(args.json), exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(out, f, indent=2)
        print(f"\nWrote JSON: {args.json}")

if __name__ == "__main__":
    main()
