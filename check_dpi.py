#!/usr/bin/env python3
"""
check_dpi.py — simple relay detector for RTC pcaps

What it does
------------
- Counts STUN/TURN, RTP, RTCP, and QUIC/443 frames in the pcap (via tshark).
- Prints top UDP destination IPs (public) to help spot relays when traffic is
  not classic RTP (e.g., Zoom/WhatsApp QUIC or app-proprietary UDP).
- Picks likely relay IPs using this order:
    1) UDP relay range 49160–49200 (TURN media)
    2) TURN control on 3478 (UDP/TCP)
    3) QUIC on UDP/443
    4) Fallback: heaviest UDP conversation peers (public)
- Enriches relay IPs with geo/ASN using local lookupip.py if present.

Usage
-----
python3 check_dpi.py --pcap /var/log/rtc/xyz.pcap
python3 check_dpi.py --latest
python3 check_dpi.py --pcap /var/log/rtc/xyz.pcap --json /var/log/rtc/xyz_summary.json
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

TURN_RELAY_RANGE = (49160, 49200)   # your coturn media ports (adjust if different)
TURN_CTRL_PORT   = 3478

# ---------- shell helpers ----------

def run(cmd: str) -> str:
    """Run a shell command and return stdout as UTF-8 string. Raise on non-zero exit."""
    proc = subprocess.run(
        shlex.split(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"cmd failed: {cmd}\nSTDERR:\n{proc.stderr.decode(errors='ignore')}"
        )
    return proc.stdout.decode(errors='ignore')

def tshark_available() -> bool:
    try:
        out = run("tshark -v")
        return bool(out)
    except Exception:
        return False

# ---------- utils ----------

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        # If parsing fails, exclude it as a relay candidate
        return True

def my_nic_ip(pcap_hint: Optional[str] = None) -> Optional[str]:
    """Best-effort: detect the VM's IP on common NIC names to attribute conv rows."""
    for nic in ("eth0", "ens160", "ens33"):
        try:
            out = run(f"ip -4 addr show {nic}")
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/", out)
            if m:
                return m.group(1)
        except Exception:
            pass
    return None

def latest_pcap(default_dir: str = "/var/log/rtc", pattern: str = "rtc-*.pcap") -> Optional[str]:
    """Return path to most recent pcap matching pattern in default_dir."""
    try:
        out = run(f"bash -lc 'ls -t {shlex.quote(default_dir)}/{shlex.quote(pattern)} 2>/dev/null | head -n 1'")
        p = out.strip()
        return p if p else None
    except Exception:
        return None

# ---------- tshark wrappers ----------

def count_filter(pcap: str, display_filter: str) -> int:
    """
    Count frames matching a tshark display filter.
    """
    cmd = f'tshark -r {shlex.quote(pcap)} -Y {shlex.quote(display_filter)} -T fields -e frame.number'
    try:
        out = run(cmd)
    except RuntimeError:
        return 0
    s = out.strip()
    return 0 if not s else len(s.splitlines())

def ip_pairs(pcap: str, display_filter: str) -> List[Tuple[str, str]]:
    """
    Return [(ip.src, ip.dst), ...] for frames matching the filter.
    """
    cmd = f'tshark -r {shlex.quote(pcap)} -Y {shlex.quote(display_filter)} -T fields -e ip.src -e ip.dst'
    try:
        out = run(cmd)
    except RuntimeError:
        return []
    pairs: List[Tuple[str, str]] = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            s, d = parts[0].strip(), parts[1].strip()
            if s and d:
                pairs.append((s, d))
    return pairs

def conv_table_udp_other_ips(pcap: str) -> Counter:
    """
    Use tshark conv,udp and attribute 'other side' relative to this host IP
    to count frames per peer (public only). Returns Counter[ip]=frames.
    """
    cmd = f'tshark -r {shlex.quote(pcap)} -q -z conv,udp'
    try:
        out = run(cmd)
    except RuntimeError:
        return Counter()

    rows = []
    for line in out.splitlines():
        if "<->" in line and ":" in line:
            try:
                left, right = line.split("<->")
                left = left.strip().split()[0]   # "IP:port"
                right = right.strip().split()[0]
                def ip_of(ep: str) -> Optional[str]:
                    m = re.match(r"(\d+\.\d+\.\d+\.\d+):\d+", ep)
                    return m.group(1) if m else None
                l_ip, r_ip = ip_of(left), ip_of(right)
                # Extract the trailing "frames" count (best-effort)
                m2 = re.findall(r"\s(\d+)\s+[0-9A-Za-z]+?\s*$", line)
                frames_total = int(m2[-1][0]) if m2 else 0
                if l_ip and r_ip:
                    rows.append(((l_ip, r_ip), frames_total))
            except Exception:
                pass

    myip = my_nic_ip()
    c = Counter()
    for (a, b), frames in rows:
        if myip:
            other = b if a == myip else a if b == myip else None
        else:
            # Unknown local IP—just pick the public one if exactly one is public
            if not is_private_ip(a) and is_private_ip(b):
                other = a
            elif not is_private_ip(b) and is_private_ip(a):
                other = b
            else:
                other = None
        if other and not is_private_ip(other):
            c[other] += frames
    return c

def top_udp_dests(pcap: str, limit: int = 10) -> List[Tuple[str, int]]:
    """
    Return top UDP destination IPs (public only) by hit count.
    """
    cmd = f'tshark -r {shlex.quote(pcap)} -Y udp -T fields -e ip.dst'
    try:
        out = run(cmd)
    except RuntimeError:
        return []
    c = Counter()
    for line in out.splitlines():
        ip = line.strip()
        if ip and not is_private_ip(ip):
            c[ip] += 1
    return c.most_common(limit)

# ---------- relay picking ----------

def pick_relays(pcap: str) -> Dict[str, int]:
    """
    Return dict ip->score for likely relay IPs in this pcap.
    Strategy:
      1) Any IP seen on UDP relay range (49160–49200) -> strong weight
      2) Any IP seen on TURN control port 3478 (UDP/TCP) -> medium weight
      3) QUIC peers on UDP/443 -> medium-low weight
      4) Fallback: heavy UDP conversation peers -> low weight
    """
    candidates: Counter = Counter()

    # 1) Relay media range
    relay_pairs = ip_pairs(pcap, f"udp && udp.port>={TURN_RELAY_RANGE[0]} && udp.port<={TURN_RELAY_RANGE[1]}")
    for s, d in relay_pairs:
        for ip in (s, d):
            if not is_private_ip(ip):
                candidates[ip] += 10

    # 2) TURN control
    for filt in (f"udp.port=={TURN_CTRL_PORT}", f"tcp.port=={TURN_CTRL_PORT}"):
        pairs = ip_pairs(pcap, filt)
        for s, d in pairs:
            for ip in (s, d):
                if not is_private_ip(ip):
                    candidates[ip] += 5

    if candidates:
        return dict(candidates)

    # 3) QUIC on 443
    quic_pairs = ip_pairs(pcap, "quic && udp.port==443")
    for s, d in quic_pairs:
        for ip in (s, d):
            if not is_private_ip(ip):
                candidates[ip] += 3

    if candidates:
        return dict(candidates)

    # 4) Fallback: heavy UDP conv peers
    conv = conv_table_udp_other_ips(pcap)
    for ip, frames in conv.items():
        if ip in ("1.1.1.1", "8.8.8.8"):  # ignore obvious DNS resolvers
            continue
        candidates[ip] += max(1, min(frames // 50, 5))

    return dict(candidates)

# ---------- enrichment ----------

def enrich_ip(ip: str) -> Dict[str, str]:
    """
    Use local lookupip.py (in same dir) to add geo/ASN where available.
    """
    ret = {"ip": ip}
    here = os.path.dirname(os.path.abspath(__file__))
    script = os.path.join(here, "lookupip.py")
    if os.path.isfile(script):
        try:
            out = run(f"python3 {shlex.quote(script)} {shlex.quote(ip)}")
            for line in out.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    ret[k.strip().lower().replace(" ", "_")] = v.strip()
        except Exception as e:
            ret["lookup_error"] = str(e)
    return ret

# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description="Detect relay IPs in a pcap (RTP/STUN/TURN/QUIC aware).")
    ap.add_argument("--pcap", help="Path to pcap file")
    ap.add_argument("--latest", action="store_true", help="Use newest /var/log/rtc/rtc-*.pcap automatically")
    ap.add_argument("--json", help="Optional path to write JSON summary")
    args = ap.parse_args()

    if not tshark_available():
        print("ERROR: tshark is not installed (sudo apt-get install -y tshark)", file=sys.stderr)
        sys.exit(2)

    # Resolve target pcap
    pcap: Optional[str] = None
    if args.latest:
        pcap = latest_pcap()
        if not pcap:
            print("No pcap files found under /var/log/rtc.", file=sys.stderr)
            sys.exit(2)
    elif args.pcap:
        pcap = args.pcap

    if not pcap or not os.path.isfile(pcap):
        print(f"File not found: {pcap!r}", file=sys.stderr)
        sys.exit(2)

    print(pcap)

    # Basic counts
    counts = {
        "stun": count_filter(pcap, "stun"),
        "rtp":  count_filter(pcap, "rtp"),
        "rtcp": count_filter(pcap, "rtcp"),
        "quic": count_filter(pcap, "quic && udp.port==443"),
    }
    print(f"Counts: STUN={counts['stun']}  RTP={counts['rtp']}  RTCP={counts['rtcp']}  QUIC443={counts['quic']}")

    # RTP flows
    rtp_pairs = ip_pairs(pcap, "rtp")
    rtp_counter = Counter()
    for s, d in rtp_pairs:
        rtp_counter[(s, d)] += 1
    if rtp_counter:
        print("\nRTP Flows (most->least):")
        for (s, d), n in rtp_counter.most_common(12):
            print(f"  {s:<15} -> {d:<15}  packets={n}")
    else:
        print("\nRTP Flows (most->least):\n  (none)")

    # Show top UDP destination IPs always (helps when RTP=0)
    udp_top = top_udp_dests(pcap, limit=10)
    if udp_top:
        print("\nTop UDP destination IPs (public):")
        for ip, hits in udp_top:
            print(f"  {ip:<15} hits={hits}")

    # Relay picking
    relay_scores = pick_relays(pcap)
    relay_sorted = sorted(relay_scores.items(), key=lambda kv: kv[1], reverse=True)
    relay_ips = [ip for ip, _ in relay_sorted]

    # If heuristics above found nothing, fall back to UDP top
    if not relay_ips and udp_top:
        relay_sorted = [(ip, hits) for ip, hits in udp_top]
        relay_ips = [ip for ip, _ in udp_top]

    print("\nRelay IPs (by score):")
    if not relay_ips:
        print("  (none found — try a longer capture and ensure both ends traverse your VPN/TURN)")
    else:
        for ip, score in relay_sorted[:10]:
            info = enrich_ip(ip)
            label = []
            for k in ("city", "region", "country", "asn"):
                if k in info and info[k]:
                    label.append(info[k])
            label_str = " | ".join(label) if label else ""
            print(f"  {ip:<15}  score={score}  {label_str}")

        print("\nThe relay IP(s): " + ", ".join(relay_ips[:3]))

    # Optional JSON out
    if args.json:
        out = {
            "pcap": pcap,
            "counts": counts,
            "rtp_pairs_top": [{"src": s, "dst": d, "packets": n} for (s, d), n in rtp_counter.most_common(20)],
            "udp_dsts_top": [{"ip": ip, "hits": hits} for ip, hits in udp_top],
            "relays": [{"ip": ip, "score": score, "enrich": enrich_ip(ip)} for ip, score in relay_sorted[:10]],
        }
        try:
            os.makedirs(os.path.dirname(args.json), exist_ok=True)
        except Exception:
            pass
        with open(args.json, "w") as f:
            json.dump(out, f, indent=2)
        print(f"\nWrote JSON: {args.json}")

if __name__ == "__main__":
    main()
