#!/usr/bin/env python3
"""
check_dpi.py  —  simple relay detector for RTC pcaps

What it does
------------
- Counts STUN/TURN, RTP, and QUIC traffic in the pcap.
- Finds likely relay IPs:
  1) Anything on TURN relay ports (UDP 49160–49200) or TURN control (UDP/TCP 3478).
  2) If no TURN, the heaviest QUIC peers (UDP/443).
  3) Fallback: top non-private peers seen in UDP flows.

- Enriches relay IPs with geo/ASN via local lookupip.py (same directory).

Usage
-----
python3 check_dpi.py --pcap /var/log/rtc/zoom_all.pcap
python3 check_dpi.py --pcap /var/log/rtc/zoom_all.pcap --json dpi_found/zoom_all_summary.json
"""

import argparse
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Set, Optional

# -------- helpers --------

def run(cmd: str) -> str:
    """Run a shell command, return stdout (UTF-8). Raise on non-zero."""
    proc = subprocess.run(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise RuntimeError(f"cmd failed: {cmd}\nSTDERR:\n{proc.stderr.decode(errors='ignore')}")
    return proc.stdout.decode(errors='ignore')

def tshark_available() -> bool:
    try:
        run("tshark -v")
        return True
    except Exception:
        return False

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True  # if parsing fails, treat as non-candidate

def my_nic_ip(pcap_hint: Optional[str]=None) -> Optional[str]:
    # Try to detect VM NIC IP (eth0 typical on Azure)
    for nic in ("eth0", "ens33", "ens160"):
        try:
            out = run(f"ip -4 addr show {nic}")
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/", out)
            if m:
                return m.group(1)
        except Exception:
            pass
    return None

# -------- analyzers (tshark) --------

def count_filter(pcap: str, display_filter: str) -> int:
    """Count frames matching a tshark display filter."""
    cmd = f'tshark -r {shlex.quote(pcap)} -Y {shlex.quote(display_filter)} -T fields -e frame.number'
    try:
        out = run(cmd)
    except RuntimeError:
        return 0
    if not out.strip():
        return 0
    return len(out.strip().splitlines())

def ip_pairs(pcap: str, display_filter: str) -> List[Tuple[str,str]]:
    """Return (src,dst) ip pairs for a filter."""
    cmd = f'tshark -r {shlex.quote(pcap)} -Y {shlex.quote(display_filter)} -T fields -e ip.src -e ip.dst'
    try:
        out = run(cmd)
    except RuntimeError:
        return []
    pairs = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            s, d = parts[0].strip(), parts[1].strip()
            if s and d:
                pairs.append((s, d))
    return pairs

def conv_table(pcap: str, which: str) -> List[Tuple[str,int,int]]:
    """
    Parse tshark conversation table.
    which = 'udp' or 'tcp'
    Returns list of (peer_ip, frames_total, bytes_total) from perspective of the VM (best-effort).
    """
    out = run(f'tshark -r {shlex.quote(pcap)} -q -z conv,{which}')
    # Collect lines like:
    # "A.B.C.D:port   <->   E.F.G.H:port   frames bytes ..."
    rows = []
    for line in out.splitlines():
        if ":" in line and "<->" in line:
            # Extract endpoints
            try:
                left, right = line.split("<->")
                left = left.strip().split()[0]       # "IP:port"
                right = right.strip().split()[0]
                def ip_of(ep: str) -> Optional[str]:
                    m = re.match(r"(\d+\.\d+\.\d+\.\d+):\d+", ep)
                    return m.group(1) if m else None
                l_ip, r_ip = ip_of(left), ip_of(right)
                # Extract frames/bytes at line end
                m2 = re.findall(r"\s(\d+)\s+([0-9A-Za-z]+)\s*$", line)
                frames_total, bytes_total = 0, 0
                if m2:
                    try:
                        frames_total = int(m2[-1][0])
                    except:
                        pass
                # We won’t rely on bytes_total parsing (units vary); frames is fine for ranking
                if l_ip and r_ip:
                    rows.append(((l_ip, r_ip), frames_total))
            except Exception:
                pass
    # Reduce into per-peer frames, ignoring private IPs
    frames_by_ip = Counter()
    myip = my_nic_ip()
    for (a, b), frames in rows:
        if myip:
            other = b if a == myip else a if b == myip else None
        else:
            # If we don't know our NIC IP, just count non-private public peers
            other = b if not is_private_ip(b) else a if not is_private_ip(a) else None
        if other and not is_private_ip(other):
            frames_by_ip[other] += frames
    # Convert to list
    return [(ip, frames, 0) for ip, frames in frames_by_ip.most_common()]

# -------- relay picking logic --------

TURN_RELAY_RANGE = (49160, 49200)  # as configured in your coturn
TURN_CTRL_PORT = 3478

def pick_relays(pcap: str) -> Dict[str, int]:
    """
    Return dict ip->score for likely relay IPs in this pcap.
    Strategy:
      1) All IPs seen on UDP relay ports 49160–49200 (strong signal).
      2) All IPs seen on TURN control 3478 (some signal).
      3) If nothing above, top QUIC peers (udp.port==443) by frequency (medium signal).
      4) Final fallback: top UDP conversation peers by frames (weak, but better than nothing).
    """
    candidates: Counter = Counter()

    # 1) Relay ports (UDP)
    relay_pairs = ip_pairs(pcap, f"udp && udp.port>={TURN_RELAY_RANGE[0]} && udp.port<={TURN_RELAY_RANGE[1]}")
    for s, d in relay_pairs:
        for ip in (s, d):
            if not is_private_ip(ip):
                candidates[ip] += 10  # strong weight

    # 2) TURN control (UDP/TCP 3478)
    for filt in (f"udp.port=={TURN_CTRL_PORT}", f"tcp.port=={TURN_CTRL_PORT}"):
        ctrl_pairs = ip_pairs(pcap, filt)
        for s, d in ctrl_pairs:
            for ip in (s, d):
                if not is_private_ip(ip):
                    candidates[ip] += 5  # medium weight

    # If we already have strong/medium candidates, we’re done
    if candidates:
        return dict(candidates)

    # 3) QUIC (udp/443)
    quic_pairs = ip_pairs(pcap, "quic && udp.port==443")
    for s, d in quic_pairs:
        for ip in (s, d):
            if not is_private_ip(ip):
                candidates[ip] += 3

    if candidates:
        return dict(candidates)

    # 4) Fallback: heavy UDP peers
    for ip, frames, _ in conv_table(pcap, "udp"):
        if not is_private_ip(ip):
            # Ignore obvious DNS resolvers (1.1.1.1, 8.8.8.8) and CDNs if extremely small
            if ip in ("1.1.1.1", "8.8.8.8"):
                continue
            candidates[ip] += max(1, min(frames // 50, 5))  # light weight based on frames

    return dict(candidates)

# -------- enrich (geo/ASN) --------

def enrich_ip(ip: str) -> Dict[str, str]:
    """
    Use local lookupip.py if present for geo/ASN. If not available, return bare dict.
    """
    ret = {"ip": ip}
    here = os.path.dirname(os.path.abspath(__file__))
    script = os.path.join(here, "lookupip.py")
    if os.path.isfile(script):
        try:
            out = run(f"python3 {shlex.quote(script)} {shlex.quote(ip)}")
            # Best-effort parse of key: value lines
            for line in out.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    ret[k.strip().lower().replace(" ", "_")] = v.strip()
        except Exception as e:
            ret["lookup_error"] = str(e)
    return ret

# -------- main --------

def main():
    ap = argparse.ArgumentParser(description="Detect relay IPs in a pcap (RTP/STUN/TURN/QUIC aware).")
    ap.add_argument("--pcap", required=True, help="Path to pcap file")
    ap.add_argument("--json", help="Optional path to write JSON summary")
    args = ap.parse_args()

    if not tshark_available():
        print("ERROR: tshark is not installed (apt-get install tshark)", file=sys.stderr)
        sys.exit(2)

    pcap = args.pcap
    if not os.path.isfile(pcap):
        print(f"File not found: {pcap}", file=sys.stderr)
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

    # RTP flows (top pairs by occurrence)
    rtp_pairs = ip_pairs(pcap, "rtp")
    rtp_counter: Counter = Counter()
    for s, d in rtp_pairs:
        rtp_counter[(s, d)] += 1
    if rtp_counter:
        print("\nRTP Flows (most->least):")
        for (s, d), n in rtp_counter.most_common(12):
            print(f"  {s:<15} -> {d:<15}  packets={n}")
    else:
        print("\nRTP Flows (most->least):\n  (none)")

    # QUIC peers (top by frequency)
    quic_counts: Counter = Counter()
    for s, d in ip_pairs(pcap, "quic && udp.port==443"):
        quic_counts[s] += 1
        quic_counts[d] += 1

    # Pick relays
    relay_scores = pick_relays(pcap)
    relay_sorted = sorted(relay_scores.items(), key=lambda kv: kv[1], reverse=True)
    relay_ips = [ip for ip, score in relay_sorted]

    # Print summary with enrichment
    print("\nRelay IPs (by score):")
    if not relay_ips:
        print("  (none found — try longer capture, ensure both ends traverse your VPN/TURN)")
    else:
        for ip, score in relay_sorted[:10]:
            info = enrich_ip(ip)
            label = []
            for k in ("city", "region", "country", "asn"):
                if k in info and info[k]:
                    label.append(info[k])
            label_str = " | ".join(label) if label else ""
            print(f"  {ip:<15}  score={score}  {label_str}")

        # One-liner your supervisor wants:
        print("\nThe relay IP(s): " + ", ".join(relay_ips[:3]))

    # Optional JSON
    if args.json:
        out = {
            "pcap": pcap,
            "counts": counts,
            "rtp_pairs_top": [{"src": s, "dst": d, "packets": n} for (s, d), n in rtp_counter.most_common(20)],
            "quic_peers_top": [{"ip": ip, "hits": n} for ip, n in quic_counts.most_common(20)],
            "relays": [{"ip": ip, "score": score, "enrich": enrich_ip(ip)} for ip, score in relay_sorted[:10]],
        }
        os.makedirs(os.path.dirname(args.json), exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(out, f, indent=2)
        print(f"\nWrote JSON: {args.json}")

if __name__ == "__main__":
    main()
