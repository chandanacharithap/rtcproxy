#!/usr/bin/env python3
"""
check_dpi.py — summarize RTC media + relay IPs from a pcap

Adds:
- Counts: STUN / RTP / RTCP / QUIC:443
- RTP decoding with Zoom (8801) and generic RTP ports (5004, 8000, …)
- Top peers
- Likely relay IPs (TURN, 8801, QUIC, heavy UDP)
- Enrichment via lookupip.py if present
- Best-effort PoP inference via traceroute/mtr + RTT
"""

import argparse, ipaddress, json, os, re, shlex, subprocess, sys
from collections import Counter
from typing import Dict, List, Tuple, Optional

# --- Ports / Hints ---
TURN_RELAY_RANGE = (49160, 49200)   # typical coturn relay range
TURN_CTRL_PORT   = 3478
ZOOM_RTP_PORTS   = [8801]
RTP_HINTS        = [5004, 8000]

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
    # US
    "sjc": "San Jose", "sfo": "San Francisco", "lax": "Los Angeles",
    "iad": "Ashburn", "dfw": "Dallas", "ord": "Chicago", "nyc": "New York",
}

# --- Shell helpers ---
def run(cmd, timeout=30) -> str:
    p = subprocess.run(cmd if isinstance(cmd, list) else shlex.split(cmd),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    return p.stdout.decode(errors="ignore") if p.returncode == 0 else ""

def run_ok(cmd, timeout=30) -> Optional[str]:
    try: return run(cmd, timeout=timeout)
    except: return None

def have(bin_name: str) -> bool:
    return subprocess.run(["bash","-lc",f"command -v {shlex.quote(bin_name)} >/dev/null 2>&1"]).returncode == 0

def is_private_ip(ip: str) -> bool:
    try: return ipaddress.ip_address(ip).is_private
    except: return True

# --- tshark helpers ---
def tshark_count(pcap, filt, extra_args="") -> int:
    out = run_ok(f'tshark -r {shlex.quote(pcap)} {extra_args} -Y {shlex.quote(filt)} -T fields -e frame.number')
    return len([ln for ln in out.splitlines() if ln.strip()]) if out else 0

def top_counts(pcap, filt, field="ip.dst", limit=15, extra_args="") -> List[Tuple[str,int]]:
    out = run_ok(f'tshark -r {shlex.quote(pcap)} {extra_args} -Y {shlex.quote(filt)} -T fields -e {field}')
    if not out: return []
    c = Counter([x.strip() for x in out.splitlines() if x.strip()])
    return c.most_common(limit)

def _decode_as_rtp_count(pcap: str, port: int) -> int:
    out = run_ok(f'tshark -r {shlex.quote(pcap)} -d udp.port=={port},rtp -Y rtp -T fields -e frame.number')
    return len(out.splitlines()) if out else 0

# --- RTP decoding w/ hints ---
def count_rtp_with_hints(pcap: str) -> int:
    n = tshark_count(pcap, "rtp")
    if n > 0:
        return n
    for p in list(dict.fromkeys(ZOOM_RTP_PORTS + RTP_HINTS)):
        n = _decode_as_rtp_count(pcap, p)
        if n > 0:
            return n
    return 0

# --- Relay picking ---
def pick_relays(pcap: str) -> List[Tuple[str,int]]:
    cand: Counter = Counter()

    # TURN relay UDP ports
    for disp in [f"udp.port>={TURN_RELAY_RANGE[0]} && udp.port<={TURN_RELAY_RANGE[1]}"]:
        for ip,n in top_counts(pcap, disp, "ip.dst"):
            if not is_private_ip(ip):
                cand[ip] += n

    # TURN control
    for disp in (f"udp.port=={TURN_CTRL_PORT}", f"tcp.port=={TURN_CTRL_PORT}"):
        for ip,n in top_counts(pcap, disp, "ip.dst"):
            if not is_private_ip(ip):
                cand[ip] += n

    # Zoom media (udp/8801)
    for ip,n in top_counts(pcap, "udp.port==8801", "ip.dst"):
        if not is_private_ip(ip):
            cand[ip] += n

    # QUIC
    for ip,n in top_counts(pcap, "quic && udp.port==443", "ip.dst"):
        if not is_private_ip(ip):
            cand[ip] += n

    return cand.most_common(10)

# --- Location inference ---
def infer_location(ip: str, port: int=8801) -> Tuple[Optional[str],List[str]]:
    hops=[]
    if have("traceroute"):
        out=run_ok(f"traceroute -n -q1 -U -p {port} {ip}",timeout=20)
        if out: hops=out.strip().splitlines()[-3:]
        if out:
            for line in out.splitlines():
                m=re.search(r"\s+\d+\s+([^\s(]+)",line)
                if m:
                    host=m.group(1).lower()
                    if not re.match(r"^\d+\.\d+\.\d+\.\d+$",host):
                        for k,city in CITY_HINTS.items():
                            if k in host: return city,hops
    return None,hops

# --- enrichment ---
def enrich_ip(ip: str) -> Dict[str,str]:
    script=os.path.join(os.path.dirname(os.path.abspath(__file__)),"lookupip.py")
    if not os.path.isfile(script): return {}
    out=run_ok(f"python3 {shlex.quote(script)} {shlex.quote(ip)}",timeout=10)
    info={}
    if out:
        for line in out.splitlines():
            if ":" in line:
                k,v=line.split(":",1)
                info[k.strip().lower().replace(" ","_")]=v.strip()
    return info

# --- main ---
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--pcap",required=True)
    ap.add_argument("--json")
    ap.add_argument("--locate-port",type=int,default=8801)
    args=ap.parse_args()

    pcap=args.pcap
    if not os.path.isfile(pcap): sys.exit(f"File not found: {pcap}")
    print(pcap)

    stun=tshark_count(pcap,"stun","-d udp.port==8801,stun")
    rtp=count_rtp_with_hints(pcap)
    rtcp=tshark_count(pcap,"rtcp","-d udp.port==8801,rtcp")
    quic=tshark_count(pcap,"quic && udp.port==443")
    counts={"stun":stun,"rtp":rtp,"rtcp":rtcp,"quic":quic}
    print(f"Counts: STUN={stun}  RTP={rtp}  RTCP={rtcp}  QUIC443={quic}")

    # Peers
    media=top_counts(pcap,"udp.port==8801","ip.dst",20)
    quic_peers=top_counts(pcap,"quic && udp.port==443","ip.dst",15)
    print("\nTop UDP/8801 peers (dst):")
    [print(f"  {ip:<15}  packets={n}") for ip,n in media] if media else print("  (none)")
    if quic_peers:
        print("\nTop QUIC/443 peers (dst):")
        [print(f"  {ip:<15}  packets={n}") for ip,n in quic_peers]

    # Relays
    relays=pick_relays(pcap)
    print("\nRelay IPs (by hits):")
    if not relays: print("  (none)")
    else:
        for ip,hits in relays:
            parts=[]; info=enrich_ip(ip)
            for k in("city","region","country","asn","isp"):
                if k in info and info[k]: parts.append(info[k])
            inferred,hops=infer_location(ip,args.locate_port)
            if inferred: parts.append(f"inferred_pop={inferred}")
            if hops: parts.append("last_hops="+" | ".join(hops))
            label=" | ".join(parts) if parts else ""
            print(f"  {ip:<15}  hits={hits}  {label}")
        print("\nThe relay IP(s): "+", ".join([ip for ip,_ in relays[:3]]))

if __name__=="__main__": main()
