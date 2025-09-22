#!/usr/bin/env python3
"""
check_dpi.py — summarize RTC media + relay IPs from a pcap

Adds:
- Counts: STUN / RTP / RTCP / QUIC:443
- Top peers (Zoom media on 8801, QUIC on 443)
- Likely relay IPs (public first)
- Enrichment via lookupip.py if present
- Best-effort PoP inference via traceroute/mtr + RTT
- Prints last 3 hops from traceroute to show actual PoP
"""

import argparse, ipaddress, json, os, re, shlex, subprocess, sys
from collections import Counter
from typing import Dict, List, Tuple, Optional

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

# --- relay picking ---
def pick_relays_from_media(media): return [(ip,n) for ip,n in media if not is_private_ip(ip)]
def pick_relays_from_quic(quic):  return [(ip,n) for ip,n in quic if not is_private_ip(ip)]

# --- location inference ---
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
    # RTT fallback
    out=run_ok(f"ping -n -c 4 {ip}",timeout=10)
    if out:
        m=re.search(r"rtt min/avg/max/[a-z]+ = .*?/(\d+\.\d+)/",out)
        if m:
            try:
                r=float(m.group(1))
                if r<8: return "Same-DC/Metro",hops
                if r<20: return "Nearby EU",hops
                if r<35: return "Regional EU",hops
                if r<70: return "In-Europe",hops
                return "Intercontinental?",hops
            except: pass
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
    rtp=tshark_count(pcap,"rtp","-d udp.port==8801,rtp")
    rtcp=tshark_count(pcap,"rtcp","-d udp.port==8801,rtcp")
    quic=tshark_count(pcap,"quic && udp.port==443")
    if stun==0: stun=tshark_count(pcap,"udp.port==8801")
    if rtcp==0: rtcp=tshark_count(pcap,"udp.port==8801")
    counts={"stun":stun,"rtp":rtp,"rtcp":rtcp,"quic":quic}
    print(f"Counts: STUN={stun}  RTP={rtp}  RTCP={rtcp}  QUIC443={quic}")

    media=top_counts(pcap,"udp.port==8801","ip.dst",20)
    quic_peers=top_counts(pcap,"quic && udp.port==443","ip.dst",15)
    print("\nTop UDP/8801 peers (dst):")
    [print(f"  {ip:<15}  packets={n}") for ip,n in media] if media else print("  (none)")
    if quic_peers:
        print("\nTop QUIC/443 peers (dst):")
        [print(f"  {ip:<15}  packets={n}") for ip,n in quic_peers]

    relays=pick_relays_from_media(media) or pick_relays_from_quic(quic_peers)
    print("\nRelay IPs (by hits):")
    if not relays: print("  (none)")
    else:
        for ip,hits in relays[:10]:
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
