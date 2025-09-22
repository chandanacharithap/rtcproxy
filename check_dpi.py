#!/usr/bin/env python3
"""
check_dpi.py — summarize RTC media + relay IPs from a pcap

Fixes:
- Stable STUN detection (only on STUN/TURN ports, not 8801)
- Always print location (rDNS city OR RTT bucket)
- Cleaner relay list (ignore DNS/infra noise)
"""

import argparse, ipaddress, json, os, re, shlex, subprocess, sys
from collections import Counter
from typing import Dict, List, Tuple, Optional

CITY_HINTS = {
    # EU
    "ams": "Amsterdam", "fra": "Frankfurt", "lhr": "London",
    "cdg": "Paris", "mad": "Madrid", "waw": "Warsaw", "mil": "Milan",
    "vie": "Vienna", "bru": "Brussels", "cph": "Copenhagen",
    "arn": "Stockholm", "osl": "Oslo", "hel": "Helsinki",
    "zrh": "Zurich", "dub": "Dublin",
    # US
    "sjc": "San Jose", "sfo": "San Francisco", "lax": "Los Angeles",
    "iad": "Ashburn", "dfw": "Dallas", "ord": "Chicago", "nyc": "New York",
}

STUN_PORTS = [3478, 5349, 19302]   # typical STUN/TURN ports
IGNORE_IPS = {"1.1.1.1", "8.8.8.8", "8.8.4.4"}  # DNS noise

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
def pick_relays(media, quic) -> List[Tuple[str,int]]:
    relays = [(ip,n) for ip,n in media if not is_private_ip(ip) and ip not in IGNORE_IPS]
    if not relays:
        relays = [(ip,n) for ip,n in quic if not is_private_ip(ip) and ip not in IGNORE_IPS]
    return relays

# --- location inference ---
def infer_location(ip: str, port: int=8801) -> str:
    # traceroute with rDNS
    if have("traceroute"):
        out=run_ok(f"traceroute -q1 -U -p {port} {ip}",timeout=20)
        if out:
            for line in out.splitlines()[-4:]:
                m=re.search(r"\s+\d+\s+([^\s(]+)",line)
                if not m: continue
                host=m.group(1).lower()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$",host): continue
                for k,city in CITY_HINTS.items():
                    if k in host: return f"pop={city}"

    # fallback RTT buckets
    out=run_ok(f"ping -n -c 4 {ip}",timeout=10)
    if out:
        m=re.search(r"rtt min/avg/max/[a-z]+ = .*?/(\d+\.\d+)/",out)
        if m:
            try:
                r=float(m.group(1))
                if r<8: return "rtt=Same-DC/Metro"
                if r<20: return "rtt=Nearby EU"
                if r<35: return "rtt=Regional EU"
                if r<70: return "rtt=In-Europe"
                return "rtt=Intercontinental?"
            except: pass
    return "location=unknown"

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

    # Stable counts
    stun=sum(tshark_count(pcap,f"udp.port=={p}") for p in STUN_PORTS)
    rtp=tshark_count(pcap,"rtp","-d udp.port==8801,rtp")
    rtcp=tshark_count(pcap,"rtcp","-d udp.port==8801,rtcp")
    quic=tshark_count(pcap,"quic && udp.port==443")

    counts={"stun":stun,"rtp":rtp,"rtcp":rtcp,"quic":quic}
    print(f"Counts: STUN={stun}  RTP={rtp}  RTCP={rtcp}  QUIC443={quic}")

    media=top_counts(pcap,"udp.port==8801","ip.dst",20)
    quic_peers=top_counts(pcap,"quic && udp.port==443","ip.dst",15)

    print("\nTop UDP/8801 peers (dst):")
    [print(f"  {ip:<15}  packets={n}") for ip,n in media] if media else print("  (none)")
    if quic_peers:
        print("\nTop QUIC/443 peers (dst):")
        [print(f"  {ip:<15}  packets={n}") for ip,n in quic_peers]

    relays=pick_relays(media, quic_peers)
    print("\nRelay IPs (by hits):")
    if not relays: print("  (none)")
    else:
        for ip,hits in relays[:10]:
            info = enrich_ip(ip)
            parts = []

            if "rdns" in info and info["rdns"]:
                parts.append(f"rdns={info['rdns']}")

            # Show PoP if found
            if "pop" in info and info["pop"]:
                parts.append(f"PoP={info['pop']}")
            elif "city" in info and info["city"]:
                parts.append(f"city={info['city']}")

            for k in ("region","country","asn","isp"):
                if k in info and info[k]:
                    parts.append(f"{k}={info[k]}")

            inferred = infer_location(ip,args.locate_port)
            if inferred and inferred != "location=unknown":
                parts.append(f"inferred={inferred}")

            label = " | ".join(parts) if parts else "no-extra-info"
            print(f"  {ip:<15}  hits={hits}  {label}")


if __name__=="__main__": main()
