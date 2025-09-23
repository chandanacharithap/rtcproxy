# #!/usr/bin/env python3
# """
# check_dpi.py — summarize RTC media + relay IPs from a pcap

# Updates:
# - Stricter relay filtering (ignore DNS/infra noise like 1.1.1.1, 8.8.8.8)
# - Prefer rDNS PoP codes (ams/fra/lhr/iad etc.) for location
# - Cleaner relay list output: IP | City | Country
# """

# import argparse, ipaddress, os, re, shlex, subprocess, sys
# from collections import Counter
# from typing import Dict, List, Tuple, Optional

# CITY_HINTS = {
#     # EU
#     "ams": "Amsterdam", "fra": "Frankfurt", "lhr": "London",
#     "cdg": "Paris", "mad": "Madrid", "waw": "Warsaw", "mil": "Milan",
#     "vie": "Vienna", "bru": "Brussels", "cph": "Copenhagen",
#     "arn": "Stockholm", "osl": "Oslo", "hel": "Helsinki",
#     "zrh": "Zurich", "dub": "Dublin",
#     # US
#     "sjc": "San Jose", "sfo": "San Francisco", "lax": "Los Angeles",
#     "iad": "Ashburn", "dfw": "Dallas", "ord": "Chicago", "nyc": "New York",
# }

# STUN_PORTS = [3478, 5349, 19302]   # typical STUN/TURN ports
# IGNORE_IPS = {"1.1.1.1", "8.8.8.8", "8.8.4.4"}  # DNS noise

# def run(cmd, timeout=30) -> str:
#     p = subprocess.run(cmd if isinstance(cmd, list) else shlex.split(cmd),
#                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
#     return p.stdout.decode(errors="ignore") if p.returncode == 0 else ""

# def run_ok(cmd, timeout=30) -> Optional[str]:
#     try: return run(cmd, timeout=timeout)
#     except: return None

# def have(bin_name: str) -> bool:
#     return subprocess.run(["bash","-lc",f"command -v {shlex.quote(bin_name)} >/dev/null 2>&1"]).returncode == 0

# def is_private_ip(ip: str) -> bool:
#     try: return ipaddress.ip_address(ip).is_private
#     except: return True

# # --- tshark helpers ---
# def tshark_count(pcap, filt, extra_args="") -> int:
#     out = run_ok(f'tshark -r {shlex.quote(pcap)} {extra_args} -Y {shlex.quote(filt)} -T fields -e frame.number')
#     return len([ln for ln in out.splitlines() if ln.strip()]) if out else 0

# def top_counts(pcap, filt, field="ip.dst", limit=15, extra_args="") -> List[Tuple[str,int]]:
#     out = run_ok(f'tshark -r {shlex.quote(pcap)} {extra_args} -Y {shlex.quote(filt)} -T fields -e {field}')
#     if not out: return []
#     c = Counter([x.strip() for x in out.splitlines() if x.strip()])
#     return c.most_common(limit)

# # --- relay picking ---
# def pick_relays(media, quic) -> List[Tuple[str,int]]:
#     relays = []
#     for ip, n in media + quic:
#         if is_private_ip(ip):
#             continue
#         if ip in IGNORE_IPS:
#             continue
#         # skip multicast / broadcast style noise
#         if ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".1"):
#             continue
#         relays.append((ip, n))
#     return relays

# # --- enrichment ---
# def enrich_ip(ip: str) -> Dict[str,str]:
#     script=os.path.join(os.path.dirname(os.path.abspath(__file__)),"lookupip.py")
#     if not os.path.isfile(script): return {}
#     out=run_ok(f"python3 {shlex.quote(script)} {shlex.quote(ip)}",timeout=10)
#     info={}
#     if out:
#         for line in out.splitlines():
#             if ":" in line:
#                 k,v=line.split(":",1)
#                 info[k.strip().lower().replace(" ","_")]=v.strip()
#     return info

# # --- main ---
# def main():
#     ap=argparse.ArgumentParser()
#     ap.add_argument("--pcap",required=True)
#     args=ap.parse_args()

#     pcap=args.pcap
#     if not os.path.isfile(pcap): sys.exit(f"File not found: {pcap}")
#     print(pcap)

#     # Packet counts
#     stun=sum(tshark_count(pcap,f"udp.port=={p}") for p in STUN_PORTS)
#     rtp=tshark_count(pcap,"rtp","-d udp.port==8801,rtp")
#     rtcp=tshark_count(pcap,"rtcp","-d udp.port==8801,rtcp")
#     quic=tshark_count(pcap,"quic && udp.port==443")

#     print(f"Counts: STUN={stun}  RTP={rtp}  RTCP={rtcp}  QUIC443={quic}")

#     media=top_counts(pcap,"udp.port==8801","ip.dst",20)
#     quic_peers=top_counts(pcap,"quic && udp.port==443","ip.dst",15)

#     print("\nTop UDP/8801 peers (dst):")
#     [print(f"  {ip:<15}  packets={n}") for ip,n in media] if media else print("  (none)")
#     if quic_peers:
#         print("\nTop QUIC/443 peers (dst):")
#         [print(f"  {ip:<15}  packets={n}") for ip,n in quic_peers]

#     relays=pick_relays(media, quic_peers)
#     print("\nRelay IPs (by hits):")
#     if not relays:
#         print("  (none)")
#     else:
#         for ip,hits in relays[:10]:
#             info = enrich_ip(ip)
#             city = info.get("city")
#             country = info.get("country")
#             rdns = info.get("rdns")

#             label_parts = []
#             if rdns: label_parts.append(f"rdns={rdns}")
#             if city: label_parts.append(f"city={city}")
#             if country: label_parts.append(f"country={country}")

#             label = " | ".join(label_parts) if label_parts else "no-info"
#             print(f"  {ip:<15}  hits={hits}  {label}")

# if __name__=="__main__": main()
#!/usr/bin/env python3
import os, sys, dpkt, socket, struct, argparse, subprocess, shlex
from collections import defaultdict

def ip_to_str(ip_bytes):
    try:
        return socket.inet_ntop(socket.AF_INET6, ip_bytes) if len(ip_bytes) == 16 else socket.inet_ntoa(ip_bytes)
    except: return "Invalid"

def detect_rtp(payload):
    if len(payload) < 12: return None
    try:
        v,p,timestamp,ssrc = (payload[0] >> 6, payload[1]&0x7F, struct.unpack("!I",payload[4:8])[0], struct.unpack("!I",payload[8:12])[0])
        if v != 2 or timestamp == 0: return None
        return {
            "payload_type": p,
            "seq": struct.unpack("!H", payload[2:4])[0],
            "timestamp": timestamp,
            "ssrc": ssrc
        }
    except: return None

def read_pcap(file):
    flows = defaultdict(list)
    with open(file, "rb") as f:
        pcap = dpkt.pcap.Reader(f) if file.endswith(".pcap") else dpkt.pcapng.Reader(f)
        for idx,(ts,buf) in enumerate(pcap):
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip  = eth.data if isinstance(eth.data,(dpkt.ip.IP,dpkt.ip6.IP6)) else None
                if not ip or not isinstance(ip.data, dpkt.udp.UDP): continue
                udp = ip.data
                info = detect_rtp(bytes(udp.data))
                if info:
                    fid=(ip_to_str(ip.src),ip_to_str(ip.dst),udp.sport,udp.dport,info["ssrc"])
                    flows[fid].append(info)
            except: continue
    return flows

def enrich_ip(ip):
    script=os.path.join(os.path.dirname(__file__),"lookupip.py")
    if not os.path.isfile(script): return {}
    try:
        out=subprocess.run(["python3",script,ip],stdout=subprocess.PIPE,timeout=10).stdout.decode()
        info={}
        for ln in out.splitlines():
            if ":" in ln: k,v=ln.split(":",1); info[k.strip().lower()]=v.strip()
        return info
    except: return {}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--pcap",required=True)
    args=ap.parse_args()
    flows=read_pcap(args.pcap)
    if not flows:
        print("No RTP flows found.")
        return
    for (src,dst,sport,dport,ssrc),pkts in flows.items():
        print(f"Flow {src}:{sport} -> {dst}:{dport} SSRC={ssrc} RTP-pkts={len(pkts)}")
        if not dst.startswith("10.") and not dst.startswith("192.") and not dst.startswith("172."):
            info=enrich_ip(dst)
            if info: print(f"   Relay {dst} => {info}")
        print()

if __name__=="__main__": main()
