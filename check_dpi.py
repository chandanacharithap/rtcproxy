#!/usr/bin/env python3
import os, sys, argparse, json, socket, struct
from collections import defaultdict, Counter
import dpkt, pyshark

def ip2str(b):
    """bytes -> dotted/colon IP string (v4/v6)"""
    try:
        return socket.inet_ntop(socket.AF_INET, b) if len(b)==4 else socket.inet_ntop(socket.AF_INET6, b)
    except Exception:
        return "Invalid"

def first_has_eth(pcap):
    """Quickly check if the capture has Ethernet link-layer"""
    cap = pyshark.FileCapture(pcap)
    for pkt in cap:
        cap.close()
        return hasattr(pkt, "eth")
    cap.close()
    return False

def detect_rtp(payload):
    """Very lightweight RTP detector (ver=2, timestamp!=0)."""
    if len(payload) < 12: return None
    b1,b2,seq,ts,ssrc = struct.unpack("!BBHII", payload[:12])
    ver = (b1>>6)&0x03
    if ver != 2: return None
    if ts == 0: return None
    pt = b2 & 0x7F
    return {"seq":seq,"ts":ts,"ssrc":ssrc,"pt":pt}

def detect_stun(payload):
    """STUN with magic cookie 0x2112A442."""
    if len(payload) < 20: return None
    mt, mlen, cookie = struct.unpack("!HHI", payload[:8])
    if cookie != 0x2112A442: return None
    return {"mt":mt,"mlen":mlen}

def detect_rtcp(payload):
    """RTCP version=2 basic check."""
    if len(payload) < 8: return None
    b1, ptype, length = struct.unpack("!BBH", payload[:4])
    ver = (b1>>6)&0x03
    if ver != 2: return None
    ssrc = struct.unpack("!I", payload[4:8])[0]
    return {"ptype":ptype,"ssrc":ssrc,"len":length}

# ------------ core ------------
def analyze_pcap(pcap_path):
    summary = {
        "pcap": pcap_path,
        "counts": {"stun":0,"rtp":0,"rtcp":0},
        "rtp_flows": [],        # [{src, dst, packets}]
        "relay_ips": []         # [{ip, packets}]
    }

    has_eth = first_has_eth(pcap_path)
    flows = defaultdict(int)   # (src_ip,src_port,dst_ip,dst_port) -> count
    stun_cnt = rtcp_cnt = rtp_cnt = 0
    dst_counter = Counter()

    with open(pcap_path,"rb") as f:
        reader = dpkt.pcapng.Reader(f) if pcap_path.endswith(".pcapng") else dpkt.pcap.Reader(f)
        for ts,buf in reader:
            # unwrap to IP layer
            if has_eth:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)): 
                    continue
            else:
                try:
                    ip = dpkt.ip.IP(buf) if (buf[0]>>4)==4 else dpkt.ip6.IP6(buf)
                except Exception:
                    continue

            # UDP only
            if not isinstance(ip.data, dpkt.udp.UDP):
                continue
            udp = ip.data
            pl = bytes(udp.data)

            # Try identify (cheap order)
            if detect_stun(pl):
                stun_cnt += 1
                continue
            r = detect_rtp(pl)
            if r:
                rtp_cnt += 1
                sip, dip = ip2str(ip.src), ip2str(ip.dst)
                sp, dp = udp.sport, udp.dport
                flows[(sip,sp,dip,dp)] += 1
                dst_counter[dip] += 1
                continue
            if detect_rtcp(pl):
                rtcp_cnt += 1
                continue

    summary["counts"]["stun"] = stun_cnt
    summary["counts"]["rtp"]  = rtp_cnt
    summary["counts"]["rtcp"] = rtcp_cnt

    # sort flows by RTP packet count
    for (sip,sp,dip,dp), cnt in sorted(flows.items(), key=lambda x:-x[1]):
        summary["rtp_flows"].append({
            "src": f"{sip}:{sp}",
            "dst": f"{dip}:{dp}",
            "packets": cnt
        })

    # relay IPs = destination IPs for RTP (weighted by packets)
    summary["relay_ips"] = [{"ip": ip, "packets": cnt} for ip,cnt in dst_counter.most_common()]
    return summary

# ------------ CLI ------------
def main():
    ap = argparse.ArgumentParser(description="Minimal RTC DPI: print RTP flows and relay IPs from a single pcap.")
    ap.add_argument("--pcap", required=True, help="Path to pcap/pcapng")
    ap.add_argument("--json", help="Optional: write JSON summary")
    args = ap.parse_args()

    res = analyze_pcap(args.pcap)

    # pretty print
    print(f"{res['pcap']}")
    print(f"Counts: STUN={res['counts']['stun']}  RTP={res['counts']['rtp']}  RTCP={res['counts']['rtcp']}")
    print("\nRTP Flows (most->least):")
    if not res["rtp_flows"]:
        print("  (none)")
    else:
        for f in res["rtp_flows"][:50]:
            print(f"  {f['src']}  ->  {f['dst']}   packets={f['packets']}")

    print("\nRelay IPs (unique, by RTP packets):")
    if not res["relay_ips"]:
        print("  (none)")
    else:
        for r in res["relay_ips"][:50]:
            print(f"  {r['ip']}  packets={r['packets']}")

    if args.json:
        with open(args.json,"w") as out:
            json.dump(res, out, indent=2)
        print(f"\nWrote JSON: {args.json}")

if __name__ == "__main__":
    main()
