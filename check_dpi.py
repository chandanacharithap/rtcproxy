#!/usr/bin/env python3
import os
import dpkt
import pyshark
import sys
import struct
from collections import defaultdict, Counter
import socket
from contextlib import redirect_stdout
import argparse
import json
import time
import multiprocessing
import subprocess



protocol = "rtp"  # can be "rtp" or "stun" or "rtcp" or "classicstun"

debug = False

start_packet_index = 1
end_packet_index = 275396
suspecious_flow = ("172.20.10.11", "172.20.10.10", 16393, 16393, 672257842, 100)


ssrc_set = set()
ssrc_set.add(0)  # 特地为了discord

# 定义有效的 RTP Payload Type
VALID_PAYLOAD_TYPES = {0, 3, 4, 7, 8, 9, 13, 14, 15, 18, 26, 31, 32, 33, 34}
VALID_DYNAMIC_PAYLOAD_TYPES = range(96, 128)  # RTP 动态负载类型


def is_valid_payload_type(pt):
    """检查 payload type 是否有效"""
    return True


def detect_rtp(packet_data):
    if len(packet_data) < 12:
        return None
    rtp_header = struct.unpack("!BBHII", packet_data[:12])

    first_byte = rtp_header[0]
    version = (first_byte >> 6) & 0x03
    padding = (first_byte >> 5) & 0x01
    extension = (first_byte >> 4) & 0x01
    cc = first_byte & 0x0F

    second_byte = rtp_header[1]
    marker = (second_byte >> 7) & 0x01
    payload_type = second_byte & 0x7F
    seq_num = rtp_header[2]
    timestamp = rtp_header[3]
    ssrc = rtp_header[4]

    if version != 2:
        return None
    if marker not in {0, 1}:
        return None
    if int(timestamp) == 0:
        return None
    if not is_valid_payload_type(payload_type):
        return None

    return {
        "length": len(packet_data),
        "version": version,
        "padding": padding,
        "extension": extension,
        "cc": cc,
        "marker": marker,
        "payload_type": payload_type,
        "seq_num": seq_num,
        "timestamp": timestamp,
        "ssrc": ssrc,
    }


def detect_classic_stun(packet_data):
    if len(packet_data) < 20:
        return None

    message_type = struct.unpack("!H", packet_data[:2])[0]
    message_length = struct.unpack("!H", packet_data[2:4])[0]
    transaction_id = packet_data[4:16]
    message = packet_data[16:]

    if message_length != len(message):
        return None

    return {
        "message_type": message_type,
        "message_length": message_length,
        "transaction_id": transaction_id.hex(),
    }


def detect_stun(packet_data):
    if len(packet_data) < 20:
        return None

    stun_header = struct.unpack("!HHI12s", packet_data[:20])
    msg_type = stun_header[0]
    msg_len = stun_header[1]
    magic_cookie = stun_header[2]
    transaction_id = stun_header[3]

    attributes_string = packet_data[20:].hex()

    STUN_MAGIC_COOKIE = 0x2112A442
    if magic_cookie != STUN_MAGIC_COOKIE:
        return None

    attributes = {}
    offset = 20
    while offset + 4 <= len(packet_data):
        attr_type, attr_length = struct.unpack("!HH", packet_data[offset:offset + 4])
        attr_value = packet_data[offset + 4:offset + 4 + attr_length]
        attributes[attr_type] = attr_value
        offset += 4 + attr_length

    return {
        "msg_type": msg_type,
        "msg_length": msg_len,
        "magic_cookie": magic_cookie,
        "transaction_id": transaction_id.hex(),
        "attributes": attributes,
        "attributes_string": attributes_string,
    }


def detect_rtcp(packet_data):
    if len(packet_data) < 8:
        return None
    first_byte, packet_type, length = struct.unpack("!BBH", packet_data[:4])
    version = (first_byte >> 6) & 0x03
    padding = (first_byte >> 5) & 0x01
    rc = first_byte & 0x1F
    if version != 2:
        return None
    if len(packet_data) < 8:
        return None
    ssrc = struct.unpack("!I", packet_data[4:8])[0]
    payload = packet_data[8:]
    if (length + 1) * 4 > len(payload) + 8:
        return None
    return {
        "version": version,
        "padding": padding,
        "rc": rc,
        "packet_type": packet_type,
        "length": length,
        "ssrc": ssrc,
        "payload": payload.hex(),
    }


# === NEW robust lookup helper ===
def safe_lookup_ip(ip: str) -> dict:
    """
    Robustly query lookupip.py for IP metadata.
    - Works whether lookup() returns dict, JSON, or key:value text.
    - Gracefully falls back to subprocess if import fails.
    - Never raises exceptions; returns only real info.
    - Skips empty or unknown fields (no '?').
    """
    info = {}
    try:
        from lookupip import lookup
        res = lookup(ip)
        if isinstance(res, dict):
            info = res
        elif isinstance(res, str):
            try:
                info = json.loads(res)
            except json.JSONDecodeError:
                for line in res.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        v = v.strip()
                        if v and v.lower() not in {"?", "none", "null", "-"}:
                            info[k.strip().lower().replace(" ", "_")] = v
    except Exception:
        script_path = os.path.join(os.path.dirname(__file__), "lookupip.py")
        if os.path.isfile(script_path):
            out = subprocess.run(
                ["python3", script_path, ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5
            ).stdout.decode("utf-8", errors="ignore")
            for line in out.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    v = v.strip()
                    if v and v.lower() not in {"?", "none", "null", "-"}:
                        info[k.strip().lower().replace(" ", "_")] = v
    return info


def validate_rtp_info_list(message_info_list, packet_count):
    relay_ips = Counter()
    for msg in message_info_list:
        dst_ip = msg["flow_info"]["dst_ip"]
        relay_ips[dst_ip] += 1

    print("Relay IPs (from RTP flows):")
    for ip, count in relay_ips.most_common():
        try:
            info = safe_lookup_ip(ip)
            parts = [f"{ip}\tpackets={count}"]
            for key in ["city", "region", "country", "asn", "isp"]:
                val = info.get(key)
                if val:
                    parts.append(f"{key}={val}")
            print(" | ".join(parts))
        except Exception as e:
            print(f"{ip}\tpackets={count} | lookup failed: {e}")

    return message_info_list


def validate_stun_info_list(message_info_list, packet_count):
    for message_info in message_info_list:
        if debug:
            print(f"message_info['msg_length'] * 2: {message_info['msg_length'] * 2}")
            print(f"len(message_info['attributes_string']): {len(message_info['attributes_string'])}")
        if message_info["msg_length"] * 2 != len(message_info["attributes_string"]):
            message_info_list.remove(message_info)

    if 1:
        print("STUN Info:")
        for message_info in message_info_list:
            print(
                f"  STUN Packet {message_info['packet_index']} (chopped {message_info['chopped_bytes']} bytes), "
                f"Msg Type: {message_info['msg_type']}, Msg Len: {message_info['msg_length']}, "
                f"Trans ID: {message_info['transaction_id']}"
            )

    return message_info_list


def validate_classic_stun_info_list(message_info_list, packet_count):
    if 1:
        print("Classic STUN Info:")
        for message_info in message_info_list:
            print(
                f"  Classic STUN Packet {message_info['packet_index']} (chopped {message_info['chopped_bytes']} bytes), "
                f"Msg Type: {message_info['message_type']}, Msg Len: {message_info['message_length']}, "
                f"Trans ID: {message_info['transaction_id']}"
            )
    return message_info_list


def validate_rtcp_info_list(message_info_list, packet_count):
    global ssrc_set
    print(f"ssrc_set: {ssrc_set}")
    print(f"length of message_info_list: {len(message_info_list)}")

    filtered_message_info_list = []
    for message_info in message_info_list:
        if message_info["ssrc"] in ssrc_set:
            filtered_message_info_list.append(message_info)

    print(f"length of message_info_list after removing: {len(filtered_message_info_list)}")
    if 1:
        print("RTCP Info:")
        for message_info in filtered_message_info_list:
            print(f"  RTCP Packet {message_info['packet_index']} (chopped {message_info['chopped_bytes']} bytes), SSRC: {message_info['ssrc']}, Payload Type: {message_info['packet_type']}")
    return filtered_message_info_list


def ip_to_str(ip_bytes):
    try:
        if len(ip_bytes) == 4:
            return socket.inet_ntoa(ip_bytes)
        elif len(ip_bytes) == 16:
            return socket.inet_ntop(socket.AF_INET6, ip_bytes)
        else:
            return "Invalid IP"
    except Exception:
        return "Invalid IP"


def read_first_packet(file_path):
    cap = pyshark.FileCapture(file_path)
    for packet in cap:
        if hasattr(packet, "eth"):
            cap.close()
            return True
        cap.close()
        return False
    cap.close()
    return False


def read_pcapng(file_path):
    has_ethernet = read_first_packet(file_path)
    packet_indices = []
    message_info_list = []

    with open(file_path, "rb") as f:
        if file_path.endswith(".pcapng"):
            pcap_reader = dpkt.pcapng.Reader(f)
        else:
            pcap_reader = dpkt.pcap.Reader(f)

        packet_index = 0
        for timestamp, buf in pcap_reader:
            packet_index += 1
            if debug:
                if packet_index < start_packet_index or packet_index > end_packet_index:
                    continue
            if has_ethernet:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue
                ip_pkt = eth.data
            else:
                if len(buf) < 1:
                    continue
                if buf[0] >> 4 == 4:
                    if len(buf) < 20:
                        continue
                    try:
                        ip_pkt = dpkt.ip.IP(buf)
                    except:
                        continue
                elif buf[0] >> 4 == 6:
                    if len(buf) < 40:
                        continue
                    try:
                        ip_pkt = dpkt.ip6.IP6(buf)
                    except:
                        continue
                else:
                    continue

            if isinstance(ip_pkt.data, dpkt.udp.UDP):
                udp_pkt = ip_pkt.data
                udp_payload = bytes(udp_pkt.data)

                for i in range(200):
                    udp_payload_slice = udp_payload[i:]
                    if protocol == "rtp":
                        rtp_info = detect_rtp(udp_payload_slice)
                        if rtp_info:
                            packet_indices.append(packet_index)
                            rtp_info["flow_info"] = {
                                "src_ip": ip_to_str(ip_pkt.src),
                                "dst_ip": ip_to_str(ip_pkt.dst),
                                "src_port": udp_pkt.sport,
                                "dst_port": udp_pkt.dport,
                            }
                            rtp_info["chopped_bytes"] = i
                            rtp_info["packet_index"] = packet_index
                            message_info_list.append(rtp_info)
                    if protocol == "stun":
                        stun_info = detect_stun(udp_payload_slice)
                        if stun_info:
                            packet_indices.append(packet_index)
                            stun_info["flow_info"] = {
                                "src_ip": ip_to_str(ip_pkt.src),
                                "dst_ip": ip_to_str(ip_pkt.dst),
                                "src_port": udp_pkt.sport,
                                "dst_port": udp_pkt.dport,
                            }
                            stun_info["chopped_bytes"] = i
                            stun_info["packet_index"] = packet_index
                            message_info_list.append(stun_info)
                    if protocol == "rtcp":
                        rtcp_info = detect_rtcp(udp_payload_slice)
                        if rtcp_info:
                            packet_indices.append(packet_index)
                            rtcp_info["flow_info"] = {
                                "src_ip": ip_to_str(ip_pkt.src),
                                "dst_ip": ip_to_str(ip_pkt.dst),
                                "src_port": udp_pkt.sport,
                                "dst_port": udp_pkt.dport,
                            }
                            rtcp_info["chopped_bytes"] = i
                            rtcp_info["packet_index"] = packet_index
                            message_info_list.append(rtcp_info)

    print(f"{file_path}")
    if protocol == "rtp":
        filtered_message_info_list = validate_rtp_info_list(message_info_list, len(packet_indices))
        packet_index_set = set(message_info["packet_index"] for message_info in filtered_message_info_list)
        print(f"Total RTP packets found: {len(packet_index_set)}")
        print(f"Total RTP messages found: {len(filtered_message_info_list)}")
    if protocol == "stun":
        filtered_message_info_list = validate_stun_info_list(message_info_list, len(packet_indices))
        packet_index_set = set(message_info["packet_index"] for message_info in filtered_message_info_list)
        print(f"Total STUN packets found: {len(packet_index_set)}")
        print(f"Total STUN messages found: {len(filtered_message_info_list)}")
    if protocol == "rtcp":
        filtered_message_info_list = validate_rtcp_info_list(message_info_list, len(packet_indices))
        packet_index_set = set(message_info["packet_index"] for message_info in filtered_message_info_list)
        print(f"Total RTCP packets found: {len(packet_index_set)}")
        print(f"Total RTCP messages found: {len(filtered_message_info_list)}")


def process_pcap_folder(folder_path):
    global protocol
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".pcap") or file.endswith(".pcapng"):
                file_path = f"{root}/{file}"
                print(f"processing file: {file_path}")
                if not os.path.exists("./dpi_found"):
                    os.makedirs("./dpi_found")
                report_path = "./dpi_found/" + os.path.splitext(file_path)[0].split("/")[-1] + "_dpi_detection.txt"
                if os.path.exists(report_path):
                    os.remove(report_path)
                with open(report_path, "w", encoding="utf-8") as f:
                    with redirect_stdout(f):
                        protocol = "stun"
                        read_pcapng(file_path)
                        protocol = "rtp"
                        read_pcapng(file_path)
                        protocol = "rtcp"
                        read_pcapng(file_path)


def process_pcap_file(file_path):
    global protocol
    if not os.path.exists("./dpi_found"):
        os.makedirs("./dpi_found")
    report_path = "./dpi_found/" + os.path.splitext(file_path)[0].split("/")[-1] + "_dpi_detection.txt"
    if os.path.exists(report_path):
        os.remove(report_path)
    with open(report_path, "w", encoding="utf-8") as f:
        with redirect_stdout(f):
            if debug:
                protocol = "rtp"
                read_pcapng(file_path)
            else:
                protocol = "stun"
                read_pcapng(file_path)
                protocol = "rtp"
                read_pcapng(file_path)
                protocol = "rtcp"
                read_pcapng(file_path)


def load_config(config_path="config.json"):
    def read_from_json(file_path):
        with open(file_path, "r") as file:
            dict = json.load(file)
        return dict

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")

    config = read_from_json(config_path)
    pcap_main_folder = config["paths"]["pcap_main_folder"]
    save_main_folder = config["paths"]["save_main_folder"]
    plugin_target_folder = config["paths"]["plugin_target_folder"]
    plugin_source_folder = config["paths"]["plugin_source_folder"]
    apps = config["apps"]
    tests = config["tests"]
    rounds = config["rounds"]
    clients = config["client_types"]
    precall_noise = config["precall_noise_duration"]
    postcall_noise = config["postcall_noise_duration"]

    return pcap_main_folder, save_main_folder, apps, tests, rounds, clients, precall_noise, postcall_noise, plugin_target_folder, plugin_source_folder


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RTP/RTC packet analyzer")
    parser.add_argument("--pcap", type=str, help="Path to a single pcap/pcapng file")
    parser.add_argument("--multiprocess", action="store_true", help="Use multiprocessing for batch mode")
    parser.add_argument("--config", type=str, default=None, help="Path to the configuration file")
    args = parser.parse_args()

    if args.pcap:
        protocol = "rtp"
        read_pcapng(args.pcap)
    elif args.config:
        config_path = args.config
        multiprocess = args.multiprocess
        pcap_main_folder, save_main_folder, apps, tests, rounds, client_types, \
            precall_noise, postcall_noise, plugin_target_folder, plugin_source_folder = load_config(config_path)
        for app_name in apps:
            for test_name in tests:
                if "noise" in test_name:
                    continue
                for test_round in rounds:
                    for client_type in client_types:
                        for i in range(1, tests[test_name] + 1):
                            pcap_subfolder = f"{pcap_main_folder}/{app_name}"
                            pcap_file_name = f"{app_name}_{test_name}_{test_round}_{client_type}.pcapng"
                            pcap_file = f"{pcap_subfolder}/{pcap_file_name}"
                            process_pcap_file(pcap_file)
    else:
        parser.print_help()
