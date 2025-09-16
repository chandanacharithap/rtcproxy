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

# ===== NEW: single-file mode switch will reuse these =====
protocol = "rtp"  # can be "rtp" or "stun" or "rtcp" or "classicstun"
debug = False
start_packet_index = 1
end_packet_index = 275396
suspecious_flow = ("172.20.10.11", "172.20.10.10", 16393, 16393, 672257842, 100)

ssrc_set = set()
ssrc_set.add(0)  # keep 0 for discord etc.

VALID_PAYLOAD_TYPES = {0, 3, 4, 7, 8, 9, 13, 14, 15, 18, 26, 31, 32, 33, 34}
VALID_DYNAMIC_PAYLOAD_TYPES = range(96, 128)

def is_valid_payload_type(pt):
    return True  # keep permissive as in your version

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
        attr_type, attr_length = struct.unpack("!HH", packet_data[offset:offset+4])
        attr_value = packet_data[offset + 4: offset + 4 + attr_length]
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

def validate_rtp_info_list(message_info_list, packet_count):
    filtered_message_info_list = []
    flow_dict = defaultdict(list)
    global ssrc_set
    for msg in message_info_list:
        flow_id = (msg["flow_info"]["src_ip"], msg["flow_info"]["dst_ip"], msg["flow_info"]["src_port"], msg["flow_info"]["dst_port"], msg["ssrc"], msg["payload_type"])
        msg["processed"] = False
        flow_dict[flow_id].append(msg)
    for flow_id, messages in flow_dict.items():
        messages_sorted = sorted(messages, key=lambda x: (x["seq_num"], x["timestamp"]))
        clusters = []
        current_cluster = []
        processed_count = 0
        while processed_count < len(messages_sorted):
            for msg in messages_sorted:
                if msg["processed"]:
                    continue
                if not current_cluster:
                    current_cluster.append(msg)
                    msg["processed"] = True
                    processed_count += 1
                else:
                    last_msg = current_cluster[-1]
                    seq_diff = int(msg["seq_num"]) - int(last_msg["seq_num"])
                    ts_diff = int(msg["timestamp"]) - int(last_msg["timestamp"])
                    if seq_diff <= 10 and 0 <= ts_diff <= 100000:
                        current_cluster.append(msg)
                        msg["processed"] = True
                        processed_count += 1
                    else:
                        continue
            if current_cluster:
                clusters.append(current_cluster)
                current_cluster = []
        for cluster in clusters:
            if len(cluster) < 4:
                continue
            if len(cluster) < 500:
                packet_index_diff = [cluster[i]["packet_index"] - cluster[i - 1]["packet_index"] for i in range(1, len(cluster))]
                if sum(packet_index_diff) / len(packet_index_diff) > 100:
                    continue
                distinct_seq = set(pkt["seq_num"] for pkt in cluster)
                if len(distinct_seq) <= len(cluster) / 2:
                    continue
                if len(set(pkt["packet_index"] for pkt in cluster)) == 1:
                    continue
            distinct_seq = set(pkt["seq_num"] for pkt in cluster)
            if len(distinct_seq) <= 3:
                continue
            timestamps = [pkt["timestamp"] for pkt in sorted(cluster, key=lambda x: x["seq_num"])]
            timestamp_valid = True
            for i in range(1, len(timestamps)):
                if timestamps[i] < timestamps[i - 1] or timestamps[i] > timestamps[i - 1] + 100000:
                    timestamp_valid = False
                    break
            for pkt in cluster:
                filtered_message_info_list.append(pkt)
    if 1:
        print("RTP Info:")
        debug_flow_group = defaultdict(list)
        for pkt in filtered_message_info_list:
            flow_id = (pkt["flow_info"]["src_ip"], pkt["flow_info"]["dst_ip"], pkt["flow_info"]["src_port"], pkt["flow_info"]["dst_port"], pkt["ssrc"], pkt["payload_type"])
            debug_flow_group[flow_id].append(pkt)
        for flow_id, messages in debug_flow_group.items():
            print(f"Flow {flow_id[0]}:{flow_id[2]} -> {flow_id[1]}:{flow_id[3]} PT={flow_id[5]}: {len(messages)} packets")
            for pkt in messages:
                print(f"  RTP Packet {pkt['packet_index']} (chopped {pkt['chopped_bytes']} bytes), SSRC: {pkt['ssrc']}, Seq Num: {pkt['seq_num']}, Version: {pkt['version']}, Padding: {pkt['padding']}, Extension: {pkt['extension']}, CC: {pkt['cc']}, Marker: {pkt['marker']}, Payload Type: {pkt['payload_type']}, Timestamp: {pkt['timestamp']}")
    ssrc_set = set(pkt["ssrc"] for pkt in filtered_message_info_list)
    ssrc_set.add(0)
    return filtered_message_info_list

def validate_stun_info_list(message_info_list, packet_count):
    for message_info in message_info_list:
        if debug:
            if message_info["msg_length"] * 2 != len(message_info["attributes_string"]):
                message_info_list.remove(message_info)
    if 1:
        print("STUN Info:")
        for message_info in message_info_list:
            print(f"  STUN Packet {message_info['packet_index']} (chopped {message_info['chopped_bytes']} bytes), Msg Type: {message_info['msg_type']}, Msg Len: {message_info['msg_length']}, Trans ID: {message_info['transaction_id']}")
    return message_info_list

def validate_classic_stun_info_list(message_info_list, packet_count):
    if 1:
        print("Classic STUN Info:")
        for message_info in message_info_list:
            print(f"  Classic STUN Packet {message_info['packet_index']} (chopped {message_info['chopped_bytes']} bytes), Msg Type: {message_info['message_type']}, Msg Len: {message_info['message_length']}, Trans ID: {message_info['transaction_id']}")
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
                        protocol = "stun"; read_pcapng(file_path)
                        protocol = "rtp";  read_pcapng(file_path)
                        protocol = "rtcp"; read_pcapng(file_path)

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
                protocol = "rtp"; read_pcapng(file_path)
            else:
                protocol = "stun"; read_pcapng(file_path)
                protocol = "rtp";  read_pcapng(file_path)
                protocol = "rtcp"; read_pcapng(file_path)

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
    parser = argparse.ArgumentParser(description="Filter out background traffic from pcap files.")
    parser.add_argument("--multiprocess", action="store_true", help="Use multiprocessing for extraction.")
    parser.add_argument("--config", type=str, default="config.json", help="Path to the configuration file.")
    # ===== NEW: single-file mode =====
    parser.add_argument("--pcap", type=str, help="Path to a single pcap/pcapng to analyze (skips config.json).")
    args = parser.parse_args()

    # ===== NEW: if --pcap given, do single-file and exit =====
    if args.pcap:
        protocol = "stun"
        process_pcap_file(args.pcap)
        sys.exit(0)

    # original batch mode:
    config_path = args.config
    multiprocess = args.multiprocess
    pcap_main_folder, save_main_folder, apps, tests, rounds, client_types, precall_noise, postcall_noise, plugin_target_folder, plugin_source_folder = load_config(config_path)

    for app_name in apps:
        for test_name in tests:
            tasks = []
            task_names = []
            if "noise" in test_name:
                continue
            for test_round in rounds:
                for client_type in client_types:
                    for i in range(1, tests[test_name] + 1):
                        pcap_subfolder = f"{pcap_main_folder}/{app_name}"
                        pcap_file_name = f"{app_name}_{test_name}_{test_round}_{client_type}.pcapng"
                        pcap_file = f"{pcap_subfolder}/{pcap_file_name}"
                        tasks.append((pcap_file,))
                        task_names.append(f"{app_name}_{test_name}_{test_round}_{client_type}")

            processes = []
            process_start_times = []
            for i, task_args in enumerate(tasks):
                if multiprocess:
                    p = multiprocessing.Process(target=process_pcap_file, args=task_args)
                    process_start_times.append(time.time())
                    processes.append(p)
                    p.start()
                else:
                    print(f"Processing {task_args}")
                    process_pcap_file(*task_args)

            if multiprocess:
                if len(processes) == 0:
                    print(f"Skip {app_name} tasks.")
                    continue
                print(f"\n{app_name} tasks started.\n")
                lines = len(processes)
                elapsed_times = [0] * len(processes)
                print("\n" * lines, end="")
                while True:
                    all_finished = True
                    status = ""
                    for i, p in enumerate(processes):
                        if p.is_alive():
                            elapsed_time = int(time.time() - process_start_times[i])
                            elapsed_times[i] = elapsed_time
                            all_finished = False
                            status += f"Running\t|{elapsed_time}s\t|{task_names[i]}\n"
                        else:
                            elapsed_time = elapsed_times[i]
                            if p.exitcode is None:
                                status += f"Unknown\t|{elapsed_time}s\t|{task_names[i]}\n"
                            elif p.exitcode == 0:
                                status += f"Done\t|{elapsed_time}s\t|{task_names[i]}\n"
                            else:
                                status += f"Code {p.exitcode}\t|{elapsed_time}s\t|{task_names[i]}\n"
                    if status[-1] == "\n":
                        status = status[:-1]
                    print("\033[F" * lines, end="")
                    for _ in range(lines):
                        print("\033[K\n", end="")
                    print("\033[F" * lines, end="")
                    print(status)
                    if all_finished:
                        print(f"\nAll {app_name} tasks are finished. (Average Runtime: {sum(elapsed_times) / len(elapsed_times):.2f}s)")
                        break
                    time.sleep(1)
                for p in processes:
                    p.join()
