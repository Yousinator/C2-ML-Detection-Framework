import pyshark
import csv
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
import datetime
import numpy as np


# TCP flag mapping from hexadecimal to letters
tcp_flag_mapping = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x40: "ECE",
    0x80: "CWR",
}


def parse_timestamp(ts):
    return datetime.datetime.fromtimestamp(float(ts))


def parse_tcp_flags(flag_hex):
    """Map TCP flags from hexadecimal to letters."""
    flags = []
    flag_hex = int(flag_hex, 16)  # Convert from hex to int for bit manipulation
    for bit, letter in tcp_flag_mapping.items():
        if flag_hex & bit:
            flags.append(letter)
    return "".join(flags) if flags else "UNK"


def calculate_entropy(data):
    """Calculate entropy of payload data."""
    if not data:
        return 0
    byte_arr = np.frombuffer(data.encode("utf-8", errors="ignore"), dtype=np.uint8)
    prob = np.bincount(byte_arr, minlength=256) / len(byte_arr)
    prob = prob[prob > 0]
    return -np.sum(prob * np.log2(prob))


def extract_packet_data(packet):

    try:
        flow_key = (
            packet.ip.src,
            packet[packet.transport_layer].srcport,
            packet.ip.dst,
            packet[packet.transport_layer].dstport,
            packet.highest_layer,
        )
        print("Done with Flow Key")
        # Extract payload, flags, and timestamp
        payload_size = int(packet.length) - int(packet.ip.hdr_len)
        payload = packet.tcp.payload if hasattr(packet.tcp, "payload") else ""
        print("Done with payload")
        entropy = calculate_entropy(payload)
        timestamp = parse_timestamp(packet.sniff_timestamp)
        flags = (
            parse_tcp_flags(getattr(packet.tcp, "flags", "0"))
            if "TCP" in packet
            else "UNK"
        )
        print("Fuck it")

        return flow_key, {
            "timestamp": timestamp,
            "payload_size": payload_size,
            "entropy": entropy,
            "flags": flags,
        }
    except AttributeError:
        return None


def process_packets(file_path):
    print("Opened")
    cap = pyshark.FileCapture(file_path, only_summaries=False, keep_packets=False)
    flows = defaultdict(
        lambda: {
            "timestamps": [],
            "payload_sizes": [],
            "entropies": [],
            "flags": set(),
            "packets": 0,
            "total_bytes": 0,
        }
    )

    with ThreadPoolExecutor() as executor:
        print("Started Executing")

        for result in executor.map(extract_packet_data, cap):
            if result:
                flow_key, packet_info = result
                flow = flows[flow_key]
                flow["timestamps"].append(packet_info["timestamp"])
                flow["payload_sizes"].append(packet_info["payload_size"])
                flow["entropies"].append(packet_info["entropy"])
                flow["flags"].add(packet_info["flags"])
                flow["packets"] += 1
                flow["total_bytes"] += packet_info["payload_size"]

        # Post-process each flow
        for flow in flows.values():
            print("Started Flows")
            timestamps = sorted(flow["timestamps"])
            inter_packet_interval = (
                np.diff([ts.timestamp() for ts in timestamps])
                if len(timestamps) > 1
                else [0]
            )
            flow["duration"] = (
                (timestamps[-1] - timestamps[0]).total_seconds()
                if len(timestamps) > 1
                else 0
            )
            flow["mean_payload_size"] = (
                np.mean(flow["payload_sizes"]) if flow["payload_sizes"] else 0
            )
            flow["std_payload_size"] = (
                np.std(flow["payload_sizes"]) if flow["payload_sizes"] else 0
            )
            flow["min_payload_size"] = (
                min(flow["payload_sizes"]) if flow["payload_sizes"] else 0
            )
            flow["max_payload_size"] = (
                max(flow["payload_sizes"]) if flow["payload_sizes"] else 0
            )
            flow["mean_entropy"] = (
                np.mean(flow["entropies"]) if flow["entropies"] else 0
            )
            flow["min_entropy"] = min(flow["entropies"]) if flow["entropies"] else 0
            flow["max_entropy"] = max(flow["entropies"]) if flow["entropies"] else 0
            flow["flags"] = "".join(sorted(flow["flags"]))
            flow["mean_inter_packet_interval"] = (
                np.mean(inter_packet_interval) if flow["payload_sizes"] else 0
            )
            flow["min_inter_packet_interval"] = (
                min(inter_packet_interval) if flow["payload_sizes"] else 0
            )
            flow["max_inter_packet_interval"] = (
                max(inter_packet_interval) if flow["payload_sizes"] else 0
            )

    return flows


def write_to_csv(flows, file_name):
    fields = [
        "Duration",
        "Source IP",
        "Destination IP",
        "Source Port",
        "Destination Port",
        "Protocol",
        "Flags",
        "Packets",
        "Bytes",
        "Mean Payload Size",
        "Std Payload Size",
        "Min Payload Size",
        "Max Payload Size",
        "Mean Entropy",
        "Min Entropy",
        "Max Entropy",
        "Mean Inter-Packet Interval",
        "Min Inter-Packet Interval",
        "Max Inter-Packet Interval",
    ]
    with open(file_name, "w", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fields)
        writer.writeheader()
        for key, data in flows.items():
            writer.writerow(
                {
                    "Duration": data["duration"],
                    "Protocol": key[4],
                    "Flags": data["flags"],
                    "Packets": data["packets"],
                    "Bytes": data["total_bytes"],
                    "Mean Payload Size": data["mean_payload_size"],
                    "Std Payload Size": data["std_payload_size"],
                    "Min Payload Size": data["min_payload_size"],
                    "Max Payload Size": data["max_payload_size"],
                    "Mean Entropy": data["mean_entropy"],
                    "Min Entropy": data["min_entropy"],
                    "Max Entropy": data["max_entropy"],
                    "Mean Inter-Packet Interval": data["mean_inter_packet_interval"],
                    "Min Inter-Packet Interval": data["min_inter_packet_interval"],
                    "Max Inter-Packet Interval": data["max_inter_packet_interval"],
                    "Source IP": key[0],
                    "Source Port": key[1],
                    "Destination IP": key[2],
                    "Destination Port": key[3],
                }
            )


# Path to the pcap file
pcap_file_path = r"data/raw/pcap/collection.pcap"

# Extract data
extracted_flows = process_packets(pcap_file_path)
# Write data to CSV
write_to_csv(extracted_flows, "data/raw/csv/collection.csv")

print("Data extraction and writing to CSV completed.")
