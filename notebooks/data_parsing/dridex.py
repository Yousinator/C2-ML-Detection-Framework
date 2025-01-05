import pyshark
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
import csv
from datetime import datetime
import numpy as np
import math


def calculate_entropy(data):
    """Calculate entropy for a sequence of bytes."""
    if len(data) == 0:
        return 0
    byte_counts = defaultdict(int)
    for byte in data:
        byte_counts[byte] += 1
    entropy = 0
    for count in byte_counts.values():
        prob = count / len(data)
        entropy -= prob * math.log2(prob)
    return entropy


def process_packet(packet):
    try:
        flow_key = (
            packet.ip.src,
            packet[packet.transport_layer].srcport,
            packet.ip.dst,
            packet[packet.transport_layer].dstport,
            packet.highest_layer,
        )

        timestamp = float(packet.sniff_timestamp)
        packet_length = int(packet.length)

        # Determine whether the packet is encrypted
        encrypted_bytes = int(packet.length) if hasattr(packet, "ssl") else 0

        # Entropy only for packets with raw data
        if hasattr(packet, "data"):
            entropy = calculate_entropy(bytes(packet.data.binary_value))
        else:
            entropy = 0

        return flow_key, timestamp, packet_length, encrypted_bytes, entropy
    except AttributeError:
        return None


def process_packets_batch(file_path, start, end):
    cap = pyshark.FileCapture(file_path, only_summaries=False, keep_packets=False, display_filter=f"frame.number >= {start} && frame.number <= {end}")
    flows = defaultdict(
        lambda: {
            "packets": 0,
            "total_bytes": 0,
            "encrypted_bytes": 0,
            "start_time": None,
            "end_time": None,
            "interpacket_sum": 0,
            "min_interval": float("inf"),
            "max_interval": 0,
            "entropy_sum": 0,
            "min_entropy": float("inf"),
            "max_entropy": 0,
        }
    )

    last_timestamps = {}

    for packet in cap:
        result = process_packet(packet)
        if result:
            flow_key, timestamp, packet_length, encrypted_bytes, entropy = result
            flow = flows[flow_key]
            flow["packets"] += 1
            flow["total_bytes"] += packet_length
            flow["encrypted_bytes"] += encrypted_bytes

            if flow["start_time"] is None:
                flow["start_time"] = timestamp
            flow["end_time"] = timestamp

            # Interpacket intervals
            if flow_key in last_timestamps:
                interval = timestamp - last_timestamps[flow_key]
                flow["interpacket_sum"] += interval
                flow["min_interval"] = min(flow["min_interval"], interval)
                flow["max_interval"] = max(flow["max_interval"], interval)
            last_timestamps[flow_key] = timestamp

            # Entropy
            flow["entropy_sum"] += entropy
            flow["min_entropy"] = min(flow["min_entropy"], entropy)
            flow["max_entropy"] = max(flow["max_entropy"], entropy)

    # Finalize interpacket averages
    for flow in flows.values():
        if flow["packets"] > 1:
            flow["avg_interval"] = flow["interpacket_sum"] / (flow["packets"] - 1)
        else:
            flow["avg_interval"] = 0

        if flow["min_interval"] == float("inf"):
            flow["min_interval"] = 0

        if flow["min_entropy"] == float("inf"):
            flow["min_entropy"] = 0

    return flows


def merge_flows(all_flows):
    final_flows = defaultdict(
        lambda: {
            "packets": 0,
            "total_bytes": 0,
            "encrypted_bytes": 0,
            "duration": 0,
            "avg_interval": 0,
            "min_interval": float("inf"),
            "max_interval": 0,
            "avg_entropy": 0,
            "min_entropy": float("inf"),
            "max_entropy": 0,
        }
    )

    for flows in all_flows:
        for key, flow in flows.items():
            final_flow = final_flows[key]
            final_flow["packets"] += flow["packets"]
            final_flow["total_bytes"] += flow["total_bytes"]
            final_flow["encrypted_bytes"] += flow["encrypted_bytes"]
            final_flow["duration"] += flow["end_time"] - flow["start_time"]

            final_flow["avg_interval"] += flow["avg_interval"]
            final_flow["min_interval"] = min(final_flow["min_interval"], flow["min_interval"])
            final_flow["max_interval"] = max(final_flow["max_interval"], flow["max_interval"])

            final_flow["avg_entropy"] += flow["entropy_sum"] / flow["packets"] if flow["packets"] > 0 else 0
            final_flow["min_entropy"] = min(final_flow["min_entropy"], flow["min_entropy"])
            final_flow["max_entropy"] = max(final_flow["max_entropy"], flow["max_entropy"])

    return final_flows


def write_to_csv(flows, file_name):
    fields = [
        "Duration",
        "Packets",
        "Bytes",
        "Encrypted Traffic Bytes",
        "Avg Interpacket Interval",
        "Min Interpacket Interval",
        "Max Interpacket Interval",
        "Avg Entropy",
        "Min Entropy",
        "Max Entropy",
    ]
    with open(file_name, "w", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fields)
        writer.writeheader()
        for key, data in flows.items():
            writer.writerow(
                {
                    "Duration": data["duration"],
                    "Packets": data["packets"],
                    "Bytes": data["total_bytes"],
                    "Encrypted Traffic Bytes": data["encrypted_bytes"],
                    "Avg Interpacket Interval": data["avg_interval"],
                    "Min Interpacket Interval": data["min_interval"],
                    "Max Interpacket Interval": data["max_interval"],
                    "Avg Entropy": data["avg_entropy"],
                    "Min Entropy": data["min_entropy"],
                    "Max Entropy": data["max_entropy"],
                }
            )


def process_large_pcap(file_path, output_csv, batch_size=1000):
    # Count total packets
    cap = pyshark.FileCapture(file_path, only_summaries=True)
    total_packets = sum(1 for _ in cap)
    cap.close()

    ranges = [(i, min(i + batch_size, total_packets)) for i in range(1, total_packets + 1, batch_size)]

    all_flows = []
    with ProcessPoolExecutor() as executor:
        results = executor.map(lambda r: process_packets_batch(file_path, *r), ranges)
        all_flows.extend(results)

    final_flows = merge_flows(all_flows)
    write_to_csv(final_flows, output_csv)


# Run
process_large_pcap("data/raw/pcap/dridex.pcap", "extracted_data.csv")

print("Data extraction and writing to CSV completed.")
