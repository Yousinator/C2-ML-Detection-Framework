import pyshark
import csv
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
import datetime

def parse_timestamp(ts):
    return datetime.datetime.fromtimestamp(float(ts))

# TCP flag mapping from hexadecimal to letters
tcp_flag_mapping = {
    0x01: 'FIN',
    0x02: 'SYN',
    0x04: 'RST',
    0x08: 'PSH',
    0x10: 'ACK',
    0x20: 'URG',
    0x40: 'ECE',
    0x80: 'CWR'
}

def parse_tcp_flags(flag_hex):
    # Map the flag hexadecimal string to its letter representation
    flags = []
    flag_hex = int(flag_hex, 16)  # Convert from hex to int for bit manipulation
    for bit, letter in tcp_flag_mapping.items():
        if flag_hex & bit:
            flags.append(letter)
    return ''.join(flags) if flags else 'UNK'  # Return 'UNK' if no flags

def extract_packet_data(packet):
    try:
        flow_key = (
            packet.ip.src,
            packet[packet.transport_layer].srcport,
            packet.ip.dst,
            packet[packet.transport_layer].dstport,
            packet.highest_layer,
        )
        # Capture flags directly in hex and parse them
        packet_info = {
            "timestamp": parse_timestamp(packet.sniff_timestamp),
            "bytes": int(packet.length),
            "flags": parse_tcp_flags(getattr(packet.tcp, "flags", "0")) if "TCP" in packet else "UNK",
        }
        return flow_key, packet_info
    except AttributeError:
        return None

def process_packets(file_path):
    cap = pyshark.FileCapture(file_path, only_summaries=False, keep_packets=False)
    flows = defaultdict(
        lambda: {
            "packets": 0,
            "total_bytes": 0,
            "start_time": None,
            "end_time": None,
            "flags": set(),
        }
    )

    with ThreadPoolExecutor() as executor:
        for result in executor.map(extract_packet_data, cap):
            if result:
                flow_key, packet_info = result
                flow = flows[flow_key]
                flow["packets"] += 1
                flow["total_bytes"] += packet_info["bytes"]
                flow["flags"].add(packet_info["flags"])
                if (
                    flow["start_time"] is None
                    or packet_info["timestamp"] < flow["start_time"]
                ):
                    flow["start_time"] = packet_info["timestamp"]
                if (
                    flow["end_time"] is None
                    or packet_info["timestamp"] > flow["end_time"]
                ):
                    flow["end_time"] = packet_info["timestamp"]

    # Calculate duration and convert flags set to string
    for flow in flows.values():
        flow["duration"] = (flow["end_time"] - flow["start_time"]).total_seconds()
        flow["flags"] = "".join(sorted(flow["flags"]))

    return flows

import csv

def write_to_csv(flows, file_name):
    # Rearranged fields according to the specified order
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
        "Flows",
        "Label",
    ]

    with open(file_name, "w", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fields)
        writer.writeheader()

        for key, data in flows.items():
            # Convert flags to 'UNK' if they are empty or contain '0'
            flags_value = data["flags"] if data["flags"] else 'UNK'
            writer.writerow(
                {
                    "Duration": data["duration"],
                    "Source IP": key[0],                 # Rearranged to match new order
                    "Destination IP": key[2],            # Rearranged to match new order
                    "Source Port": key[1],               # Rearranged to match new order
                    "Destination Port": key[3],          # Rearranged to match new order
                    "Protocol": key[4],                  # Unchanged
                    "Flags": flags_value,                 # Unchanged
                    "Packets": data["packets"],          # Unchanged
                    "Bytes": data["total_bytes"],        # Unchanged
                    "Flows": 1,                           # Unchanged
                    "Label": "Benign",                   # Unchanged
                }
            )


# Path to the pcap file
pcap_file_path = r"C:\Users\omar abuhassan\OneDrive\Desktop\work\ScytheEx-AI\classical_ml\data\raw\pcap\emotet.pcap"

# Extract data
extracted_flows = process_packets(pcap_file_path)
# Write data to CSV
write_to_csv(extracted_flows, "extracted_data.csv")

print("Data extraction and writing to CSV completed.")