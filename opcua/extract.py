# import pyshark

# pcap_file = "/home/garlicbread/opcua/OPCUA-Binary.pcap"

# cap = pyshark.FileCapture(pcap_file, display_filter="opcua")

# for packet in cap:
#     try:
#         print(packet)
#     except Exception as e:
#         print(f"Error parsing packet: {e}")

# cap.close()

from scapy.all import rdpcap, Raw, IP, TCP, UDP
import pandas as pd

pcap_file = "/home/garlicbread/opcua/OPCUA-Binary.pcap"

packets = rdpcap(pcap_file)

packet_data = []

for packet in packets:
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        else:
            src_ip, dst_ip = None, None

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            src_port, dst_port = None, None

        raw_payload = packet[Raw].load.hex()[:100] if Raw in packet else None

        packet_data.append({
            "timestamp": packet.time,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "opcua_payload": raw_payload
        })

    except Exception as e:
        print(f"Error parsing packet: {e}")

df = pd.DataFrame(packet_data)

csv_path = "features.csv"
df.to_csv(csv_path, index=False)

print(f"Feature extraction complete. Saved to {csv_path}")
