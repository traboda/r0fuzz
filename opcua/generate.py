import torch
import numpy as np
import pandas as pd
from scapy.all import Ether, IP, TCP, Raw, wrpcap, rdpcap
import os
import binascii
import struct

print("Starting packet generation script...")

try:
    csv_path = "/home/garlicbread/opcua/features.csv"
    print(f"Loading data from {csv_path}")
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} rows from CSV")

    original_pcap_path = "/home/garlicbread/opcua/OPCUA-Binary.pcap"
    print(f"Loading original packets from {original_pcap_path}")
    original_packets = rdpcap(original_pcap_path)
    print(f"Loaded {len(original_packets)} original packets for header templates")
    
    read_request_template = None
    read_response_template = None
    write_request_template = None
    write_response_template = None
    
    for packet in original_packets:
        if TCP in packet and Raw in packet:
            payload = bytes(packet[Raw].load)
            if len(payload) >= 8: 
                message_type_byte = payload[0] if len(payload) > 0 else 0
                message_length = len(payload)
                
                if message_length > 140 and message_length < 145:
                    read_request_template = payload
                elif message_length > 125 and message_length < 130:
                    read_response_template = payload
                elif message_length > 145 and message_length < 150:
                    write_request_template = payload
                elif message_length > 105 and message_length < 110:
                    write_response_template = payload
    
    if not read_request_template:
        read_request_template = bytearray(143)
        read_request_template[0:4] = b"OPCU"  
        read_request_template[4:8] = struct.pack("<I", 143) 
        read_request_template[12:16] = struct.pack("<I", 0x000004D2)  
    
    if not read_response_template:
        read_response_template = bytearray(126)
        read_response_template[0:4] = b"OPCU" 
        read_response_template[4:8] = struct.pack("<I", 126) 
        read_response_template[12:16] = struct.pack("<I", 0x000004D5)  
    
    if not write_request_template:
        write_request_template = bytearray(147)
        write_request_template[0:4] = b"OPCU"  
        write_request_template[4:8] = struct.pack("<I", 147)  
        write_request_template[12:16] = struct.pack("<I", 0x000004D3)  
    
    if not write_response_template:
        write_response_template = bytearray(108)
        write_response_template[0:4] = b"OPCU"  
        write_response_template[4:8] = struct.pack("<I", 108) 
        write_response_template[12:16] = struct.pack("<I", 0x000004D6) 
    
    packet_templates = {
        "read_request": read_request_template,
        "read_response": read_response_template,
        "write_request": write_request_template,
        "write_response": write_response_template
    }
    
    packet_sizes = {
        "read_request": 143,
        "read_response": 126,
        "write_request": 147,
        "write_response": 108
    }
    
    print("Packet templates extracted or created")
    
    num_packets = 100
    print(f"Generating {num_packets} synthetic packets...")
    
    covert_message = "covertchannelisastealthyattack"
    covert_packets = []
    
    first_segment = "covertchannelisa"
    for char in first_segment:
        binary = format(ord(char), '08b')
        for bit in binary:
            if bit == '0':
                covert_packets.append(("write_request", packet_templates["write_request"]))
                covert_packets.append(("write_response", packet_templates["write_response"]))
            else:
                covert_packets.append(("read_request", packet_templates["read_request"]))
                covert_packets.append(("read_response", packet_templates["read_response"]))
    
    second_segment = "stealthyattack"
    for char in second_segment:
        binary = format(ord(char), '08b')
        for bit in binary:
            if bit == '0':
                covert_packets.append(("read_request", packet_templates["read_request"]))
            else:
                covert_packets.append(("read_response", packet_templates["read_response"]))
    
    remaining = num_packets - len(covert_packets)
    if remaining > 0:
        packet_types = list(packet_templates.keys())
        for _ in range(remaining):
            packet_type = np.random.choice(packet_types)
            covert_packets.append((packet_type, packet_templates[packet_type]))
    
    tcp_templates = []
    for packet in original_packets:
        if TCP in packet:
            tcp_templates.append({
                'sport': packet[TCP].sport,
                'dport': packet[TCP].dport,
                'flags': packet[TCP].flags
            })
    
    if not tcp_templates:
        tcp_templates = [{'sport': 4840, 'dport': 4840, 'flags': 'PA'}]
    
    synthetic_packets = []
    
    for i, (packet_type, template) in enumerate(covert_packets):
        if i >= num_packets:
            break
            
        payload = bytearray(template)
        
        
        random_data_start = 24  
        for j in range(random_data_start, len(payload)):
            if j % 16 != 0: 
                payload[j] = np.random.randint(0, 255)
        
        payload_size = len(payload)
        payload[4:8] = struct.pack("<I", payload_size)
        
        
        identifier_offset = 20
        if identifier_offset + 4 <= len(payload):
            payload[identifier_offset:identifier_offset+4] = struct.pack("<I", i+1000)
        
        tcp_idx = i % len(tcp_templates)
        
        try:
            packet = (Ether() / 
                     IP(src="192.168.1.100", dst="192.168.1.200") / 
                     TCP(
                         sport=tcp_templates[tcp_idx]['sport'],
                         dport=tcp_templates[tcp_idx]['dport'],
                         flags=tcp_templates[tcp_idx]['flags'],
                         seq=np.random.randint(1000, 9000),
                         ack=np.random.randint(1000, 9000)
                     ) /
                     Raw(load=bytes(payload)))
            
            synthetic_packets.append(packet)
            
            if packet_type.endswith("_request") and i+1 < num_packets:
                response_type = packet_type.replace("request", "response")
                if response_type in packet_templates:
                    response_payload = bytearray(packet_templates[response_type])
                    
                    response_size = len(response_payload)
                    response_payload[4:8] = struct.pack("<I", response_size)
                    
                    if identifier_offset + 4 <= len(response_payload):
                        response_payload[identifier_offset:identifier_offset+4] = payload[identifier_offset:identifier_offset+4]
                    
                    response = (Ether() / 
                              IP(dst="192.168.1.100", src="192.168.1.200") / 
                              TCP(
                                  dport=tcp_templates[tcp_idx]['sport'],
                                  sport=tcp_templates[tcp_idx]['dport'],
                                  flags='PA',
                                  seq=packet[TCP].ack,
                                  ack=packet[TCP].seq + len(payload)
                              ) /
                              Raw(load=bytes(response_payload)))
                    
                    synthetic_packets.append(response)
                    i += 1  
        
        except Exception as e:
            print(f"Error creating packet {i}: {str(e)}")
    
    output_dir = "data"
    os.makedirs(output_dir, exist_ok=True)
    pcap_file = os.path.join(output_dir, "opcua.pcap")
    wrpcap(pcap_file, synthetic_packets)
    print(f"Successfully wrote {len(synthetic_packets)} packets to {pcap_file}")
    
    log_file = os.path.join(output_dir, "packet_log.txt")
    with open(log_file, 'w') as f:
        for i, (packet_type, _) in enumerate(covert_packets[:len(synthetic_packets)]):
            f.write(f"Packet {i+1}: {packet_type} ({packet_sizes[packet_type]} bytes)\n")
    
    print(f"Created packet log at {log_file}")

except Exception as e:
    print(f"ERROR: {str(e)}")
    import traceback
    traceback.print_exc()