from scapy.all import Ether, IP, TCP, Raw, wrpcap, rdpcap
from collections import defaultdict
from sklearn.cluster import KMeans
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split
import random
import struct
import logging
import numpy as np
import os

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class Generation:
    def __init__(self):
        self.patterns = defaultdict(list)
        self.function_code_model = None
        self.field_model = None
        self.logging_enabled = True

    def train(self, pcap_dir):
        logging.info("[+] Learning patterns from .pcap files...")

        if not os.path.isdir(pcap_dir):
            logging.error(f"[-] Directory not found: {pcap_dir}")
            return

        try:
            features = []
            for root, _, files in os.walk(pcap_dir):
                for file in files:
                    if file.endswith(".pcap"):
                        pcap_file = os.path.join(root, file)
                        logging.info(f"[+] Processing {pcap_file}")
                        features.extend(self.extract_features(pcap_file))

            if not features:
                logging.error("[-] No features extracted for training.")
                return

            features = np.array(features)
            self.train_function_code_model(features)
            self.train_field_model(features)
            logging.info("[+] Patterns learned and models trained successfully.")
        except Exception as e:
            logging.error(f"[-] Error during training: {e}")

    def extract_features(self, pcap_file):
        features = []
        valid_function_codes = [1, 2, 3, 4, 5, 6, 15, 16, 23]

        try:
            packets = rdpcap(pcap_file)
            logging.info(f"[+] Processing {pcap_file} with {len(packets)} packets")
            for packet in packets:
                if TCP in packet and Raw in packet:
                    payload = packet[Raw].load
                    if packet[TCP].dport == 502:  
                        if len(payload) >= 8:
                            func_code = payload[7]
                            if func_code in valid_function_codes:
                                start_addr = int.from_bytes(payload[8:10], byteorder="big")
                                quantity = int.from_bytes(payload[10:12], byteorder="big")
                                features.append([func_code, start_addr, quantity])
        except Exception as e:
            logging.error(f"[-] Error processing {pcap_file}: {e}")
        return features

    def train_function_code_model(self, features):
        if not features or len(features) == 0:
            logging.error("[-] No features extracted for training function code model.")
            return
        
        function_codes = np.array([[f[0]] for f in features])
        n_clusters = min(3, len(np.unique(function_codes)))
        if n_clusters <= 0:
            logging.error("[-] Cannot train function code model: not enough unique function codes.")
            return
            
        self.function_code_model = KMeans(n_clusters=n_clusters)  
        self.function_code_model.fit(function_codes)
        logging.info("[+] Function code model trained successfully.")

    def train_field_model(self, features):
        if not features or len(features) == 0:
            logging.error("[-] No features extracted for training field model.")
            return
        
        X = features[:, 0].reshape(-1, 1)  
        y = features[:, 1:] 
            
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        self.field_model = RandomForestRegressor(n_estimators=100, random_state=42)
        self.field_model.fit(X_train, y_train)
        logging.info("[+] Field model trained successfully.")

    def generate_modbus_query_packet(self):
        return self._generate_modbus_packet(is_response=False)

    def generate_modbus_response_packet(self):
        return self._generate_modbus_packet(is_response=True)

    def _generate_modbus_packet(self, is_response=False):
        valid_function_codes = [1, 2, 3, 4, 5, 6, 15, 16, 23]

        if self.function_code_model:
            cluster_idx = np.random.randint(0, len(self.function_code_model.cluster_centers_))
            func_code = int(self.function_code_model.cluster_centers_[cluster_idx][0])
            if func_code not in valid_function_codes:
                func_code = random.choice(valid_function_codes)
        else:
            func_code = random.choice(valid_function_codes)

        if self.field_model:
            predicted_values = self.field_model.predict([[func_code]])
            start_addr = int(max(0, predicted_values[0][0]))
            quantity = int(max(1, predicted_values[0][1]))
        else:
            start_addr = random.randint(0, 65535)
            quantity = random.randint(1, 200)

        if func_code in [1, 2, 3, 4, 15, 16] and quantity > 125:
            quantity = 125

        try:
            if is_response:
                return self._generate_modbus_response(func_code, start_addr, quantity)
            else:
                return self._generate_modbus_query(func_code, start_addr, quantity)
        except Exception as e:
            logging.error(f"[-] Error generating Modbus packet: {e}")
            return None
            
    def _generate_modbus_query(self, func_code, start_addr, quantity):
        if func_code in [1, 2, 3, 4]:
            pdu = (
                func_code.to_bytes(1, byteorder="big") +
                start_addr.to_bytes(2, byteorder="big") +
                quantity.to_bytes(2, byteorder="big")
            )
        elif func_code in [5, 6]:
            value = quantity  
            pdu = (
                func_code.to_bytes(1, byteorder="big") +
                start_addr.to_bytes(2, byteorder="big") +
                value.to_bytes(2, byteorder="big")
            )
        elif func_code in [15, 16]:
            byte_count = (quantity + 7) // 8 if func_code == 15 else quantity * 2
            values = bytes([0xFF for _ in range(byte_count)])
            pdu = (
                func_code.to_bytes(1, byteorder="big") +
                start_addr.to_bytes(2, byteorder="big") +
                quantity.to_bytes(2, byteorder="big") +
                byte_count.to_bytes(1, byteorder="big") +
                values
            )
        elif func_code == 23:
            read_start_addr = start_addr
            read_quantity = quantity
            write_start_addr = start_addr + quantity
            write_quantity = quantity
            write_byte_count = write_quantity * 2
            write_values = bytes([0xFF for _ in range(write_byte_count)])
            pdu = (
                func_code.to_bytes(1, byteorder="big") +
                read_start_addr.to_bytes(2, byteorder="big") +
                read_quantity.to_bytes(2, byteorder="big") +
                write_start_addr.to_bytes(2, byteorder="big") +
                write_quantity.to_bytes(2, byteorder="big") +
                write_byte_count.to_bytes(1, byteorder="big") +
                write_values
            )
        else:
            raise ValueError(f"Unsupported function code: {func_code}")

        trans_id = random.randint(0, 65535)
        proto_id = 0x0000
        length = len(pdu) + 1
        unit_id = 0x01

        mbap_header = (
            trans_id.to_bytes(2, byteorder="big") +
            proto_id.to_bytes(2, byteorder="big") +
            length.to_bytes(2, byteorder="big") +
            unit_id.to_bytes(1, byteorder="big")
        )

        modbus_packet = mbap_header + pdu

        return Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=random.randint(1024, 65535), dport=502, flags="PA") / Raw(load=modbus_packet)

    def _generate_modbus_response(self, func_code, start_addr, quantity):
        """Generate a Modbus response PDU based on function code."""
        if func_code in [1, 2]:
            byte_count = (quantity + 7) // 8
            values = bytes([random.randint(0, 255) for _ in range(byte_count)])
            pdu = (
                func_code.to_bytes(1, byteorder="big") +
                byte_count.to_bytes(1, byteorder="big") +
                values
            )
        elif func_code in [3, 4]:
            byte_count = quantity * 2
            values = bytes([random.randint(0, 255) for _ in range(byte_count)])
            pdu = (
                func_code.to_bytes(1, byteorder="big") +
                byte_count.to_bytes(1, byteorder="big") +
                values
            )
        elif func_code in [5, 6]:
            pdu = (
                func_code.to_bytes(1, byteorder="big") +
                start_addr.to_bytes(2, byteorder="big") +
                quantity.to_bytes(2, byteorder="big") 
            )
        elif func_code in [15, 16]:
            pdu = (
                func_code.to_bytes(1, byteorder="big") +
                start_addr.to_bytes(2, byteorder="big") +
                quantity.to_bytes(2, byteorder="big")
            )
        elif func_code == 23:
            read_byte_count = quantity * 2
            read_values = bytes([random.randint(0, 255) for _ in range(read_byte_count)])
            pdu = (
                func_code.to_bytes(1, byteorder="big") +
                read_byte_count.to_bytes(1, byteorder="big") +
                read_values
            )
        else:
            raise ValueError(f"Unsupported function code: {func_code}")

        trans_id = random.randint(0, 65535)
        proto_id = 0x0000
        length = len(pdu) + 1
        unit_id = 0x01

        mbap_header = (
            trans_id.to_bytes(2, byteorder="big") +
            proto_id.to_bytes(2, byteorder="big") +
            length.to_bytes(2, byteorder="big") +
            unit_id.to_bytes(1, byteorder="big")
        )

        modbus_packet = mbap_header + pdu

        return Ether() / IP(src="192.168.1.2", dst="192.168.1.1") / TCP(sport=502, dport=random.randint(1024, 65535), flags="PA") / Raw(load=modbus_packet)
        modbus_packet = mbap_header + pdu

    def generate_modbus_packet(self):
        valid_function_codes = [1, 2, 3, 4, 5, 6, 15, 16, 23]

        if self.function_code_model:
            cluster_idx = np.random.randint(0, len(self.function_code_model.cluster_centers_))
            func_code = int(self.function_code_model.cluster_centers_[cluster_idx][0])
            if func_code not in valid_function_codes:
                func_code = random.choice(valid_function_codes)
        else:
            func_code = random.choice(valid_function_codes)

        if self.field_model:
            predicted_values = self.field_model.predict([[func_code]])
            start_addr = int(max(0, predicted_values[0][0]))  
            quantity = int(max(1, predicted_values[0][1])) 
        else:
            start_addr = random.randint(0, 65535)
            quantity = random.randint(1, 200)

        if func_code in [1, 2, 3, 4, 15, 16] and quantity > 125:
            quantity = 125

        try:
            if func_code in [1, 2, 3, 4]:  
                pdu = (
                    func_code.to_bytes(1, byteorder="big") +
                    start_addr.to_bytes(2, byteorder="big") +
                    quantity.to_bytes(2, byteorder="big")
                )
            elif func_code in [5, 6]: 
                value = quantity  
                pdu = (
                    func_code.to_bytes(1, byteorder="big") +
                    start_addr.to_bytes(2, byteorder="big") +
                    value.to_bytes(2, byteorder="big")
                )
            elif func_code in [15, 16]: 
                byte_count = (quantity + 7) // 8 if func_code == 15 else quantity * 2
                values = bytes([0xFF for _ in range(byte_count)]) 
                pdu = (
                    func_code.to_bytes(1, byteorder="big") +
                    start_addr.to_bytes(2, byteorder="big") +
                    quantity.to_bytes(2, byteorder="big") +
                    byte_count.to_bytes(1, byteorder="big") +
                    values
                )
            elif func_code == 23:  
                read_start_addr = start_addr
                read_quantity = quantity
                write_start_addr = start_addr + quantity
                write_quantity = quantity
                write_byte_count = write_quantity * 2
                write_values = bytes([0xFF for _ in range(write_byte_count)])
                pdu = (
                    func_code.to_bytes(1, byteorder="big") +
                    read_start_addr.to_bytes(2, byteorder="big") +
                    read_quantity.to_bytes(2, byteorder="big") +
                    write_start_addr.to_bytes(2, byteorder="big") +
                    write_quantity.to_bytes(2, byteorder="big") +
                    write_byte_count.to_bytes(1, byteorder="big") +
                    write_values
                )
            else:
                raise ValueError(f"Unsupported function code: {func_code}")

            trans_id = random.randint(0, 65535)  
            proto_id = 0x0000  
            length = len(pdu) + 1 
            unit_id = 0x01 

            mbap_header = (
                trans_id.to_bytes(2, byteorder="big") +
                proto_id.to_bytes(2, byteorder="big") +
                length.to_bytes(2, byteorder="big") +
                unit_id.to_bytes(1, byteorder="big")
            )

            modbus_packet = mbap_header + pdu

            return Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(dport=502, sport=random.randint(1024, 65535), flags="PA") / Raw(load=modbus_packet)
        except Exception as e:
            logging.error(f"[-] Error generating Modbus packet: {e}")
            return None

    def generate_corpus(self, num_samples=20, output_file="new_packets.pcap", protocol="modbus"):
        synthetic_packets = []

        for _ in range(num_samples):
            query_packet = self.generate_modbus_query_packet()
            response_packet = self.generate_modbus_response_packet()
            if query_packet:
                synthetic_packets.append(query_packet)
            if response_packet:
                synthetic_packets.append(response_packet)

        wrpcap(output_file, synthetic_packets)
        logging.info(f"[+] Generated {len(synthetic_packets)} {protocol} packets and saved to {output_file}")
        return synthetic_packets

                    
        