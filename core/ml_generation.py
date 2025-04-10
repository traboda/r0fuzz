from scapy.all import Ether, IP, TCP, Raw, wrpcap, rdpcap
from collections import defaultdict
from sklearn.cluster import KMeans
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split
import random
import logging
import numpy as np
import os
import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class Generation:
    def __init__(self):
        self.patterns = defaultdict(list)
        self.function_code_model = None
        self.field_model = None
        self.logging_enabled = True

    def train(self, pcap_path):
        """
        Learn patterns from PCAP file(s).
        Args:
            pcap_path (str): Path to a PCAP file or a directory of PCAP files.
        Returns:
            bool: True if training succeeded, False otherwise.
        """
        logging.info(f"[+] Learning patterns from PCAP source: {pcap_path}")
        
        features = []
        pcap_count = 0
        
        try:
            if not os.path.exists(pcap_path):
                logging.error(f"[-] The specified path does not exist: {pcap_path}")
                return False

            if os.path.isfile(pcap_path):
                if pcap_path.lower().endswith(".pcap"):
                    logging.info(f"[+] Processing single PCAP file: {pcap_path}")
                    file_features = self.extract_features(pcap_path)
                    if file_features:
                        features.extend(file_features)
                        pcap_count = 1
                        logging.info(f"[+] Successfully processed {pcap_path} with {len(file_features)} features extracted")
                    else:
                        logging.warning(f"[!] No valid Modbus/TCP features found in {pcap_path}")
                        return False
                else:
                    logging.error(f"[-] File is not a .pcap file: {pcap_path}")
                    return False

            elif os.path.isdir(pcap_path):
                logging.info(f"[+] Processing directory of PCAP files: {pcap_path}")
                processed_files = 0
                for root, _, files in os.walk(pcap_path):
                    for file in files:
                        if file.lower().endswith(".pcap"):
                            pcap_file = os.path.join(root, file)
                            try:
                                logging.info(f"[+] Processing {pcap_file}")
                                file_features = self.extract_features(pcap_file)
                                if file_features:
                                    features.extend(file_features)
                                    processed_files += 1
                                    logging.info(f"[+] Processed {pcap_file} with {len(file_features)} features")
                                else:
                                    logging.warning(f"[!] No valid Modbus/TCP features found in {pcap_file}")
                            except Exception as e:
                                logging.error(f"[-] Error processing {pcap_file}: {e}")
                                continue
                
                pcap_count = processed_files
                if pcap_count == 0:
                    logging.error(f"[-] No valid .pcap files with Modbus/TCP traffic found in {pcap_path}")
                    return False

            else:
                logging.error(f"[-] Path is neither a file nor directory: {pcap_path}")
                return False

            if not features:
                logging.error("[-] No features extracted for training.")
                return False

            # Convert to numpy array for ML processing
            features = np.array(features)
            
            # Train models
            self.train_function_code_model(features)
            self.train_field_model(features)
            
            logging.info(f"[+] Successfully learned patterns from {pcap_count} file(s)")
            logging.info(f"[+] Function code model: {'trained' if self.function_code_model else 'not trained'}")
            logging.info(f"[+] Field model: {'trained' if self.field_model else 'not trained'}")
            
            return True

        except Exception as e:
            logging.error(f"[-] Error during training: {str(e)}", exc_info=True)
            return False

    def extract_features(self, pcap_file):
        features = []
        valid_function_codes = [1, 2, 3, 4, 5, 6, 15, 16, 23]
        packet_count = 0
        modbus_packet_count = 0

        try:
            packets = rdpcap(pcap_file)
            logging.debug(f"[+] Processing {pcap_file} with {len(packets)} packets")
            
            for packet in packets:
                packet_count += 1
                try:
                    if TCP in packet and Raw in packet:
                        payload = packet[Raw].load
                        # Check for Modbus/TCP (port 502)
                        if packet[TCP].dport == 502 or packet[TCP].sport == 502:
                            if len(payload) >= 8:  # Minimum Modbus/TCP PDU length
                                func_code = payload[7]
                                if func_code in valid_function_codes:
                                    start_addr = int.from_bytes(payload[8:10], byteorder="big")
                                    quantity = int.from_bytes(payload[10:12], byteorder="big")
                                    features.append([func_code, start_addr, quantity])
                                    modbus_packet_count += 1
                except Exception as e:
                    logging.debug(f"[!] Error processing packet {packet_count}: {str(e)}")
                    continue
            
            logging.info(f"[+] Processed {packet_count} packets, found {modbus_packet_count} valid Modbus/TCP packets in {pcap_file}")
            
        except Exception as e:
            logging.error(f"[-] Error reading pcap file {pcap_file}: {str(e)}")
        
        return features

    def train_function_code_model(self, features):
        if not features.any():
            logging.error("[-] No features to train function code model.")
            return

        function_codes = np.array([[f[0]] for f in features])
        unique_codes = np.unique(function_codes)
        n_clusters = min(3, len(unique_codes))

        if n_clusters <= 0:
            logging.error("[-] Cannot train function code model: not enough unique function codes.")
            return

        self.function_code_model = KMeans(n_clusters=n_clusters)
        self.function_code_model.fit(function_codes)
        logging.info(f"[+] Function code model trained successfully with {n_clusters} clusters.")

    def train_field_model(self, features):
        if not features.any():
            logging.error("[-] No features to train field model.")
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
            pdu = func_code.to_bytes(1, "big") + start_addr.to_bytes(2, "big") + quantity.to_bytes(2, "big")
        elif func_code in [5, 6]:
            pdu = func_code.to_bytes(1, "big") + start_addr.to_bytes(2, "big") + quantity.to_bytes(2, "big")
        elif func_code in [15, 16]:
            byte_count = (quantity + 7) // 8 if func_code == 15 else quantity * 2
            values = bytes([0xFF for _ in range(byte_count)])
            pdu = func_code.to_bytes(1, "big") + start_addr.to_bytes(2, "big") + quantity.to_bytes(2, "big") + byte_count.to_bytes(1, "big") + values
        elif func_code == 23:
            read_start_addr = start_addr
            read_quantity = quantity
            write_start_addr = start_addr + quantity
            write_quantity = quantity
            write_byte_count = write_quantity * 2
            write_values = bytes([0xFF for _ in range(write_byte_count)])
            pdu = (
                func_code.to_bytes(1, "big") +
                read_start_addr.to_bytes(2, "big") +
                read_quantity.to_bytes(2, "big") +
                write_start_addr.to_bytes(2, "big") +
                write_quantity.to_bytes(2, "big") +
                write_byte_count.to_bytes(1, "big") +
                write_values
            )
        else:
            raise ValueError(f"Unsupported function code: {func_code}")

        trans_id = random.randint(0, 65535)
        proto_id = 0
        length = len(pdu) + 1
        unit_id = 1

        mbap = trans_id.to_bytes(2, "big") + proto_id.to_bytes(2, "big") + length.to_bytes(2, "big") + unit_id.to_bytes(1, "big")
        return Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=random.randint(1024, 65535), dport=502, flags="PA") / Raw(load=mbap + pdu)

    def _generate_modbus_response(self, func_code, start_addr, quantity):
        if func_code in [1, 2]:
            byte_count = (quantity + 7) // 8
            values = bytes([random.randint(0, 255) for _ in range(byte_count)])
            pdu = func_code.to_bytes(1, "big") + byte_count.to_bytes(1, "big") + values
        elif func_code in [3, 4]:
            byte_count = quantity * 2
            values = bytes([random.randint(0, 255) for _ in range(byte_count)])
            pdu = func_code.to_bytes(1, "big") + byte_count.to_bytes(1, "big") + values
        elif func_code in [5, 6, 15, 16]:
            pdu = func_code.to_bytes(1, "big") + start_addr.to_bytes(2, "big") + quantity.to_bytes(2, "big")
        elif func_code == 23:
            byte_count = quantity * 2
            values = bytes([random.randint(0, 255) for _ in range(byte_count)])
            pdu = func_code.to_bytes(1, "big") + byte_count.to_bytes(1, "big") + values
        else:
            raise ValueError(f"Unsupported function code: {func_code}")

        trans_id = random.randint(0, 65535)
        proto_id = 0
        length = len(pdu) + 1
        unit_id = 1

        mbap = trans_id.to_bytes(2, "big") + proto_id.to_bytes(2, "big") + length.to_bytes(2, "big") + unit_id.to_bytes(1, "big")
        return Ether() / IP(src="192.168.1.2", dst="192.168.1.1") / TCP(sport=502, dport=random.randint(1024, 65535), flags="PA") / Raw(load=mbap + pdu)

    def generate_corpus(self, num_samples=20, output_dir="ml-gen", output_file=None, protocol="modbus"):
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                logging.info(f"[+] Created output directory: {output_dir}")
            except Exception as e:
                logging.error(f"[-] Failed to create output directory {output_dir}: {e}")
                return None

        if output_file is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"{protocol}_synthetic_{timestamp}.pcap"

        if not output_file.endswith(".pcap"):
            output_file += ".pcap"

        output_path = os.path.join(output_dir, output_file)
        synthetic_packets = []

        for _ in range(num_samples):
            query = self.generate_modbus_query_packet()
            response = self.generate_modbus_response_packet()
            if query:
                synthetic_packets.append(query)
            if response:
                synthetic_packets.append(response)

        if not synthetic_packets:
            logging.error("[-] No packets were generated.")
            return None

        try:
            wrpcap(output_path, synthetic_packets)
            logging.info(f"[+] Saved {len(synthetic_packets)} packets to {output_path}")
            return output_path
        except Exception as e:
            logging.error(f"[-] Failed to write packets: {e}")
            return None