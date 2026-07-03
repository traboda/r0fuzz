from scapy.all import Ether, IP, TCP, Raw, wrpcap, rdpcap
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import random
import struct
import logging
import os
import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

PORT_MODBUS = 502
PORT_OPCUA = 4840
PAD_TOKEN = 256   
VOCAB_SIZE = 257  
MODBUS_VALID_FUNCTION_CODES = [1, 2, 3, 4, 5, 6, 15, 16, 22, 23]

OPCUA_UNCHUNKED_MESSAGE_TYPES = [b"HEL", b"ACK", b"ERR"]
OPCUA_CHUNKABLE_MESSAGE_TYPES = [b"OPN", b"MSG", b"CLO"]
OPCUA_CHUNK_TYPES = [b"F", b"C", b"A"]


class ByteLSTM(nn.Module):


    def __init__(self, vocab_size=VOCAB_SIZE, emb_dim=32, hidden_dim=128):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, emb_dim, padding_idx=PAD_TOKEN)
        self.lstm = nn.LSTM(emb_dim, hidden_dim, batch_first=True)
        self.output_layer = nn.Linear(hidden_dim, 256)

    def forward(self, x, hidden=None):
        emb = self.embedding(x)
        out, hidden = self.lstm(emb, hidden)
        logits = self.output_layer(out)
        return logits, hidden


class Generation:


    def __init__(self):
        self.models = {}           
        self.payload_lengths = {}  

    def _collect_pcap_files(self, pcap_path):
        if os.path.isfile(pcap_path):
            return [pcap_path] if pcap_path.lower().endswith(".pcap") else []
        files = []
        if os.path.isdir(pcap_path):
            for root, _, names in os.walk(pcap_path):
                for name in names:
                    if name.lower().endswith(".pcap"):
                        files.append(os.path.join(root, name))
        return files

    def extract_payloads(self, pcap_path, protocol):

        port = PORT_MODBUS if protocol == "modbus" else PORT_OPCUA
        pcap_files = self._collect_pcap_files(pcap_path)
        if not pcap_files:
            logging.error(f"[-] No .pcap files found at {pcap_path}")
            return []

        payloads = []
        for pcap_file in pcap_files:
            try:
                packets = rdpcap(pcap_file)
            except Exception as e:
                logging.warning(f"[!] Skipping unreadable pcap {pcap_file}: {e}")
                continue

            for packet in packets:
                if TCP in packet and Raw in packet:
                    if packet[TCP].sport == port or packet[TCP].dport == port:
                        payload = bytes(packet[Raw].load)
                        if len(payload) >= 8:
                            payloads.append(payload)

        logging.info(f"[+] Extracted {len(payloads)} {protocol} payloads from {len(pcap_files)} pcap file(s)")
        return payloads

    def train(self, pcap_path, protocol="modbus", epochs=30, max_len=128, lr=1e-3):

        payloads = self.extract_payloads(pcap_path, protocol)
        if not payloads:
            logging.error(f"[-] No training data for {protocol}; aborting train().")
            return False

        max_len = min(max_len, max(len(p) for p in payloads))
        self.payload_lengths[protocol] = [min(len(p), max_len) for p in payloads]

        inputs = torch.full((len(payloads), max_len), PAD_TOKEN, dtype=torch.long)
        targets = torch.full((len(payloads), max_len), PAD_TOKEN, dtype=torch.long)
        for i, payload in enumerate(payloads):
            payload = payload[:max_len]
            in_seq = [PAD_TOKEN] + list(payload[:-1])  # PAD_TOKEN doubles as START marker here
            inputs[i, :len(in_seq)] = torch.tensor(in_seq, dtype=torch.long)
            targets[i, :len(payload)] = torch.tensor(list(payload), dtype=torch.long)

        model = ByteLSTM()
        optimizer = torch.optim.Adam(model.parameters(), lr=lr)
        criterion = nn.CrossEntropyLoss(ignore_index=PAD_TOKEN)

        dataset = TensorDataset(inputs, targets)
        batch_size = min(32, len(payloads))
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        model.train()
        for epoch in range(epochs):
            total_loss = 0.0
            for batch_inputs, batch_targets in loader:
                optimizer.zero_grad()
                logits, _ = model(batch_inputs)
                loss = criterion(logits.reshape(-1, 256), batch_targets.reshape(-1))
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            logging.info(f"[{protocol}] Epoch {epoch + 1}/{epochs} - loss: {total_loss:.4f}")

        model.eval()
        self.models[protocol] = model

        os.makedirs("models", exist_ok=True)
        model_path = os.path.join("models", f"{protocol}_lstm.pth")
        torch.save(model.state_dict(), model_path)
        logging.info(f"[+] Saved trained {protocol} model to {model_path}")
        return True

    def generate_sequence(self, protocol, length, temperature=0.8):

        model = self.models.get(protocol)
        if model is None:
            raise RuntimeError(f"No trained model for protocol '{protocol}'; call train() first")

        model.eval()
        generated = []
        hidden = None
        next_input = torch.tensor([[PAD_TOKEN]], dtype=torch.long)

        with torch.no_grad():
            while len(generated) < length:
                logits, hidden = model(next_input, hidden)
                probs = torch.softmax(logits[0, -1] / temperature, dim=-1)
                next_byte = torch.multinomial(probs, 1).item()
                generated.append(next_byte)
                next_input = torch.tensor([[next_byte]], dtype=torch.long)

        return bytes(generated)

    def _fixup_modbus(self, raw_bytes):

        buf = bytearray(raw_bytes)
        if len(buf) < 8:
            buf.extend(bytes(8 - len(buf)))

        buf[0:2] = struct.pack(">H", random.randint(0, 65535))  # transaction id
        buf[2:4] = b"\x00\x00"                                   # protocol id, always 0
        length_val = max(1, min(len(buf) - 6, 65535))            # unit id + PDU byte count
        buf[4:6] = struct.pack(">H", length_val)

        if buf[7] not in MODBUS_VALID_FUNCTION_CODES:
            buf[7] = min(MODBUS_VALID_FUNCTION_CODES, key=lambda code: abs(code - buf[7]))
        return bytes(buf)

    def _fixup_opcua(self, raw_bytes):

        buf = bytearray(raw_bytes)
        if len(buf) < 8:
            buf.extend(bytes(8 - len(buf)))

        if bytes(buf[0:3]) not in OPCUA_UNCHUNKED_MESSAGE_TYPES + OPCUA_CHUNKABLE_MESSAGE_TYPES:
            message_type = random.choice(OPCUA_UNCHUNKED_MESSAGE_TYPES + OPCUA_CHUNKABLE_MESSAGE_TYPES)
            buf[0:3] = message_type
        else:
            message_type = bytes(buf[0:3])

        if message_type in OPCUA_UNCHUNKED_MESSAGE_TYPES:
            buf[3:4] = b"F"
        elif bytes(buf[3:4]) not in OPCUA_CHUNK_TYPES:
            buf[3:4] = random.choice(OPCUA_CHUNK_TYPES)

        buf[4:8] = struct.pack("<I", len(buf))
        return bytes(buf)

    def _build_modbus_valid_pdu(self):
        """Deterministically build a spec-conformant Modbus PDU (request shape)
        for a randomly chosen valid function code, with every length/count
        field correctly derived -- nothing here can come out malformed."""
        function_code = random.choice(MODBUS_VALID_FUNCTION_CODES)

        if function_code in (1, 2):
            start_addr = random.randint(0, 0xFFFF)
            quantity = random.randint(1, 2000)
            pdu = struct.pack(">BHH", function_code, start_addr, quantity)
        elif function_code in (3, 4):
            start_addr = random.randint(0, 0xFFFF)
            quantity = random.randint(1, 125)
            pdu = struct.pack(">BHH", function_code, start_addr, quantity)
        elif function_code == 5:
            addr = random.randint(0, 0xFFFF)
            value = random.choice([0x0000, 0xFF00])
            pdu = struct.pack(">BHH", function_code, addr, value)
        elif function_code == 6:
            addr = random.randint(0, 0xFFFF)
            value = random.randint(0, 0xFFFF)
            pdu = struct.pack(">BHH", function_code, addr, value)
        elif function_code == 15:
            start_addr = random.randint(0, 0xFFFF)
            quantity = random.randint(1, 1968)
            byte_count = (quantity + 7) // 8
            values = bytes(random.randint(0, 255) for _ in range(byte_count))
            pdu = struct.pack(">BHHB", function_code, start_addr, quantity, byte_count) + values
        elif function_code == 16:
            start_addr = random.randint(0, 0xFFFF)
            quantity = random.randint(1, 123)
            byte_count = quantity * 2
            values = bytes(random.randint(0, 255) for _ in range(byte_count))
            pdu = struct.pack(">BHHB", function_code, start_addr, quantity, byte_count) + values
        elif function_code == 22:
            ref_addr = random.randint(0, 0xFFFF)
            and_mask = random.randint(0, 0xFFFF)
            or_mask = random.randint(0, 0xFFFF)
            pdu = struct.pack(">BHHH", function_code, ref_addr, and_mask, or_mask)
        else:  # 23
            read_start = random.randint(0, 0xFFFF)
            read_qty = random.randint(1, 125)
            write_start = random.randint(0, 0xFFFF)
            write_qty = random.randint(1, 121)
            write_byte_count = write_qty * 2
            write_values = bytes(random.randint(0, 255) for _ in range(write_byte_count))
            pdu = struct.pack(">BHHHHB", function_code, read_start, read_qty, write_start, write_qty, write_byte_count) + write_values

        return pdu

    def _build_modbus_valid_packet(self):
        """Wrap a valid PDU in a valid MBAP header."""
        pdu = self._build_modbus_valid_pdu()
        trans_id = random.randint(0, 0xFFFF)
        unit_id = random.randint(0, 247)
        length_val = len(pdu) + 1  # unit id + PDU
        mbap = struct.pack(">HHHB", trans_id, 0, length_val, unit_id)
        return mbap + pdu

    def _build_opcua_valid_packet(self):

        version = 0
        receive_buffer_size = random.choice([8192, 16384, 65535, 65536])
        send_buffer_size = random.choice([8192, 16384, 65535, 65536])
        max_message_size = random.choice([0, 65536, 131072])
        max_chunk_count = random.choice([0, 1, 100])

        if random.random() < 0.5:
            host = random.choice(["localhost", "192.168.1.1", "opcua-server"])
            endpoint_url = f"opc.tcp://{host}:4840".encode()
            body = struct.pack("<IIIII", version, receive_buffer_size, send_buffer_size,
                                max_message_size, max_chunk_count)
            body += struct.pack("<i", len(endpoint_url)) + endpoint_url
            message_type = b"HEL"
        else:
            body = struct.pack("<IIIII", version, receive_buffer_size, send_buffer_size,
                                max_message_size, max_chunk_count)
            message_type = b"ACK"

        header = message_type + b"F" + struct.pack("<I", 8 + len(body))
        return header + body

    def generate_corpus(self, num_samples=20, output_dir=None, output_file=None, protocol="modbus", strict_valid=True):

        if protocol not in ("modbus", "opcua"):
            logging.error(f"[-] Unsupported protocol '{protocol}' for corpus generation.")
            return None
        if not strict_valid and protocol not in self.models:
            logging.error(f"[-] No trained model for protocol '{protocol}'. Call train() first.")
            return None

        output_dir = output_dir or os.path.join("ml-gen", protocol)
        os.makedirs(output_dir, exist_ok=True)

        if output_file is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"{protocol}_synthetic_{timestamp}.pcap"
        if not output_file.endswith(".pcap"):
            output_file += ".pcap"
        output_path = os.path.join(output_dir, output_file)

        port = PORT_MODBUS if protocol == "modbus" else PORT_OPCUA

        if strict_valid:
            build_packet = self._build_modbus_valid_packet if protocol == "modbus" else self._build_opcua_valid_packet
        else:
            lengths_seen = self.payload_lengths.get(protocol) or [64]
            fixup = self._fixup_modbus if protocol == "modbus" else self._fixup_opcua

            def build_packet():
                target_len = max(8, random.choice(lengths_seen) + random.randint(-4, 4))
                raw = self.generate_sequence(protocol, length=target_len, temperature=random.uniform(0.6, 1.1))
                return fixup(raw)

        synthetic_packets = []
        for _ in range(num_samples):
            payload = build_packet()
            packet = (
                Ether()
                / IP(src="192.168.1.1", dst="192.168.1.2")
                / TCP(sport=random.randint(1024, 65535), dport=port, flags="PA")
                / Raw(load=payload)
            )
            synthetic_packets.append(packet)

        try:
            wrpcap(output_path, synthetic_packets)
            logging.info(f"[+] Saved {len(synthetic_packets)} packets to {output_path}")
            return output_path
        except Exception as e:
            logging.error(f"[-] Failed to write packets: {e}")
            return None
