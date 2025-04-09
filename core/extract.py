from scapy.all import *
import argparse

class Extractor(object):
    def __init__(self, r0obj, verbosity="INFO"):
        self.PORT_MODBUS = 502
        self.input = r0obj.seed
        self.verbosity = verbosity

    def extract_modbus_fields(self, packets):
        """
        Extract Modbus fields from a single packet and update the fields_dict.
        """
        fields_dict = {"transID1": [], "transID2": [], "protoID1": [], "protoID2": [], "length1": [], "length2": [], "unitID": [], "functionCode": [], "start_addr": [], "count": [] }

        for packet in packets:
            try:
                if packet.haslayer("TCP") and packet["TCP"].sport == self.PORT_MODBUS:
                    hex_val = getattr(packet["TCP"], "load")
                    packet_len = len(hex_val)
                    
                    if (packet_len >= 12):
                        fields_dict["transID1"].append(hex_val[0])
                        fields_dict["transID2"].append(hex_val[1])
                        fields_dict["protoID1"].append(hex_val[2])
                        fields_dict["protoID2"].append(hex_val[3])
                        fields_dict["length1"].append(hex_val[4])
                        fields_dict["length2"].append(hex_val[5])
                        fields_dict["unitID"].append(hex_val[6])
                        fields_dict["functionCode"].append(hex_val[7])
                        fields_dict["start_addr"].append(hex_val[8:10])
                        fields_dict["count"].append(hex_val[10:12])
                        
            except Exception as e:
                print(f"Error extracting Modbus fields: {e}")
                return None

        return fields_dict

    def extract_opcua_fields(self, packets):
        fields_dict = {
            # Message type
            "msgtype1": [], "msgtype2": [], "msgtype3": [],
            # Chunk type
            "ctype": [],
            # Message size
            "msgsize": [],
            # Secure channel ID
            "secc1": [], "secc2": [], "secc3": [], "secc4": [],
            # Security token ID
            "secID1": [], "secID2": [], "secID3": [], "secID4": [],
            # Sequence number
            "seq1": [], "seq2": [], "seq3": [], "seq4": [],
            # Request ID
            "reqID1": [], "reqID2": [], "reqID3": [], "reqID4": [],
            # Encoding
            "encoding": []
        }

        for i in packets:
            try:
                if i.haslayer("OpcUa") and i[self.layer].sport == self.PORT:
                    hex_val = getattr(i[self.layer], self.field, None)
                    packet_len = len(hex_val)

                    if (packet_len >= 25):
                        fields_dict["msgtype1"].append(hex_val[0])
                        fields_dict["msgtype2"].append(hex_val[1])
                        fields_dict["msgtype3"].append(hex_val[2])
                        fields_dict["ctype"].append(hex_val[3])
                        fields_dict["msgsize"].append(hex_val[4])
                        fields_dict["secc1"].append(hex_val[5])
                        fields_dict["secc2"].append(hex_val[6])
                        fields_dict["secc3"].append(hex_val[7])
                        fields_dict["secc4"].append(hex_val[8])
                        fields_dict["secID1"].append(hex_val[9])
                        fields_dict["secID2"].append(hex_val[10])
                        fields_dict["secID3"].append(hex_val[11])
                        fields_dict["secID4"].append(hex_val[12])
                        fields_dict["seq1"].append(hex_val[13])
                        fields_dict["seq2"].append(hex_val[14])
                        fields_dict["seq3"].append(hex_val[15])
                        fields_dict["seq4"].append(hex_val[16])
                        fields_dict["reqID1"].append(hex_val[17])
                        fields_dict["reqID2"].append(hex_val[18])
                        fields_dict["reqID3"].append(hex_val[19])
                        fields_dict["reqID4"].append(hex_val[20])
                        fields_dict["encoding"].append(hex_val[21])
            
            except Exception as e:
                print(f"Error extracting OpcUa fields: {e}")
                return None

        sys.exit(0)
        return fields_dict


    def extract_fields_from_packets(self, protocol):
        """
        Extract fields from a list of packets based on the specified protocol.
        """
        packets = rdpcap(self.input)
        if protocol == "modbus":
            extracted_data = self.extract_modbus_fields(packets)
        elif protocol == "opcua":
            extracted_data = self.extract_opcua_fields(packets)
        else:
            raise ValueError("[X] Unsupported protocol")

        return dict(extracted_data)
    
def main():
    # Argument parser for command-line arguments
    parser = argparse.ArgumentParser(description="Extract fields from a pcap file.")
    parser.add_argument(
        "pcap_file", type=str, help="Path to the pcap file"
    )
    parser.add_argument(
        "--protocol",
        type=str,
        choices=["modbus", "dnp3"],
        default="modbus",
        help="Protocol to extract fields for (default: modbus)",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Log level (default: INFO)",
    )
    args = parser.parse_args()

    # Instantiate the Extractor class
    extractor = Extractor(verbosity=args.log_level)

    # Read the pcap file
    try:
        packets = rdpcap(args.pcap_file)
        print(f"[+] Successfully read {len(packets)} packets from {args.pcap_file}")
    except Exception as e:
        print(f"[X] Unable to read the file: {e}")
        return

    # Extract fields based on the protocol
    if args.protocol == "modbus":
        extracted_fields = extractor.extract_fields_from_packets(packets, protocol="modbus")

    # Print the extracted fields
    if extracted_fields:
        print("\nExtracted Fields:")
        for idx, fields in enumerate(extracted_fields, start=1):
            print(f"\nPacket {idx}:")
            for key, value in fields.items():
                print(f"{key}: {value}")
    else:
        print("No fields extracted.")

if __name__ == "__main__":
    main()