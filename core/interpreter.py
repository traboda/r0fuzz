from core.logger import get_logger
import socket
import time
from scapy.all import *

class Intepreter(object):
    def __init__(self, r0obj):
        self.r0obj = r0obj
        self.HOST = r0obj.ip
        self.src_port = 49901
        self.dest_port = r0obj.port
        self.verbosity = self.r0obj.log_level
        self.logger = get_logger("Interpreter", self.verbosity)
        self.crash_log = get_logger("crash_log", self.verbosity)

    def create_socket(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            ret_code = sock.connect_ex((self.HOST, self.dest_port))
        except:
            pass
        return sock, ret_code

    def create_connection(self):
        ret_code = None

        while ret_code != 0:
            sock_obj, ret_code = self.create_socket()
            
        return sock_obj

    def send_packet(self, packet):
        ret_val = None
        print("[*] Send Packet")

        sock_obj = self.create_connection()
        try:
            sock_obj.send(packet)

        except:
            self.logger.error("[-] Sending Failed!")
            sock_obj.close()

        else:
            self.logger.debug(f"{packet}")
            print("[*] Sent: %s" % hexstr(packet))

            # Recv Packet
            try:
                RespPacket = sock_obj.recv(1024)
                print("[*] Received: %s" % hexstr(RespPacket))
                self.logger.debug(f"RECV:{RespPacket}")

            except:
                print(f"[*] Failed ")
                self.logger.error("[-] Failed to receive")

            sock_obj.close()

            return ret_val
            