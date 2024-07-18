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
        # subprocess.Popen(["pkill", "-9", "server"])

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

        # self.logger.info("[+] Connected to Server: %s" % self.HOST)

        return sock_obj

    def send_packet(self, packet):

        ret_val = None

        self.logger.debug("[*] Send Packet")

        sock_obj = self.create_connection()
        # send packet
        try:
            sock_obj.send(packet)

        except:

            self.logger.error("[-] Sending Failed!")
            sock_obj.close()
            # sock_obj = self.create_connection()

        else:

            self.logger.debug("[+] Sent Packet: %s" % hexstr(packet))

            print("[*] Sent: %s" % hexstr(packet))

            # Recv Packet
            try:
                RespPacket = sock_obj.recv(1024)
                print("[*] Received: %s" % hexstr(RespPacket))

            except:

                print(f"[*] Failed ")
                self.logger.error("[-] Failed to receive")

            sock_obj.close()

            # server_exit_code = server_process.wait()
            # print("[*] Exit Code: ", server_exit_code)

            # if server_exit_code:
            #    self.crash_log.info(str(packet))
            #    ret_val = packet
            # time.sleep(2)

            return ret_val
