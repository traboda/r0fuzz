from core.logger import get_logger

import socket
import sys
from types import *
import struct


class DFuzz(object):
    def __init__(self, r0obj):
        self.r0obj = r0obj
        self.HOST = r0obj.ip 
        self.dest_port = r0obj.port
        self.verbosity = self.r0obj.log_level

        self.logger = get_logger("Dumbfuzz", self.verbosity)

    def create_connection(self, dest_ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            self.logger.error("[-] Unable to establish socket connection")
            sys.exit(1)

        self.HOST = dest_ip
        try:
            sock.settimeout(0.5)
            sock.connect((self.HOST, self.dest_port))
        except socket.error as msg:
            self.logger.error(msg)
        else:
            self.logger.info("[+] Connected to Server: %s" % dest_ip)
        return sock

    def hexstr(self, s):
        t = ""
        for i in range(0, len(s)):
            t = t + str(hex(s[i]))[2:] + "-"
        return t[:-1]

    def dumb_fuzzing(self):
        sock = self.create_connection(self.HOST, self.dest_port)
        print(type(sock))
        length1 = 0
        length2 = 6
        unitID = 1

        for transID1 in range(0, 0xFF):
            for protoID1 in range(0, 0xFF):
                for functionCode in range(0, 0xFF):
                    for functionData1 in range(0, 0xFF):
                        for functionData2 in range(0, 0xFF):
                            TotalModbusPacket = (
                                struct.pack(">H", transID1)
                                + struct.pack(">H", protoID1)
                                + struct.pack(">B", length1)
                                + struct.pack(">B", length2)
                                + struct.pack(">B", unitID)
                                + struct.pack(">B", functionCode)
                                + struct.pack(">H", functionData1)
                                + struct.pack(">H", functionData2)
                            )
                            # print(str(TotalModbusPacket))
                            print(self.hexstr((TotalModbusPacket)))
                            self.logger.debug(
                                "[+] Packet sent: %s" % self.hexstr(TotalModbusPacket)
                            )
                            try:
                                print("sseennnttt", TotalModbusPacket)
                                sock.send(TotalModbusPacket)
                                # print >>sys.stderr,'received: %s'% self.hexstr(sock.recv(1024).decode("utf-8"))
                            except socket.timeout:
                                self.logger.warning("Sending Timed Out!")
                            except socket.error:
                                self.logger.warning("Sending Failed!")
                                sock.close()
                                sock = self.create_connection(self.HOST, self.dest_port)
                                # logging.info("Try to Reconnect...")
                            else:
                                self.logger.debug(
                                    "[+] Sent Packet: %s"
                                    % self.hexstr(TotalModbusPacket)
                                )
                                print("Sent: %s" % self.hexstr(TotalModbusPacket))
