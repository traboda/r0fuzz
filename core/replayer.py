from core.logger import get_logger
from core.interpreter import *
import time
import ast

class Replayer(object):
    def __init__(self, r0obj):
        self.r0obj = r0obj
        self.HOST = r0obj.ip
        self.dest_port = r0obj.port
        self.verbosity = self.r0obj.log_level
        self.logger = get_logger("Replayer", self.verbosity)
        self.Interpret = Intepreter(r0obj)

    def replayPackets(self):
        self.logger.debug("Replaying crash packets")
        
        with open(self.r0obj.crash_log, 'r') as cl:
            crash_packets = cl.read().splitlines()
            
        cnt = 1
        for packet in crash_packets:
            print(cnt)
            packet_bytes = ast.literal_eval(packet)
            ret_code = self.Interpret.send_packet(packet_bytes)
            cnt += 1
            
            
            