import socket
import sys	
from types import *
import struct
import time
import logging
import pickle
from scapy.all import *

HOST = '127.0.0.1'
src_port = 49901    
dest_port = 5020     

FORMAT = ('%(asctime)-15s %(threadName)-15s'
	' %(levelname)-8s %(module)-15s:%(lineno)-8s %(message)s')

logging.basicConfig(format=FORMAT)
log = logging.getLogger()
log.setLevel(logging.DEBUG)

class Modbus(Packet):
    name = "Modbus/tcp"
    fields_desc = [ ShortField("Transaction Identifier", 1),
                    ShortField("Protocol Identifier", 0),
                    ShortField("Length", 2),
                    XByteField("Unit Identifier",0),
                    ByteField("Function Code", 0)
                    ]



def create_connection(dest_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as msg:
        sys.stderr.write("[ERROR] %s\n" % msg[1])
        sys.exit(1)

    HOST = dest_ip
    try:
    	#sock.bind((HOST,src_port))
        sock.settimeout(0.5)
        sock.connect((HOST, dest_port))
    except socket.error as msg:
        logging.exception("Connection Failed!")
    else:
        logging.info("Connected to Server: %s" % dest_ip)

    return sock

def hexstr(s):
    return '-'.join('%02x' % ord(c) for c in s)

def make_packet(packet):

	TotalModbusPacket =  ""
	TotalModbusPacket += struct.pack(">B", packet['transID1'])
	TotalModbusPacket += struct.pack(">B", packet['transID2'])
	TotalModbusPacket += struct.pack(">B", packet['protoID1'])
	TotalModbusPacket += struct.pack(">B", packet['protoID2'])
	TotalModbusPacket += struct.pack(">B", packet['length1'])
	TotalModbusPacket += struct.pack(">B", packet['length2'])
	TotalModbusPacket += struct.pack(">B", packet['unitID'])
	TotalModbusPacket += struct.pack(">B", packet['functionCode'])
	TotalModbusPacket += struct.pack(">H", packet['functionData1'])
	TotalModbusPacket += struct.pack(">H", packet['functionData2'])

	return TotalModbusPacket


def AddToPCAP(packet):
	pkt = Ether()/IP()/TCP(sport=src_port, dport = dest_port)/packet/Modbus()
	wrpcap('test.pcap', pkt, append=True)

def send_packet(dest_ip):
	sock = create_connection(dest_ip, dest_port)

	packet = {
		'transID1' : 0x0,
		'transID2' : 0xc,
		'protoID1' : 0x0,
		'protoID2' : 0x0,
		'length1' : 0x0,
		'length2' : 0x6,
		'unitID' : 0x0,
		'functionCode' : 0x1, 
		'functionData1' : 0x54,
		'functionData2' : 0x9
	}

	for functionCode in [0x10] : # Fuzzing specific parameters
		for functionData1 in [0x21]:
			for functionData2 in [65535]:

				packet['functionCode'] = functionCode
				packet['functionData1'] = functionData1
				packet['functionData2'] = functionData2

				ModbusPacket = make_packet(packet) 
				#AddToPCAP(ModbusPacket)
				#AddToPCAP(RespPacket)
				try:
					sock.send(ModbusPacket)
				except socket.timeout:
					logging.exception("Sending Timed Out!")
				except socket.error:
					#logging.exception("Sending Failed!")
					sock.close()
					sock = create_connection(dest_ip, dest_port)
					#logging.info("Try to Reconnect...")
				else:
					logging.debug("Sent Packet: %s" % hexstr(ModbusPacket))
					print("Sent: %s" % hexstr(ModbusPacket))
					RespPacket = sock.recv(1024)
					print >>sys.stderr,'received: %s'% hexstr(RespPacket)


send_packet(HOST)