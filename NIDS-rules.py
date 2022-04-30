from asyncio import protocols
from csv import Sniffer
from distutils.file_util import write_file
import io
from prometheus_client import Counter
import pyshark
import sys
from sniffer import Dissector
from pyshark.capture.live_capture import LiveCapture
import scapy.all


"""
#DoS attacks port 80 based assume
#
protocollayers = {}
protocolAttributes = {}

class Rules():
    protocols_tcp = {}
    protocols_udp = {}
    #Define protocol
    def protocols_tcp(self, name, s_port, d_port, seq, ack, len):
        self.name = name

    def protocols_udp(self, name, s_port, d_port, len):
        self.name = name
        # self.s_port = s_port
        # self.d_port = d_port
        # self.len = len

    #Define protocols to check for
    def network_conversation(protocols_tcp, protocols_udp):
        try:
            for protocol in protocols_udp and protocols_tcp:
                if protocols_tcp.name == "tcp":
                    protocollayers[protocol] = ["tcp"]
                    protocolAttributes = {"Name": 0, "Src. Port": 0, "Dst. Port": 0, "Seq": 0, "Ack": 0, "Len": 0}
                elif protocols_udp.name == "udp": 
                    protocollayers[protocol] = ["none", "udp"]
                    protocolAttributes = {"Name": 0, "Src. Port": 0, "Dst. Port": 0, "Len": 0}
            return {"protocollayers": protocollayers,  "protocolAttributes": protocolAttributes}
        except AttributeError as e:
            print(e)
            SystemExit()

def print_protocol_cap():
    # sniffer = scapy.Sniffer()
    # myDissector = sniffer.Dissector()
    # c1_tcp = {}
    # c1 = Counter
    capture = pyshark.LiveCapture("WI-FI")
    for packet in capture:
        #dispatch packets to different protocols
       # appending(packet)
        #analysis()
        if "tcp" in packet:
            print("TCP is here")
            if packet.source_addr.count > int(10):
                #cancel connection
                #or add to black_list
       # elif "udp" in capture:
           # print("UDP here")

def TCP_list():
    #define packet
    #Atrribute with self.XXXX
    #Fecth attributes here
    # self.s_port = s_port
    # self.d_port = d_port
    # self.seq = seq
    # self.ack = ack
    # self.len = len
    tcp_list = ()

    #For attribute in packet write to file continue with next line break
    for packet in caputre:
        append.tcp_list()
        for lines in tcp_list:
            writetofile

def UDP_list():
    #define packet
    #Atrribute with self.XXXX
    tcp_list = ()

    #For attribute in packet write to file continue with next line break
    for packet in caputre:
        append.tcp_list()
        for lines in tcp_list:
            writetofile

##Implement later
def Other_List():
    
print_protocol_cap()
"""