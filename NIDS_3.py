import io
import re
import time
import pyshark
import sys
from pyshark.capture.live_capture import LiveCapture
from scapy.all import *
import pandas as pd

#DoS attacks port 80 based assume
protocollayers = {}
protocolAttributes = {}

TCP_list = [] #TCP list packet storage
UDP_list = [] #UDP list package storage

##################
TLP_packets = {}
TLP_attr = {}

ICMP_packets = {}
ICMP_attr = {}

def Cap():
    count = 0
    capture = pyshark.LiveCapture("WI-FI")
    for packet in capture:
        alarm = False
        count += 1
        distribute(packet)
        #Time based capture, i.e 3 sec packet capturing
        if count > 10:
            (alarm, attack) = analysis()
            count = 0
        if alarm:
            mitigation(attack)

def distribute(packet) :
    TCP_object = open(r"C:/Users/edina/Downloads/Lang. Based Sec/TCP.txt", "w")
    UDP_object = open(r"C:/Users/edina/Downloads/Lang. Based Sec/UDP.txt", "w")
    try:
        protocol = packet.transport_layer
        if "tcp" in packet:
            #str1 = [["Name":packet.layers, "Src. Port": packet[protocol].srcport, "Dst. Port": packet[protocol].dstport]] # "Seq.": packet.sequence, "Len": packet.length, "Time": time.time, "Attri": TLP_attr
            TCP_object.writelines("TCP")
            print("TCP")
            #print(str1)
            TCP_list.extend(packet)
        elif "udp" in packet:
            #str2 = {"Name":packet.layers, "Src. Port": packet[protocol].srcport, "Dst. Port": packet[protocol].dstport, "Len": packet.length, "Time": time.time}
            UDP_object.writelines("UDP")
            print("UDP")
            UDP_list.extend(packet)
        
        # if "tcp" in packet or "udp" in packet :
        #     TLP_packets += [[packet.layers, packet[protocol].srcport, packet[protocol].dstport, packet.length, time.time, TLP_attr]]
        #     TCP_attr += 1
        # elif "icmp" in packet :
        #     ICMP_packets += [[packet.layers, packet[protocol].srcport, packet[protocol].dst, packet.length, time.time, ICMP_attr]]
        #     ICMP_attr += 1

    except AttributeError as e:
            print(e)
            SystemExit()
    TCP_object.close()
    UDP_object.close()

DOS_list = []
Attcak_list2 = []

#SYN flood
#UDP flood
#ICMP FLood
#Cases-switch here
#Assume that syn flood is coming from one ip address, then its easier to block
def analysis():
    start_time = time.time
    for packet in TLP_packets:
        if start_time - packet[4] < 10:
            return (True, "DoS")

        else:
            break
    return(False, "")

def mitigation(attack):

    return 0


start = time.time  
Cap()




















# class Rules():
#     protocols_tcp = {}
#     protocols_udp = {}
#     #Define protocol
#     def protocols_tcp(self, name, s_port, d_port, seq, ack, len):
#         self.name = name

#     def protocols_udp(self, name, s_port, d_port, len):
#         self.name = name
#         # self.s_port = s_port
#         # self.d_port = d_port
#         # self.len = len

#     #Define protocols to check for
#     def network_conversation(protocols_tcp, protocols_udp):
#         try:
#             for protocol in protocols_udp and protocols_tcp:
#                 if protocols_tcp.name == "tcp":
#                     protocollayers[protocol] = ["tcp"]
#                     protocolAttributes = {"Name": 0, "Src. Port": 0, "Dst. Port": 0, "Seq": 0, "Ack": 0, "Len": 0}
#                 elif protocols_udp.name == "udp": 
#                     protocollayers[protocol] = ["none", "udp"]
#                     protocolAttributes = {"Name": 0, "Src. Port": 0, "Dst. Port": 0, "Len": 0}
#             return {"protocollayers": protocollayers,  "protocolAttributes": protocolAttributes}
#         except AttributeError as e:
#             print(e)
#             SystemExit()

# def print_protocol_cap():
#     # sniffer = scapy.Sniffer()
#     # myDissector = sniffer.Dissector()
#     # c1_tcp = {}
#     # c1 = Counter
#     capture = pyshark.LiveCapture("WI-FI")
#     for packet in capture:
#         #dispatch packets to different protocols
#         appending(packet)
#         analysis()
#         if "tcp" in packet:
#             print("TCP is here")
#             if packet.source_addr.count > int(10):
#                 #cancel connection
#                 #or add to black_list
#                 print("h")
#         elif "udp" in capture:
#             print("UDP here")

# def TCP_list():
#     #define packet
#     #Atrribute with self.XXXX
#     #Fecth attributes here
#     # self.s_port = s_port
#     # self.d_port = d_port
#     # self.seq = seq
#     # self.ack = ack
#     # self.len = len
#     tcp_list = ()

#     #For attribute in packet write to file continue with next line break
#     for packet in caputre:
#         append.tcp_list()
#         for lines in tcp_list:
#             writetofile

# def UDP_list():
#     #define packet
#     #Atrribute with self.XXXX
#     tcp_list = ()

#     #For attribute in packet write to file continue with next line break
#     for packet in caputre:
#         append.tcp_list()
#         for lines in tcp_list:
#             writetofile

# ##Implement later
# def Other_List():