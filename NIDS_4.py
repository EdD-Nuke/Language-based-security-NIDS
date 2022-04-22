import io
import re
import time
import pyshark
import sys
from pyshark.capture.live_capture import LiveCapture
from scapy.all import *
import pandas as pd
import os

#DoS attacks port 80 based assume
protocollayers = {}
protocolAttributes = {}

TCP_list = [] #TCP list packet storage
UDP_list = [] #UDP list package storage
UDP_list_DNS = []

##################
TLP_packets = {}
TLP_attr = {}

ICMP_packets = {}
ICMP_attr = {}

def Cap():
    count = 0
    capture = pyshark.LiveCapture("WI-FI", display_filter='tcp.analysis.fast_retransmission')
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

    field_names = packet.tcp._all_fields
    field_values = packet.tcp._all_fields.values()
    for field_name in field_names:
        for field_value in field_values:
            if field_name == 'tcp.payload':
               print(f'{field_name} -- {field_value}')

def distribute(packet) :
    TCP_object = open(r"C:/Users/edina/Downloads/Lang. Based Sec/TCP.txt", "a")
    UDP_object = open(r"C:/Users/edina/Downloads/Lang. Based Sec/UDP.txt", "a")
    UDP_DNS_object = open(r"C:/Users/edina/Downloads/Lang. Based Sec/UDP_DNS.txt", "a")
    try:
        count += 1
        protocol = packet.transport_layer
        if "tcp" in packet and "ip" not in packet:
            #packet_time = packet.sniff_time
            str_N = ('Name: ', packet.layers) #[-2]
            str_S_p = ('Scr. Port: ', packet[protocol].srcport)
            str_D_p = ('Dst. Port: ', packet[protocol].dstport)
            str1 = (str_N, str_S_p, str_D_p )# "Seq.": packet.sequence, "Len": packet.length, "Time": time.time, "Attri": TLP_attr   packet_time
            TCP_object.writelines(str(str1) + os.linesep)
            print ('%s  %s:%s --> %s:%s' % (str_N, packet[protocol].srcaddr, str_S_p, str_D_p, packet[protocol].dstaddr))
            TCP_list.extend(packet)
        elif "udp" in packet:
            packet_time2 = packet.sniff_time
            str_N_2 = ('Name: ', packet.layers[-2])
            str_S_p_2 = ('Scr. Port: ', packet[protocol].srcport)
            str_D_p_2 = ('Dst. Port: ', packet[protocol].dstport)
            str2 = (str_N_2, str_S_p_2, str_D_p_2, packet_time2)
            #{"Name":packet.layers, "Src. Port": packet[protocol].srcport, "Dst. Port": packet[protocol].dstport, "Len": packet.length, "Time": time.time}
            UDP_object.writelines(str(str2) + os.linesep)
            UDP_list.extend(packet)
            print ('%s  %s:%s --> %s:%s' % (str_N_2, packet[protocol].srcaddr, str_S_p, str_D_p, packet[protocol].dstaddr))
        
        # if "tcp" in packet or "udp" in packet :
        #     TLP_packets += [[packet.layers, packet[protocol].srcport, packet[protocol].dstport, packet.length, time.time, TLP_attr]]
        #     TCP_attr += 1
        # elif "icmp" in packet :
        #     ICMP_packets += [[packet.layers, packet[protocol].srcport, packet[protocol].dst, packet.length, time.time, ICMP_attr]]
        #     ICMP_attr += 1

        elif "udp" in packet and packet[packet.transport_layer].dstport == '53':
            packet_time2 = packet.sniff_time
            str3 = ('Name: ', packet.layers)
            str3 += ('Scr. Port: ', packet[protocol].srcport)
            str3 += ('Dst. Port: ', packet[protocol].dstport)
            UDP_DNS_object.writelines(str(str3) + os.linesep)
            UDP_list_DNS.extend(packet)
        #
        #
        #Here look for more packet petterns!

        #CHECKER FOR SEQ DATA
        seq = packet[protocol].seq
        print("packet count %d seq is %s " %(count, seq ))

    except AttributeError as e:
            print(e)
            SystemExit()
    TCP_object.close()
    UDP_object.close()
    UDP_DNS_object.close()

DOS_list = []
Attcak_list2 = []

#SYN flood
#UDP flood
#ICMP FLood
#Cases-switch here
#Assume that syn flood is coming from one ip address, then its easier to block
def analysis():
    start_time = time.time
    for packet in TCP_list and UDP_list:
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
