import io
import re
import time
import pyshark
import sys
from pyshark.capture.live_capture import LiveCapture
from scapy.all import *
import pandas as pd
import os
from math import ceil
import socket

##Add ssh question to Main Slack LAng B. Sec

#DoS attacks port 80 based assume

TCP_list = [] #TCP list packet storage
UDP_list = [] #UDP list package storage
UDP_list_DNS = []

##################
TLP_packets = {}
TLP_attr = {}
ICMP_packets = {}
ICMP_attr = {}

"""
My thinking (David): 
When we notice an attack, we will have to start save all the upcoming packets. As said before, we should store all the info we need in files to read later,
but we also need some info for mitigation. Therefore, we should start so store all the ip-addresses for all upcoming packets in a list, and then send that
list to mitigation. Then mitigation can search for the most common ip-address and add it to a blacklist file (or something similar).
Also: For some reason, with some runs, there comes a lot of packets with ack = 1 which is weird.. that leads me to believe
that we can only check for SYN flags. But maybe that is enough. 
"""

def Cap():
    #INIT:
    SYN_counter = 0
    ACK_counter = 0
    UDP_counter = 0
    Ports_List = {} #List of all ports visited every 5 seconds
    scan_attack_counter = 0
    DoS_attack_counter = 0
    IP_scan_attack = None

    timer_analysis_start = time.time()
    capture = pyshark.LiveCapture("WI-FI")
    Local_IP = socket.gethostbyname(socket.gethostname())

    try:
        for packet in capture:
            timer_analysis_end = time.time()
            DoS = False
            Scan = False
            Scan_indicator(packet, Local_IP, Ports_List)
            Dos_indicator(packet, SYN_counter, ACK_counter, UDP_counter)

            if timer_analysis_end - timer_analysis_start > 5 :      #Analysis every 5 seconds
                print("analysing")
                timer_analysis_start = time.time()
                (DoS, Scan) = analysis(SYN_counter, ACK_counter, UDP_counter, Ports_List, IP_scan_attack)

            if DoS or Scan:
                distribute(packet)
                if DoS :
                    DoS_attack_counter += 1
                    mitigation_DoS()
                else :
                    scan_attack_counter += 1
                    mitigation_Scan()
    except AttributeError as e:
            print(e)
            SystemExit()

def Scan_indicator(packet, Local_IP, Ports_List) :
    try: 
        packet.ip.dst
    except AttributeError as e:
        print(e)
    else :
        if packet.ip.dst == Local_IP and packet[packet.transport_layer].dstport != None :
            if packet.ip.src in Ports_List.keys :
                if packet[packet.transport_layer].dstport not in Ports_List[packet.ip.src] :
                    Ports_List[packet.ip.src].extend(packet[packet.transport_layer].dstport)
            else :
                Ports_List[packet.ip.src] = [packet[packet.transport_layer].dstport]

def Dos_indicator(packet, SYN_counter, ACK_counter, UDP_counter) :
    #print("In counter_up_to_date")
    #This needs to change to flag_syn or whataver represents the syn flag
    if "tcp" in packet:
        try: 
            packet.tcp.flags_syn
        except AttributeError as e:
            print()
        else:
            #Check the first message in the tcp handshake
            if packet.tcp.flags_syn == "1" and packet.tcp.flags_ack == "0":
             #print(packet.tcp)  
             SYN_counter += 1
             print("Syn_counter: ", SYN_counter)
             return SYN_counter
        # try: 
        #     packet.tcp.flags_ack
        # except AttributeError as e:
        #     print()
        # else:
        #     if packet.tcp.flags_ack == "1" and packet.tcp.flags_syn == "0": #and packet.tcp.window_size_value < 1024:
        #      #print("Window: ", packet.tcp.window_size_value)
        #      print("ack: ",packet.tcp.ack)
        #      print("flags_ack: ",packet.tcp.flags_ack)
        #      print(packet.tcp)
        #      ACK_counter += 1
        #      #print("Ack_counter + 1")
        #      return ACK_counter
    elif "udp" in packet:
        print("UDP-counter: ", UDP_counter)
        UDP_counter += 1
        return UDP_counter


def distribute(packet) :
    ##INITIALIZATION:##____________________________________________________
    sourceAddress = packet.ip.src
    destinationAddress = packet.ip.dst
    #FLAGS:
    synFlag = bool(packet.tcp.flags_syn)
    ackFlag = bool(packet.tcp.flags_ack)
    resetFlag = bool(packet.tcp.flags_reset)
    protocol = packet.transport_layer

    #FILE OBJECTS:
    TCP_object = open(r"TCP.txt", "a")
    UDP_object = open(r"UDP.txt", "a")
    UDP_DNS_object = open(r"UDP_DNS.txt", "a")
    ##_____________________________________________________________________________

    try:
        #Check if TCP syn and fin messages are fine then scan trough the tcp and fetch to file
        field_names = packet.tcp._all_fields
        field_values = packet.tcp._all_fields.values()
        for field_name in field_names:
            for field_value in field_values:
                if field_name == 'tcp.payload':
                    print(f'{field_name} -- {field_value[100:120, 1]}') #100:120, 1
                    print("*"*10 + "Continuiing" + "*"*10)

        if "tcp" in packet and "ip" not in packet:
            #packet_time = packet.sniff_time
            str_N = ('Name: ', packet.layers) #[-2]
            str_S_p = ('Scr. Port: ', packet[protocol].srcport)
            str_D_p = ('Dst. Port: ', packet[protocol].dstport)
            str1 = (str_N, str_S_p, str_D_p )# "Seq.": packet.sequence, "Len": packet.length, "Time": time.time, "Attri": TLP_attr   packet_time
            TCP_object.writelines(str(str1) + os.linesep)
            print ('%s  %s:%s --> %s:%s' % (str_N, packet[protocol].srcaddr, str_S_p, str_D_p, packet[protocol].dstaddr))
            #TCP_list.extend(packet)
        elif "udp" in packet:
            #packet_time2 = packet.sniff_time
            str_N_2 = ('Name: ', packet.layers[-2])
            str_S_p_2 = ('Scr. Port: ', packet[protocol].srcport)
            str_D_p_2 = ('Dst. Port: ', packet[protocol].dstport)
            str2 = (str_N_2, str_S_p_2, str_D_p_2) #packet_time2
            #{"Name":packet.layers, "Src. Port": packet[protocol].srcport, "Dst. Port": packet[protocol].dstport, "Len": packet.length, "Time": time.time}
            UDP_object.writelines(str(str2) + os.linesep)
            #UDP_list.extend(packet)
            print ('%s  %s:%s --> %s:%s' % (str_N_2, packet[protocol].srcaddr, str_S_p, str_D_p, packet[protocol].dstaddr))
        
        # if "tcp" in packet or "udp" in packet :
        #     TLP_packets += [[packet.layers, packet[protocol].srcport, packet[protocol].dstport, packet.length, time.time, TLP_attr]]
        #     TCP_attr += 1
        # elif "icmp" in packet :
        #     ICMP_packets += [[packet.layers, packet[protocol].srcport, packet[protocol].dst, packet.length, time.time, ICMP_attr]]
        #     ICMP_attr += 1

        # elif "udp" in packet and packet[packet.transport_layer].dstport == '53':
        #     packet_time2 = packet.sniff_time
        #     str3 = ('Name: ', packet.layers)
        #     str3 += ('Scr. Port: ', packet[protocol].srcport)
        #     str3 += ('Dst. Port: ', packet[protocol].dstport)
        #     UDP_DNS_object.writelines(str(str3) + os.linesep)
        #     UDP_list_DNS.extend(packet)
        #
        #
        #Here look for more packet petterns!

    except AttributeError as e:
            print(e)
            SystemExit()
    TCP_object.close()
    UDP_object.close()
    UDP_DNS_object.close()

def analysis(SYN_counter, ACK_counter, UDP_counter, Ports_List, IP_scan_attack):
    DoS = analysis_DoS(SYN_counter, ACK_counter, UDP_counter)
    Scan = analysis_Scan(Ports_List, IP_scan_attack)
    return(DoS, Scan)

def analysis_DoS(SYN_counter, ACK_counter, UDP_counter):
    if SYN_counter - ACK_counter > 10 :
        SYN_counter = 0
        ACK_counter = 0
        return (True) #'TCP SYN Flood'
    elif UDP_counter <= 10:
        SYN_counter = 0
        ACK_counter = 0
        return(False) #"No TCP SYN flood"
    elif UDP_counter > 10:
        UDP_counter = 0
        return (True) #, "UDP Flood"
    else:
        return (False) #, "No UDP flood"

def analysis_Scan(Ports_List, IP_scan_attack):
    Different_Ports = []
    for address_IP in Ports_List.keys :
        if len(Ports_List[address_IP]) > 200 :
            IP_scan_attack = address_IP
            Ports_List = {}
            return True
        else :
            for port in Ports_List[address_IP] :
                if port not in Different_Ports :
                    Different_Ports.extend(port)
    Ports_List = {}
    if len(Different_Ports) > 300 :
        return True
    return False

##Append port info, source address and type of attack
##Print stuff later

def mitigation_DoS(attack):

    return 0

def mitigation_Scan(attack):

    return 0


start = time.time()
Cap()
SystemExit(time)
