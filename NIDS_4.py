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

#INIT:
counts_seq = 0
SYN_counter = 0
ACK_counter = 0
UDP_counter = 0
global Ports_List
Ports_List = [] #List of all ports visited every 5 seconds


def Cap():
    global Ports_List
    timer_analysis_start = time.time()
    capture = pyshark.LiveCapture("WI-FI")
    Local_IP = socket.gethostbyname(socket.gethostname())

    try:
        for packet in capture:
            timer_analysis_end = time.time()
            DoS = False
            Scan = False
            print(packet)
            if packet.ip.dst == Local_IP and packet[packet.transport_layer].dstport != None:
                Ports_List.extend(packet[packet.transport_layer].dstport)
            counters_up_to_date(packet)

            if timer_analysis_end - timer_analysis_start > 5 :      #Analysis every 5 seconds
                print("analysing")
                timer_analysis_start = time.time()
                (DoS, Scan) = analysis()

            if DoS or Scan:
                distribute(packet)
                if DoS :
                    mitigation_DoS()
                else :
                    mitigation_Scan()
    except AttributeError as e:
            print(e)
            SystemExit()

def counters_up_to_date(packet) :
    global SYN_counter
    global ACK_counter
    global UDP_counter
    #print("In counter_up_to_date")
    #This needs to change to flag_syn or whataver represents the syn flag
    if "tcp" in packet :
        SYN_counter += 1
        return SYN_counter
    #This needs to change to flag_ack or whataver represents the ack flag
    elif "ack" in packet :
        ACK_counter += 1
        return ACK_counter
    elif "udp" in packet :
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


#SYN flood
#UDP flood
#ICMP FLood
#Cases-switch here
#Assume that syn flood is coming from one ip address, then its easier to block

def analysis_DoS():
    global SYN_counter
    global ACK_counter
    global UDP_counter
    start_time = time.time()
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

def analysis_Scan():
    global Ports_List
    number_of_visited_ports = different(Ports_List)
    Ports_List = []
    if number_of_visited_ports > 1000 :
        return True
    return False

def analysis():
    DoS = analysis_DoS()
    Scan = analysis_Scan()
    return(DoS, Scan)

##Append port info, source address and type of attack
##Print stuff later

def different(List) :
    n = len(List)
    counter = 0
    for i in range (0,n) :
        check = 0
        for j in range (0,i) :
            if List[i] == List[j] :
                check += 1
        if check == 0 :
            counter += 1
    return counter

def mitigation_DoS(attack):

    return 0

def mitigation_Scan(attack):

    return 0


start = time.time()
print("it works")
Cap()
SystemExit(time)


# def analysis():
#     start_time = time.time
#     if sourceAddress == '127.0.0.1':
#         for packet in TCP_list and UDP_list:
#             if start_time - packet[4] < 10:
#                 #CHECKER FOR SEQ DATA
#                 seq = packet[protocol].seq
#                 print("packet count seq is %s " %(seq)) #counts_seq
#                 return (True, "DoS")
#             #HAlf open connection:
#             elif ackFlag == True and resetFlag == True:
#                 counts_seq += 1
#                 timer = ceil(time.perf_counter())
#                 if counts_seq > 20 and timer > 10:
#                     print("Here is some analysis: ( victim : {} ->  attacker : {} )".format(sourceAddress ,destinationAddress))
#                 else:
#                     print("No problemo!")
#             else:
#                 break
#         return(False, "")