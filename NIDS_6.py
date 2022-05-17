# import io
# import re
import time
import pyshark
import sys
from pyshark.capture.live_capture import LiveCapture
from scapy.all import *
#import pandas as pd
import os
#from math import ceil
import socket
import warnings
import numpy as np

def Cap():
    print("starting")
    #INIT:
    start = time.time()
    SYN_counter = 0
    ACK_counter = 0
    UDP_counter = 0
    Ports_List = {} #List of all ports visited every 5 seconds
    scan_attack_counter = 0
    DoS_attack_counter = 0
    IP_scan_attack = None
    timer_analysis_start = time.time()
    capture = pyshark.FileCapture('C:/Users/edina/OneDrive/Backup/Skrivbord/capture_1_test.pcap')
    Local_IP = socket.gethostbyname(socket.gethostname())
    try:
        for packet in capture:
            #print("aksdfh")
            #print(capture)
            try:
                print("icmp: ", packet.icmp.type)
            except AttributeError as e:
                 pass
            timer_analysis_end = time.time()
            DoS = False
            UDP_flood = False
            TCP_flood = False
            Scan = False
            #print("here in for?")
            Scan_indicator(packet, Local_IP, Ports_List)
            Dos_indicator(packet, SYN_counter, ACK_counter, UDP_counter)
            if timer_analysis_end - timer_analysis_start > 0 :      #Analysis every 5 seconds
                timer_analysis_start = time.time()
                #print("before nalysis")
                (DoS, Scan) = analysis(SYN_counter, ACK_counter, UDP_counter, Ports_List, IP_scan_attack, UDP_flood, TCP_flood)
            if DoS or Scan:
                print("Dos: ", DoS)
                print("Scan: ", Scan)
                distribute(packet)
                if DoS :
                    DoS_attack_counter += 1
                    print("DOS ATTACK TIME: %s, and %s" % (time.time()-start, DoS_attack_counter))
                    mitigation_DoS(UDP_flood, TCP_flood)
                else :
                    scan_attack_counter += 1
                    print("SCAN ATTACK TIME: %s, and %s" % (time.time()-start, scan_attack_counter))
                    mitigation_Scan()
    except AttributeError as e:
            pass
            #print(e) #"In cap: "
            SystemExit()

def Scan_indicator(packet, Local_IP, Ports_List) :
    try: 
         packet.ip.dst
         packet[packet.transport_layer].dstport
    except AttributeError as e:
        pass
        #print("In scan",e)
    else:            
        if packet.ip.dst == Local_IP and packet[packet.transport_layer].dstport != None :
            if packet.ip.src in Ports_List.keys():
                Ports_List[packet.ip.src].extend(packet[packet.transport_layer].dstport)
                new_list = np.unique(np.array(Ports_List[packet.ip.src])).tolist()
                Ports_List[packet.ip.src] = new_list 
            else :
                Ports_List[packet.ip.src] = [packet[packet.transport_layer].dstport]


def Dos_indicator(packet, SYN_counter, ACK_counter, UDP_counter) :
    #print("in dos indicator")
    #This needs to change to flag_syn or whataver represents the syn flag
    if "tcp" in packet:
        try: 
            packet.tcp.flags_syn
        except AttributeError as e:
            pass
        #print(e)
        else:
            #Check the first message in the tcp handshake
            if packet.tcp.flags_syn == "1" and packet.tcp.flags_ack == "0":
             #print(packet.tcp)  
             SYN_counter += 1
             #print("Syn_counter: ", SYN_counter)
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
        #print("UDP-counter: ", UDP_counter)
        UDP_counter += 1
        return UDP_counter


def distribute(packet) :
    #print("distribute")
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
        #field_names = packet.tcp._all_fields
        #field_values = packet.tcp._all_fields.values()
        # for field_name in field_names:
        # #for field_value in field_values:  
        #     if field_name == 'tcp.payload':
        #         print(f'{field_name}') #-- {field_value[100:120, 1]}') #100:120, 1
        #         print("*"*10 + "Continuiing" + "*"*10) 
        if "tcp" in packet and "ip" not in packet:
            #packet_time = packet.sniff_time
            str_N = ('Name: ', packet.layers) #[-2]
            str_S_p = ('Scr. Port: ', packet[protocol].srcport)
            str_D_p = ('Dst. Port: ', packet[protocol].dstport)
            str1 = (str_N, str_S_p, str_D_p )# "Seq.": packet.sequence, "Len": packet.length, "Time": time.time, "Attri": TLP_attr   packet_time
            TCP_object.writelines(str(str1) + os.linesep)
            print ('%s  %s:%s --> %s:%s' % (str_N, packet[protocol].srcaddr, str_S_p, str_D_p, packet[protocol].dstaddr))
        elif "udp" in packet:
            #packet_time2 = packet.sniff_time
            str_N_2 = ('Name: ', packet.layers[-2])
            str_S_p_2 = ('Scr. Port: ', packet[protocol].srcport)
            str_D_p_2 = ('Dst. Port: ', packet[protocol].dstport)
            str2 = (str_N_2, str_S_p_2, str_D_p_2) #packet_time2
            #{"Name":packet.layers, "Src. Port": packet[protocol].srcport, "Dst. Port": packet[protocol].dstport, "Len": packet.length, "Time": time.time}
            UDP_object.writelines(str(str2) + os.linesep)
            print ('%s  %s:%s --> %s:%s' % (str_N_2, packet[protocol].srcaddr, str_S_p, str_D_p, packet[protocol].dstaddr))
        elif packet.icmp.type == '8':
            print("Should be icmp src %s, should be icmp dst %s: " % (packet[protocol].srcaddr, packet[protocol].dstaddr))

    except AttributeError as e:
            #print(e)
            pass
            SystemExit()
    TCP_object.close()
    UDP_object.close()
    UDP_DNS_object.close()

def analysis(SYN_counter, ACK_counter, UDP_counter, Ports_List, IP_scan_attack, UDP_flood, TCP_flood):
    #print("ANALYSIS")
    DoS = analysis_DoS(SYN_counter, ACK_counter, UDP_counter, UDP_flood, TCP_flood)
    Scan = analysis_Scan(Ports_List, IP_scan_attack)
    #print("END OF ANALYSIS")
    return(DoS, Scan)

def analysis_DoS(SYN_counter, ACK_counter, UDP_counter, UDP_flood, TCP_flood):
    if SYN_counter - ACK_counter > 10 : #in packet
        SYN_counter = 0
        ACK_counter = 0
        TCP_flood = True
        return (True) #'TCP SYN Flood'
    elif UDP_counter <= 10:
        SYN_counter = 0
        ACK_counter = 0
        return(False) #"No TCP SYN flood"
    elif UDP_counter > 10:
        UDP_counter = 0
        UDP_flood = True
        return (True) #, "UDP Flood"
    else:
        return (False) #, "No UDP flood"

def analysis_Scan(Ports_List, IP_scan_attack):
    #print("dictionary of ip and ports : ", Ports_List)
    for address_IP in Ports_List.keys() :
        if  len(Ports_List[address_IP])> 40 : #40 ports every 5 seconds
            IP_scan_attack = address_IP
            print("The attack: ", address_IP, IP_scan_attack)
            Ports_List = {}
            return True
    Ports_List = {}
    return False

# def analysis_icmp(icmp_counter):
#     check if packet.icmp.seq == 1000




def mitigation_DoS(UDP_flood, TCP_flood):
    print("MITIGATION DOS")
    blacklist_UDP = []
    blacklist_TCP = []
    if UDP_flood == True:
        try:
            warnings.warn("Warning suspicoius connedctions")
            print("You have chosen to exit.")
            print("The UDP connection you chose to blacklist and end is: ")
            source_address = packet.ip.src
            source_port = packet[packet.transport_layer].srcport
            blacklist_UDP.append(packet)
            return f'Source address: {source_address}' \
                        f'\nSource port: {source_port}\n'
        except OSError as e:
                print("Error: " + str(e.errno) + "\n Could not close connection.")
            
    elif TCP_flood == True: #TCP_FLOOD is syn and ack = 0
        warnings.warn("Warning suspicoius connedctions")
        print("You have chosen to exit.")
        print("The TCP connection you chose to blacklist and end is: ")
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        blacklist_TCP.append(packet)
        return f'Source address: {source_address}' \
            f'\nSource port: {source_port}\n'
    
    else:
        print("nothing to detect")

def mitigation_Scan():
    #Case one, ip address mitigation

    #Case 2: Document the ports being used otherwise gather information about the scan
    return 0

Cap()
#SystemExit(time)
#Ip address 130.241.238.143
##sudo nmap -sS -p 1-5000 192.168.44.1 130.241.238.143
#nmap -p 1-3339 --script smb-flood.nse 130.241.239.250
