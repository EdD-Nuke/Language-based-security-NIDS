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
from collections import Counter

#initialization
icmp_counter = 0
SYN_counter = 0
ACK_counter = 0
UDP_counter = 0
scan_attack_counter = 0
DoS_attack_counter = 0
UDP_flood = False
TCP_flood = False
scan_attack = False
list_of_ip_addresses = []
attacker_ip = ""
Ports_List = {} #List of all ports visited every 5 seconds
Local_IP = socket.gethostbyname(socket.gethostname())
IP_of_attacker = None
IP_of_ICMP_attacker = None


def Cap():
    print("starting")
    #INIT:
    start = time.time()
    global scan_attack_counter
    global DoS_attack_counter
    global Ports_List
    global attacker_ip
    global TCP_flood
    global UDP_flood
    global Local_IP
    global list_of_ip_addresses
    storage_counter = 0
    timer_analysis_start = time.time()
    capture = pyshark.LiveCapture("loopback")
    #capture = pyshark.LiveCapture("WI-FI")
    try:
        for packet in capture:
            try:
                packet.ip.src
            except AttributeError as e:
                pass
            else:
                list_of_ip_addresses.append(packet.ip.src)
            timer_analysis_end = time.time()
            DoS = False
            Scan = False
            ICMP = False
            Scan_indicator(packet)
            Dos_indicator(packet)
            if timer_analysis_end - timer_analysis_start > 5 : #Analysis every 5 seconds
                timer_analysis_start = time.time()
                (DoS, Scan, ICMP) = analysis()
            if DoS or Scan or ICMP:
                storage_counter = 100
                print("Dos: ", DoS)
                print("Scan: ", Scan)
                print("ICMP: ", ICMP)
                #distribute(packet) TODO fix this function
                if DoS :
                    attacker_ip = find_attacker_ip()
                    print("ATTACKER IP: ", attacker_ip)
                    DoS_attack_counter += 1
                    print("DOS ATTACK TIME: %s, and %s" % (time.time()-start, DoS_attack_counter))
                    mitigation_DoS()
                    #SystemExit()
                elif Scan or ICMP :
                    attacker_ip = IP_of_attacker
                    print("IP_of_attacker: ", IP_of_attacker)
                    scan_attack_counter += 1 #TODO this does not really make sense 
                    print("SCAN ATTACK TIME: %s, and %s" % (time.time()-start, scan_attack_counter))
                    mitigation_Scan()
                    #SystemExit()
            if storage_counter >= 0 :
                distribute(packet)
                storage_counter = storage_counter - 1

    except AttributeError as e:
            pass
            print("error, system will exit because: ", e) #"In cap: "
            SystemExit()


#Finds the most common ip address
def find_attacker_ip() :
    global list_of_ip_addresses
    c = Counter(list_of_ip_addresses)
    c.most_common(1)
    print ("",c.most_common(1))
    return (c.most_common(1)[0])[0] #Return only the ip, skip the number of occurrences



def Scan_indicator(packet) :
      global Local_IP
      global Ports_List
      global icmp_counter
      try:
          packet.icmp.seq
      except AttributeError as e:
         #print("ICMP error: ", e)
         pass
      else:
           icmp_counter = icmp_counter + 1
           #print("ICMP count: ", icmp_counter)
           #print("ICMP all fields: ", packet.icmp._all_fields)
      try: 
          packet.ip.dst
          packet[packet.transport_layer].dstport
      except AttributeError as e:
         pass
         #print("In scan",e)
      else:         
             #print("port reached : ", packet[packet.transport_layer].dstport)   
         if packet.ip.dst == Local_IP and packet[packet.transport_layer].dstport != None :
             if packet.ip.src in Ports_List.keys():
                 test_list = Ports_List[packet.ip.src]
                 test_list.append(packet[packet.transport_layer].dstport)
                 new_list = np.unique(np.array(test_list)).tolist()
                 Ports_List[packet.ip.src] = new_list 
             else :
                 Ports_List[packet.ip.src] = [packet[packet.transport_layer].dstport]


def Dos_indicator(packet) :
    global ACK_counter
    global SYN_counter
    global UDP_counter
    if "tcp" in packet:
        try: 
            packet.tcp.flags_syn
        except AttributeError as e:
            pass
        else:
            #Check the first message in the tcp handshake
            if packet.tcp.flags_syn == "1" and packet.tcp.flags_ack == "0":
             #print(packet.tcp)  
             SYN_counter += 1
             print("Syn_counter: ", SYN_counter, "port reached : ", packet[packet.transport_layer].dstport)
             return SYN_counter
    elif "udp" in packet:
        print("UDP counter: ", UDP_counter)
        UDP_counter += 1
        return UDP_counter


def distribute(packet) :

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
            protocol = packet.transport_layer
            #packet_time = packet.sniff_time
            str_N = ('Name: ', packet.layers) #[-2]
            str_S_p = ('Scr. Port: ', packet[protocol].srcport)
            str_D_p = ('Dst. Port: ', packet[protocol].dstport)
            str1 = (str_N, str_S_p, str_D_p )# "Seq.": packet.sequence, "Len": packet.length, "Time": time.time, "Attri": TLP_attr   packet_time
            TCP_object.writelines(str(str1) + os.linesep)
            print ('%s  %s:%s --> %s:%s' % (str_N, packet[protocol].srcaddr, str_S_p, str_D_p, packet[protocol].dstaddr))
        elif "udp" in packet:
            protocol = packet.transport_layer
            #packet_time2 = packet.sniff_time
            str_N_2 = ('Name: ', packet.layers[-2])
            str_S_p_2 = ('Scr. Port: ', packet[protocol].srcport)
            str_D_p_2 = ('Dst. Port: ', packet[protocol].dstport)
            str2 = (str_N_2, str_S_p_2, str_D_p_2) #packet_time2
            #{"Name":packet.layers, "Src. Port": packet[protocol].srcport, "Dst. Port": packet[protocol].dstport, "Len": packet.length, "Time": time.time}
            UDP_object.writelines(str(str2) + os.linesep)
            print ('%s  %s:%s --> %s:%s' % (str_N_2, packet[protocol].srcaddr, str_S_p, str_D_p, packet[protocol].dstaddr))

    except AttributeError as e:
            print(e)
            pass
            SystemExit()
    TCP_object.close()
    UDP_object.close()
    UDP_DNS_object.close()

def analysis():
    print("ANALYSIS")
    DoS = analysis_DoS()
    Scan = analysis_Scan()
    ICMP = analysis_icmp()
    return(DoS, Scan, ICMP)

def analysis_DoS():
    global SYN_counter
    global UDP_counter
    global TCP_flood
    global UDP_flood
    print("Syn_counter2: ", SYN_counter)
    print("Udp_counter2: ", UDP_counter)
    if SYN_counter > 400 :
        print("In syn")
        TCP_flood = True
        SYN_counter = 0
        return (True) # TCP SYN Flood
    elif UDP_counter > 400:
        print("In syn")
        UDP_flood = True
        UDP_counter = 0
        return(True) # UDP Flood
    else :
        SYN_counter = 0
        UDP_counter = 0
        UDP_flood = False
        TCP_flood = False
        return (False) #, "No UDP flood"


def analysis_Scan():
    global Ports_List
    global IP_of_attacker
    global scan_attack
    print("dictionary of ip and ports : ", Ports_List)
    for address_IP in Ports_List.keys() :
        if  len(Ports_List[address_IP])> 40 : #40 ports every 5 seconds
            IP_of_attacker = address_IP
            print("The attack: ", address_IP, IP_of_attacker)
            Ports_List = {}
            scan_attack = True
            return True
    Ports_List = {}
    scan_attack = False
    return False

def analysis_icmp():
 global icmp_counter
 global scan_attack
 global IP_of_ICMP_attacker
 print("in analysis_icmp: ", icmp_counter)
 if icmp_counter > 10:
     print("icmp attack")
     icmp_counter = 0
     scan_attack = True
     return True




def mitigation_DoS():
    global TCP_flood
    global UDP_flood
    global attacker_ip
    print("MITIGATION DOS")
    blacklist_UDP = []
    blacklist_TCP = []
    if UDP_flood :
        try:
            #warnings.warn("Warning suspicoius connedctions")
            #print("You have chosen to exit.")
            #print("The UDP connection you chose to blacklist and end is: ")
            #source_port = packet[packet.transport_layer].srcport
            blacklist_UDP.append(attacker_ip)
            print("BlackList_UDP: ", blacklist_UDP)
            return f'BlackList_UDP: {blacklist_UDP}'
        except OSError as e:
                print("Error: " + str(e.errno) + "\n Could not close connection.")
            
    elif TCP_flood : #TCP_FLOOD is syn and ack = 0

        blacklist_TCP.append(attacker_ip)
        print("BlackList_TCP: ", blacklist_TCP)
        return f'BlackList_TCP: {blacklist_TCP}'
    
    else:
        print("Nothing to detect")

#Not sure what to do in here
def mitigation_Scan():
    global attacker_ip
    global IP_scan_attack
    global scan_attack
    blacklist_scan = []
    if scan_attack :
        try :
            blacklist_scan.append(attacker_ip)
            print("Blacklist_scan: ", blacklist_scan)
            return f'BlackList_scan: {blacklist_scan}'
        except OSError as e:
                print("Error: " + str(e.errno) + "\n Could not close connection.")

    else:
        print("Nothing to detect")

Cap()
#SystemExit(time)
#Ip address 130.241.238.143
##sudo nmap -sS -p 1-5000 192.168.44.1 130.241.238.143
#nmap -p 1-3339 --script smb-flood.nse 130.241.239.250
