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
list_of_ip_addresses = []
attacker_ip = ""
Ports_List = {} #List of all ports visited every 5 seconds
Local_IP = socket.gethostbyname(socket.gethostname())


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
    timer_analysis_start = time.time()
    #capture = pyshark.LiveCapture("loopback")
    capture = pyshark.LiveCapture("WI-FI")
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
            Scan_indicator(packet)
            Dos_indicator(packet)
            if timer_analysis_end - timer_analysis_start > 5 : #Analysis every 5 seconds
                timer_analysis_start = time.time()
                (DoS, Scan) = analysis()
            if DoS or Scan:
                print("Dos: ", DoS)
                print("Scan: ", Scan)
                #distribute(packet) TODO fix this function
                if DoS :
                    attacker_ip = find_attacker_ip()
                    print("ATTACKER IP: ", attacker_ip)
                    DoS_attack_counter += 1
                    print("DOS ATTACK TIME: %s, and %s" % (time.time()-start, DoS_attack_counter))
                    mitigation_DoS(UDP_flood, TCP_flood)
                    #SystemExit()
                elif Scan :
                    scan_attack_counter += 1 #TODO this does not really make sense 
                    print("SCAN ATTACK TIME: %s, and %s" % (time.time()-start, scan_attack_counter))
                    mitigation_Scan()
                    #SystemExit()

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
      global Ports_list
      global icmp_counter
      try:
         packet.icmp.seq
      except AttributeError as e:
        #print("ICMP error: ", e)
        pass
      else:
          icmp_counter = icmp_counter + 1
          print("ICMP count: ", icmp_counter)
    # try: 
    #      packet.ip.dst
    #      packet[packet.transport_layer].dstport
    # except AttributeError as e:
    #     pass
    #     #print("In scan",e)
    # else:            
    #     if packet.ip.dst == Local_IP and packet[packet.transport_layer].dstport != None :
    #         if packet.ip.src in Ports_List.keys():
    #             Ports_List[packet.ip.src].extend(packet[packet.transport_layer].dstport)
    #             new_list = np.unique(np.array(Ports_List[packet.ip.src])).tolist()
    #             Ports_List[packet.ip.src] = new_list 
    #         else :
    #             Ports_List[packet.ip.src] = [packet[packet.transport_layer].dstport]


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
             print("Syn_counter: ", SYN_counter)
             return SYN_counter
    elif "udp" in packet:
        print("UDP counter: ", UDP_counter)
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
           print("in here")
           #print("Should be icmp src %s, should be icmp dst %s: " % (packet[protocol].srcaddr, packet[protocol].dstaddr))

    except AttributeError as e:
            #print(e)
            pass
            SystemExit()
    TCP_object.close()
    UDP_object.close()
    UDP_DNS_object.close()

def analysis():
    print("ANALYSIS")
    DoS = analysis_DoS()
    Scan = analysis_icmp()
    #Scan = analysis_Scan(Ports_List, IP_scan_attack)
    #print("END OF ANALYSIS")
    return(DoS, Scan)

def analysis_DoS():
    global SYN_counter
    global UDP_counter
    global TCP_flood
    global UDP_flood
    print("Syn_counter2: ", SYN_counter)
    print("Udp_counter2: ", UDP_counter)
    if SYN_counter > 50 :
        print("In syn")
        TCP_flood = True
        SYN_counter = 0
        return (True) # TCP SYN Flood
    elif UDP_counter > 50:
        print("In syn")
        UDP_flood = True
        UDP_counter = 0
        return(True) # UDP Flood
    else :
        SYN_counter = 0
        UDP_counter = 0
        return (False) #, "No UDP flood"

#Not used anymore
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

def analysis_icmp():
 global icmp_counter
 print("in analysis_icmp: ", icmp_counter)
 if icmp_counter > 10:
     print("icmp attack")
     icmp_counter = 0
     return True




def mitigation_DoS(UDP_flood, TCP_flood):
    print("MITIGATION DOS")
    blacklist_UDP = []
    blacklist_TCP = []
    if UDP_flood :
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
            
    elif TCP_flood : #TCP_FLOOD is syn and ack = 0
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

#Not sure what to do in here
def mitigation_Scan():
    print("Scan mitigation")
    #Case one, ip address mitigation

    #Case 2: Document the ports being used otherwise gather information about the scan
    return 0

Cap()
#SystemExit(time)
#Ip address 130.241.238.143
##sudo nmap -sS -p 1-5000 192.168.44.1 130.241.238.143
#nmap -p 1-3339 --script smb-flood.nse 130.241.239.250
