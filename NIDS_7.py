import time
import pyshark
from pyshark.capture.live_capture import LiveCapture
from scapy.all import *
import os
import socket
import numpy as np
from collections import Counter

#initialization
icmp_counter = 0 #Counts the number of ICMP packets received
SYN_counter = 0  #Counts the number of SYN packets received
ACK_counter = 0  #Counts the number of ACK packets received (not currently used)
UDP_counter = 0  #Counts the number of UDP packets received
UDP_flood = False
TCP_flood = False
scan_attack = False
ICMP_attack = False
list_of_ip_addresses = [] #Collects src ip addresses from captured traffic
attacker_ip = ""
Ports_List = {} #List of all ports visited every 5 seconds
Local_IP = socket.gethostbyname(socket.gethostname())
IP_of_scan_attacker = None


#Adjust these for according to preference/testing
SYN_threshold = 400 #Number of SYN packets in analysis_interval before attack detected
UDP_threshold = 400 #Number of UDP packets in analysis_interval before attack detected
ICMP_threshold = 10 #Number of ICMP packets in analysis_interval before attack detected
Analysis_interval = 2 #Interval for attack analysis (packets are checked every x seconds)

'''
The main method, 
- Captures traffic
- Sends packets to Scan and DoS indicators and updates counters and ports_list accordingly
- Sends packets to analysis to detect attacks
- Calls mitigation if attack
- Also calls distibrute to save information about the attack

'''

def Cap():
    print("starting")
    #INIT:
    start = time.time()
    global Ports_List
    global attacker_ip
    global TCP_flood
    global UDP_flood
    global Local_IP
    global list_of_ip_addresses
    global Analysis_interval
    storage_counter = 0
    timer_analysis_start = time.time()
    capture = pyshark.LiveCapture("loopback") #For testing scanning attacks
    #capture = pyshark.LiveCapture("WI-FI")   #For testing SYN and UDP DoS attacks
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
            if timer_analysis_end - timer_analysis_start > Analysis_interval : #Analysis every 5 seconds
                timer_analysis_start = time.time()
                (DoS, Scan, ICMP) = analysis()
            if DoS or Scan or ICMP:
                storage_counter = 100
                print("Dos: ", DoS)
                print("Scan: ", Scan)
                print("ICMP: ", ICMP)
                attacker_ip = find_attacker_ip()
                if DoS :
                    print("ATTACKER IP: ", attacker_ip)
                    print("SCAN ATTACK TIME: %s" % (time.time()-start))
                    mitigation_DoS()
                    list_of_ip_addresses = [] #Reset the list after attack
                    #SystemExit() #Choose to exit after attack detection and mitigation
                elif Scan :
                    print("ATTACKER IP: ", IP_of_scan_attacker)
                    print("SCAN ATTACK TIME: %s" % (time.time()-start))
                    mitigation_Scan()
                    list_of_ip_addresses = [] #Reset the list after attack
                    #SystemExit() #Choose to exit after attack detection and mitigation
                elif ICMP :
                    print("ATTACKER IP: ", attacker_ip)
                    print("SCAN ATTACK TIME: %s" % (time.time()-start))
                    mitigation_Scan()
                    list_of_ip_addresses = [] #Reset the list after attack
                    #SystemExit() #Choose to exit after attack detection and mitigation
            if storage_counter >= 0 :
                distribute(packet)
                storage_counter = storage_counter - 1

    except AttributeError as e:
            pass
            print("error, system will exit because: ", e)


#Finds the most common ip address
def find_attacker_ip() :
    global list_of_ip_addresses
    c = Counter(list_of_ip_addresses)
    c.most_common(1)
    return (c.most_common(1)[0])[0] #Return only the ip, skip the number of occurrences


#Takes packet and checks if icmp, then it updates icmp_counter.
#If packet is udp or tcp, Ports_List is updated with all the targeted ports
def Scan_indicator(packet) :
      global Local_IP
      global Ports_List
      global icmp_counter
      try:
          packet.icmp.seq
      except AttributeError as e:
         pass
      else:
           icmp_counter = icmp_counter + 1
      try: 
          packet.ip.dst
          packet[packet.transport_layer].dstport
      except AttributeError as e:
         pass
      else:         
         if packet.ip.dst == Local_IP and packet[packet.transport_layer].dstport != None :
             if packet.ip.src in Ports_List.keys():
                 temp_list = Ports_List[packet.ip.src]
                 temp_list.append(packet[packet.transport_layer].dstport)
                 new_list = np.unique(np.array(temp_list)).tolist()
                 Ports_List[packet.ip.src] = new_list 
             else :
                 Ports_List[packet.ip.src] = [packet[packet.transport_layer].dstport]


#Takes packet and checks if its the first step in the TCP handshake, then it updates SYN_counter
#Otherwise it checks if the packet is UDP, then it updates UDP_counter
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
            #Check if its the first message in the tcp handshake
            if packet.tcp.flags_syn == "1" and packet.tcp.flags_ack == "0":
             SYN_counter += 1
             return SYN_counter
    elif "udp" in packet:
        UDP_counter += 1
        return UDP_counter

#Creates files for TCP and UDP packet information and adds information to the files if attack is detected
def distribute(packet) :

    #FILE OBJECTS:
    TCP_object = open(r"TCP.txt", "a")
    UDP_object = open(r"UDP.txt", "a")

    try:
        if "tcp" in packet:
            protocol = packet.transport_layer
            str_N = ('Name: ', packet.layers) 
            str_S_p = ('Scr. Port: ', packet[protocol].srcport)
            str_D_p = ('Dst. Port: ', packet[protocol].dstport)
            str1 = (str_N, str_S_p, str_D_p )
            TCP_object.writelines(str(str1) + os.linesep)
            print ("TCP: ",str_N, packet[protocol].srcaddr, str_S_p, str_D_p, packet[protocol].dstaddr)
        elif "udp" in packet:
            protocol = packet.transport_layer
            str_N_2 = ('Name: ', packet.layers[-2])
            str_S_p_2 = ('Scr. Port: ', packet[protocol].srcport)
            str_D_p_2 = ('Dst. Port: ', packet[protocol].dstport)
            str2 = (str_N_2, str_S_p_2, str_D_p_2)
            UDP_object.writelines(str(str2) + os.linesep)
            print ("UDP: ",str_N_2, packet[protocol].srcaddr, str_S_p, str_D_p, packet[protocol].dstaddr)
        #else :
            #print("Neither TCP nor UDP")

    except AttributeError as e:
            #print("Distribute - Attribute error: ", repr(e))
            pass
            SystemExit()
    TCP_object.close()
    UDP_object.close()

#Analysis function, distributes to DoS, Scan and icmp scan methods
def analysis():
    print("ANALYSIS")
    DoS = analysis_DoS()
    Scan = analysis_Scan()
    ICMP = analysis_icmp()
    return(DoS, Scan, ICMP)

#TCP SYN and UDP Denial Of Service analysis
def analysis_DoS():
    global SYN_counter
    global UDP_counter
    global TCP_flood
    global UDP_flood
    global SYN_threshold
    if SYN_counter > SYN_threshold : #Change in initialization
        TCP_flood = True
        SYN_counter = 0
        print("SYN Flood DoS attack!")
        return (True) # TCP SYN Flood
    elif UDP_counter > UDP_threshold: #Change in initialization
        UDP_flood = True
        UDP_counter = 0
        print("UDP DoS attack!")
        return(True) # UDP Flood
    else :
        SYN_counter = 0
        UDP_counter = 0
        UDP_flood = False
        TCP_flood = False
        return (False)

#Checks if there is an ongoing TCP or UDP scanning attack
def analysis_Scan():
    global Ports_List
    global IP_of_scan_attacker
    global scan_attack
    #print("dictionary of ip and ports : ", Ports_List)
    for address_IP in Ports_List.keys() :
        if  len(Ports_List[address_IP])> 5 : #40 ports every 5 seconds
            IP_of_scan_attacker = address_IP
            Ports_List = {}
            scan_attack = True
            print("Scan attack!")
            return True
    Ports_List = {}
    scan_attack = False
    return False

#Checks if there is an ongoing ICMP scanning attack
def analysis_icmp():
 global icmp_counter
 global ICMP_attack
 global ICMP_threshold
 if icmp_counter > ICMP_threshold:
     icmp_counter = 0
     ICMP_attack = True
     print("ICMP attack!")
     return True
 else :
    ICMP_attack = False
    return False


#Adds the attack_ip to a blacklist that can later be used to block the ip address(es) (for Dos)
def mitigation_DoS():
    global TCP_flood
    global UDP_flood
    global attacker_ip
    print("MITIGATION DOS")
    blacklist_UDP_flood = []
    blacklist_TCP_flood = []
    if UDP_flood :
        try:
            blacklist_UDP_flood.append(attacker_ip)
            print("BlackList_UDP_flood: ", blacklist_UDP_flood)
            return f'BlackList_UDP_flood: {blacklist_UDP_flood}'
        except OSError as e:
                print("Error: " + str(e.errno) + "\n Could not close connection.")
            
    elif TCP_flood : #TCP_FLOOD is syn and ack = 0

        blacklist_TCP_flood.append(attacker_ip)
        print("BlackList_TCP_flood: ", blacklist_TCP_flood)
        return f'BlackList_TCP_flood: {blacklist_TCP_flood}'
    
    else:
        print("Nothing to mitigate")

#Adds the attack_ip to a blacklist that can later be used to block the ip address(es) (For scan)
def mitigation_Scan():
    global attacker_ip
    global IP_of_scan_attacker
    global IP_scan_attack
    global scan_attack
    global ICMP_attack
    blacklist_scan = []
    blacklist_icmp_scan = []
    if scan_attack :
        try :
            blacklist_scan.append(IP_of_scan_attacker)
            print("Blacklist_scan: ", blacklist_scan)
            return f'BlackList_scan: {blacklist_scan}'
        except OSError as e:
                print("Error: " + str(e.errno) + "\n Could not close connection.")

    elif ICMP_attack :
        try :
            blacklist_icmp_scan.append(attacker_ip)
            print("blacklist_icmp_scan: ", blacklist_icmp_scan)
            return f'blacklist_icmp_scan: {blacklist_icmp_scan}'
        except OSError as e:
                print("Error: " + str(e.errno) + "\n Could not close connection.")

    
    else:
        print("Nothing to mitigate")

#Start
Cap()
