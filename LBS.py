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

#global TCP_list
TCP_list = [] #TCP list packet storage
#global UDP_list
UDP_list = [] #UDP list package storage
SYN_counter = 0
ACK_counter = 0
UDP_counter = 0



def Cap():
    timer_analysis_start = time.time()
    #print("Start time: " , timer_analysis_start)
    capture = pyshark.LiveCapture("WI-FI")

    for packet in capture:
        timer_analysis_end = time.time()
        #print("End time: ", timer_analysis_end)
        alarm = False
        counters_up_to_date(packet)

        if timer_analysis_end - timer_analysis_start > 1 :      #Analysis every 5 seconds
            timer_analysis_start = time.time()
            (alarm, attack) = analysis(packet)
            #print(alarm, attack)

        if alarm:
            print(attack)
            distribute(packet)
            #mitigation(attack)


def counters_up_to_date(packet) :
    #print("In counter_up_to_date")
    global SYN_counter
    global ACK_counter
    global UDP_counter
    #This needs to change to flag_syn or whataver represents the syn flag
    if "tcp" in packet :
        SYN_counter += 1
    #This needs to change to flag_ack or whataver represents the ack flag
    elif "ack" in packet :
        ACK_counter += 1
    elif "udp" in packet :
        UDP_counter += 1


def distribute(packet) :
    TCP_object = open(r"TCP.txt", "a")
    UDP_object = open(r"UDP.txt", "a")
    UDP_DNS_object = open(r"UDP_DNS.txt", "a")
    #TCP_object = open(r"C:/Users/edina/Downloads/Lang. Based Sec/TCP.txt", "a")
    #UDP_object = open(r"C:/Users/edina/Downloads/Lang. Based Sec/UDP.txt", "a")
    #UDP_DNS_object = open(r"C:/Users/edina/Downloads/Lang. Based Sec/UDP_DNS.txt", "a")
    try:
        #counts_seq += 1
        protocol = packet.transport_layer

        #Check if TCP syn and fin messages are fine then scan trough the tcp and fetch to file
        field_names = packet.tcp._all_fields
        field_values = packet.tcp._all_fields.values()
        #for field_name in field_names:
            #for field_value in field_values:
                #if field_name == 'tcp.payload':
                    #print(f'{field_name} -- {field_value[100:120, 1]}') #100:120, 1
                    #print("*"*10 + "Continuiing" + "*"*10)
        #We only want to save SYN packets here so check the SYN flag 
        if "tcp" in packet:
            #packet_time = packet.sniff_time
            str_N = ('Name: ', packet.layers) #[-2]
            str_S_p = ('Scr. Port: ', packet[protocol].srcport)
            str_D_p = ('Dst. Port: ', packet[protocol].dstport)
            str1 = (str_N, str_S_p, str_D_p )# "Seq.": packet.sequence, "Len": packet.length, "Time": time.time, "Attri": TLP_attr   packet_time
            print("Write to the tcp file")
            TCP_object.writelines(str(str1) + os.linesep)
            print ('%s  %s:%s --> %s:%s' % (str_N, packet[protocol].srcaddr, str_S_p, str_D_p, packet[protocol].dstaddr))
            #TCP_list.extend(packet)
        elif "udp" in packet:
            packet_time2 = packet.sniff_time
            str_N_2 = ('Name: ', packet.layers[-2])
            str_S_p_2 = ('Scr. Port: ', packet[protocol].srcport)
            str_D_p_2 = ('Dst. Port: ', packet[protocol].dstport)
            str2 = (str_N_2, str_S_p_2, str_D_p_2, packet_time2)
            #{"Name":packet.layers, "Src. Port": packet[protocol].srcport, "Dst. Port": packet[protocol].dstport, "Len": packet.length, "Time": time.time}
            print("Write to the udp file")
            UDP_object.writelines(str(str2) + os.linesep)
            #UDP_list.extend(packet)
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
            #UDP_list_DNS.extend(packet)
        #
        #
        #Here look for more packet petterns!

        #CHECKER FOR SEQ DATA
        seq = packet[protocol].seq
        print("packet count seq is %s " %(seq)) #counts_seq

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
def analysis(packet):
    global SYN_counter
    global ACK_counter
    global UDP_counter
    start_time = time.time()
    if "tcp" in packet:
        if SYN_counter - ACK_counter > 10 :
            SYN_counter = 0
            ACK_counter = 0
            return (True, 'TCP SYN Flood')
        else :
            SYN_counter = 0
            ACK_counter = 0
            return(False, "No TCP SYN flood")
    elif "udp" in packet:
        if UDP_counter > 10:
            UDP_counter = 0
            return (True, "UDP Flood")
        else:
            return (False, "No UDP flood")
    else:
        return (False, "No TCP or UDP")
 
"""
Idea:
* Use livecapture that runs all the time
* Dot not save all the packet info
* Only save value of counters
* Start saving packets when an attack is detected
* SYN flood attack detection:
    SYNCounter should count number of messages with SYN flag
    ACKCounter should count number of messages with ACK flag
    Also start a SYNFloodTimer
    IF SYNCounter - ACKCounter > threshold in timeframe then we set off alarm and block start saving packets
    ELSE reset both counters and timeframe
    Start over 
* ICMP/UDP flood
    ICMPCounter should count the number of packets received from same IP address
    UDPCounter should count the number of packets received from same IP address
    Trigger alarm if ICMPCounter || UDPCounter > threshold in timeframe
    ELSE reset timer and counters and start over
"""

def dosAnalysis(packet):
    switcher = {
        0: ""

    }





def mitigation(attack):

    return 0


start = time.time  
Cap()
