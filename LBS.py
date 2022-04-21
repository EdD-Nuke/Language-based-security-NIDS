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

global TCP_list
TCP_list = [] #TCP list packet storage
global UDP_list
UDP_list = [] #UDP list package storage
global SYN_counter
SYN_counter = 0
global ACK_counter
ACK_counter = 0



def Cap():
    timer_analysis_start = time.time
    capture = pyshark.LiveCapture("WI-FI")

    for packet in capture:
        timer_analysis_end = time.time
        alarm = False
        counters_up_to_date(packet)

        if timer_analysis_end - timer_analysis_start > 5 :      #Analysis every 5 seconds
            timer_analysis_start = time.time
            (alarm, attack) = analysis()

        if alarm:
            distribute(packet)
            mitigation(attack)


def counters_up_to_date(packet) :
    if "syn" in packet :
        SYN_counter += 1
    elif "ack" in packet :
        ACK_counter += 1


def distribute(packet) :
    TCP_object = open(r"C:/Users/edina/Downloads/Lang. Based Sec/TCP.txt", "w")
    UDP_object = open(r"C:/Users/edina/Downloads/Lang. Based Sec/UDP.txt", "w")
    try:
        protocol = packet.transport_layer
        if "tcp" in packet:
            TCP_object.writelines("TCP")
            print("TCP")
            TCP_list.extend(packet)
        elif "udp" in packet:
            UDP_object.writelines("UDP")
            print("UDP")
            UDP_list.extend(packet)
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
    if SYN_counter - ACK_counter > 100 :
        SYN_counter = 0
        ACK_counter = 0
        return (True, 'DoS')
    else :
        SYN_counter = 0
        ACK_counter = 0
    return(False, "")
 
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