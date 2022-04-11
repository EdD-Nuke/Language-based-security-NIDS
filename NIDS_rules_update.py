from distutils.file_util import write_file
import io
import re
import time
import pyshark
import sys
from pyshark.capture.live_capture import LiveCapture

#DoS attacks port 80 based assume
protocollayers = {}
protocolAttributes = {}

##################
TLP_packets = {}
TLP_attr = {}

ICMP_packets = {}
ICMP_attr = {}

def Cap():
    count = 0
    capture = pyshark.LiveCapture("WI-FI")
    for packet in capture:
        count += 1
        distribute(packet, capture)
        if count > 10:
            (alarm) = analysis() #, attack
            count = 0
        #if alarm:
            #mitigation(attack)

def distribute(packet, capture) :
    TCP_object = open(r"TCP.txt", "w")
    UDP_object = open(r"UDP.txt", "w")
    try:
        if "tcp" in capture():
            str1 = [{"Name":packet.name, "Src. Port": packet.src_port, "Dst. Port": packet.dest_port, "Seq.": packet.sequence, "Len": packet.length, "Time": time.time, "Attri": TLP_attr}]
            TCP_object.write(str1)
        elif "udp" in capture:
            str2 = [{"Name":packet.name, "Src. Port": packet.src_port, "Dst. Port": packet.dest_port, "Len": packet.length, "Time": time.time}]
            UDP_object.write(str2)
        
        if "tcp" in packet or "udp" in packet :
            TLP_packets += [[packet.name, packet.src_port, packet.dest_port, packet.length, time.time, TLP_attr]]
            TCP_attr += 1
        elif "icmp" in packet :
            ICMP_packets += [[packet.name, packet.src_addr, packet.dest_addr, packet.length, time.time, ICMP_attr]]
            ICMP_attr += 1
    except AttributeError as e:
            print(e)
            SystemExit()
    TCP_object.close()
    UDP_object.close()


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
