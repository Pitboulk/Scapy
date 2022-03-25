#!/usr/bin/python3

from scapy.all import *

ipsrc = "192.168.198.128"
ipdst = "192.168.198.129"

ip = IP(src=ipsrc, dst=ipdst)
SYN = TCP(sport=40508, dport=90, flags="S", seq=12345)

send(ip/SYN, count=1)
