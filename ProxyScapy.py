
#!/usr/bin/python3

from scapy.all import *
import hashlib


def packetForger(pkt):
        if pkt[TCP].flags == 2:
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
                hashed = str(pkt[IP].src)+str(pkt[TCP].sport) + \
                             str(pkt[IP].dst)+str(pkt[TCP].dport)
                hashedCookie = int(hashlib.sha1(
                    hashed.encode("utf-8")).hexdigest(), 16) % (10 ** 8)
                print(pkt[TCP].seq)
                print(hashedCookie)
                newSeq = pkt[TCP].seq + 1
                print(newSeq)
                ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
                synack_packet = TCP(sport=dport, dport=sport, flags="SA", seq=hashedCookie, ack=new$
                send(ip/synack_packet)

        elif pkt[TCP].flags == 16:
                print(pkt[TCP].flags)
                f=open("/home/gautier/whitelist.txt", "a")
                f.write(pkt[IP].src)
        else:
                pass

sniff(prn=packetForger, filter="tcp and port 90", store=0)
