from scapy.all import *

packet = IP(dst="10.0.0.192") / TCP(dport=1200, sport=3333, flags="F")

a, u = sr(packet, timeout=5, verbose=0)

print(a, u)
