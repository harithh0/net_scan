import ipaddress

from scapy.all import DNS, DNSQR, IP, TCP, UDP, sr

# imports everything (func, classes, vars) from scapy.all without prefixing them with 'scapy.all.<func>' but can litter namespace and can cause issues if 2 things have the same name. similar to usenamespace std;
# from scapy.all import *


class Setup:
    __common_ports = (22, 25, 80, 443, 445, 8080, 8443)

    def __init__(self, host):
        self.host = host

    def syn_scan(self):
        """
        does syn scan on host
        """

        print(f"Scanning (SYN) {self.host}")
        """
        - all other flags will be set by scapy automatically
        - returns a tuple full of 'scapy QueryAnswer' objects, of answered results and unanswered results. answered does not mean port is opened, 
            it just simply saying that we got a reponse back from the request we sent
        - 'IP / TCP' builds the SYN packet and 'sr' (send and recieve) sends them to the host and ports
        - Timeout of 2 sec, saying if it doesn't hear back from target after request send in 2 sec it will close it
        - 'sr' sends packets at layer 3 and waits for a reply 
            - it will send it and the OS checks its routing table: if the IP is on the local subnet
        """
        answered, unanswered = sr(
            IP(dst=self.host) /
            TCP(sport=9999, dport=list(Setup.__common_ports), flags="S"),
            timeout=2,
            verbose=0,
        )

        print("Scan finished")
        """
        - go through the packet we sent and received from the answered tuple. Packet is of IP type
        - accessing the TCP layer of each packet
        """

        for sent, recv in answered:
            if sent[TCP].dport == recv[TCP].sport and recv[TCP].flags == "SA":
                print(f"{recv[TCP].sport} open")

    def dns_scan(self):
        """
        sends DNS request (port 53) to host and sees if it responds with DNS reponse, thus telling us it's a DNS server
        """

        print(f"Scanning (DNS) {self.host}")

        # crafts packet and sends it
        packet = (
            IP(dst=self.host) / UDP(dport=53) /
            # 'rd' is
            DNS(rd=1, qd=DNSQR(qname="google.com")))

        answered, unanswered = sr(packet, timeout=2, verbose=0)

        if answered and answered[UDP]:
            print(f"{self.host} is a DNS Server")
        else:
            print(f"No DNS server found on {self.host}")


x = Setup("8.8.8.8")
x.syn_scan()
x.dns_scan()
