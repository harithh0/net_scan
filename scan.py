import ipaddress

from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, sr, sr1

# imports everything (func, classes, vars) from scapy.all without prefixing them with 'scapy.all.<func>' but can litter namespace and can cause issues if 2 things have the same name. similar to usenamespace std;
# from scapy.all import *


class Setup:
    __common_ports = (22, 25, 80, 443, 445, 8080, 8443, 12345)
    SOURCE_PORT = 3333

    def __init__(self, host):
        self.host = host

    def syn_scan(self):
        """
        does syn scan on host
        """

        print(f"Scanning (SYN) {self.host}")
        """
        - all other flags will be set by scapy automatically
            - Manually is <protocol/layer>(<flags> = ..)
        - returns a tuple full of 'scapy QueryAnswer' objects, of answered results and unanswered results. answered does not mean port is opened, 
            it just simply saying that we got a reponse back from the request we sent
        - 'IP / TCP' builds the SYN packet and 'sr' (send and recieve) sends them to the host and ports
        - Timeout of 2 sec, saying if it doesn't hear back from target after request send in 2 sec it will close it
        - 'sr' sends packets at layer 3 and waits for a reply 
            - it will send it and the OS checks its routing table: if the IP is on the local subnet -> do ARP for device, else ARP for defualt gateway then route to it
            - OS wraps the IP packet in an Ethernet frame with the proper MAC and sends the full Ethernet frame via NIC.
        """
        answered, unanswered = sr(
            IP(dst=self.host) / TCP(sport=Setup.SOURCE_PORT,
                                    dport=list(Setup.__common_ports),
                                    flags="S"),
            timeout=2,
            verbose=0,
        )

        print("Scan finished")
        """
        - go through the packet we sent and received from the answered tuple. Packet is of IP type
        - accessing the TCP layer of each packet and checking to make sure the sent and recv ports match and that the recv packet TCP layer has a flag of SYN ACK
        - if it the port is closed (no service running) but allowed through firewall, the host will send a packet with RST ACK flags
        """

        for sent, recv in answered:
            if sent[TCP].dport == recv[TCP].sport:
                if recv[TCP].flags == "SA":
                    print(f"{recv[TCP].sport} open")
                elif recv[TCP].flags == "RA":
                    print(f"{recv[TCP].sport} closed")

    def dns_scan(self):
        """
        - sends DNS request (port 53) to host and sees if it responds with DNS reponse, thus telling us it's a DNS server
        - If port is closed, it will send out an ICMP "port unreachable"
        """

        print(f"Scanning (DNS) {self.host}")

        # crafts IP (3) -> UDP (4) -> DNS (5/7) packet and sends it
        packet = (
            IP(dst=self.host) / UDP(sport=Setup.SOURCE_PORT, dport=53) /
            # 'rd' (recursion desired flag), tells DNS server "if you don't know the answer go find it for me", common for client -> DNS requests
            # 'qd' is the query data flag, with a DNS Query Record, with domain name google.com. By defualt it will have 'qtype' is A
            DNS(rd=1, qd=DNSQR(qname="google.com")))

        response = sr1(packet, timeout=2, verbose=0)
        # answered, _ = sr(packet, timeout=1, verbose=0)
        """checks if UDP data is inside the response, not very accurate as it can still give false positive if the server sends back any UDP data. It needs to check if its a DNS response aswell"""
        # if response and UDP in response:
        #     print(f"{self.host} is a DNS Server")
        # else:
        #     print(f"No DNS server found on {self.host}")
        """
        so this is better:
        - Unlike TCP where we recieve a RST (reset) = true packet, in UDP if the request does not go through the dest will send a ICMP Type 3 Code 3 (Port Unreachable)
            response, unless filitered
        """
        # makes sure we actually get a response, we will recieve someting if it fails (ICMP) or goes through
        if response:
            # original DNS query is embedded in the ICMP error message if it fails
            if response.haslayer(ICMP):
                icmp_layer = response[ICMP]
                if icmp_layer.type == 3 and icmp_layer.code == 3:
                    print(
                        f"No DNS server found on {self.host} (port unreachable)"
                    )
            elif response.haslayer(DNS):
                dns_layer = response[DNS]
                # make sure that its a valid DNS response (no errors)
                if dns_layer.qr == 1 and dns_layer.rcode == 0:
                    print(f"{self.host} is a DNS Server")
            else:
                print(f"No DNS server found on {self.host}")
        else:
            # if response was empty (likely no ICMP) packet sent from host
            print(f"No DNS server found on {self.host}")


# while True:
#     ip_target_input = input("Enter ip: ")
#     try:
#         ip_target = ipaddress.ip_address(ip_target_input)
#         break
#     except ValueError:
#         print("Please enter valid IP address")

# x = Setup("8.8.8.8")
x = Setup("10.0.0.192")

# x = Setup("10.0.0.1")
x.syn_scan()
# x.dns_scan()
