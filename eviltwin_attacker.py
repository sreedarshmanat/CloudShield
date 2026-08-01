from scapy.all import Ether, IP, UDP, sendp

def launch_evil_twin_attack():
    # Construct a Layer 2 Ethernet frame carrying our Evil Twin signature
    packet = (
        Ether(dst="ff:ff:ff:ff:ff:ff") /
        IP(src="10.0.2.99", dst="10.0.2.15") /
        UDP(sport=1234, dport=65535)
    )

    print("[*] Broadcasting Layer 2 Evil Twin threat signature on enp0s3...")
    sendp(packet, iface="enp0s3", verbose=1)
    print("[+] Evil Twin threat transmission complete!")

if __name__ == "__main__":
    launch_evil_twin_attack()
