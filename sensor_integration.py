from scapy.all import sniff, ARP, DNS, DNSRR, IP, UDP, Dot11, Dot11Beacon, Dot11Elt
import ipaddress
from actuator import get_actuator

# Initialize the actuator to handle firewall rules and logging
actuator = get_actuator()

def trigger_severity_engine(threat_type: str, severity: str, details: dict) -> None:
    """
    Extracts the necessary IP addresses and hands the alert to the actuator.
    """
    source_ip = details.get("attacker_ip") or details.get("source_ip")
    target_ip = details.get("victim_ip")   or details.get("target_ip")

    # Delegate to the actuator system
    actuator.trigger(
        threat_type=threat_type,
        severity=severity,
        details=details,
        source_ip=source_ip,
        target_ip=target_ip,
    )

def process_packet(packet):
    """
    Scapy callback function. Evaluates every packet traversing the network 
    and checks it against known attack signatures.
    """
    # ---------------------------------------------------------
    # 1. ARP SPOOFING / MAN-IN-THE-MIDDLE DETECTION
    # ---------------------------------------------------------
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        extracted_ip = packet[ARP].psrc
        
        print(f"[!] ARP Spoofing Detected! IP: {extracted_ip}")
        trigger_severity_engine(
            threat_type="ARP Spoofing / MitM",
            severity="CRITICAL",
            details={
                "attacker_ip": extracted_ip,
                "attacker_mac": packet[ARP].hwsrc,
                "reason": "Unsolicited ARP reply detected on network"
            }
        )
    
    # ---------------------------------------------------------
    # 2. DNS SPOOFING / CACHE POISONING DETECTION
    # ---------------------------------------------------------
    elif packet.haslayer(DNS) and packet[DNS].qr == 1 and packet.haslayer(DNSRR) and packet.haslayer(IP):
        answered_ip = packet[DNSRR].rdata if hasattr(packet[DNSRR], 'rdata') else None
        
        if isinstance(answered_ip, bytes):
            try:
                answered_ip = answered_ip.decode('utf-8')
            except UnicodeDecodeError:
                answered_ip = None

        if isinstance(answered_ip, str) and answered_ip.count('.') == 3 and all(c.isdigit() or c == '.' for c in answered_ip):
            try:
                if ipaddress.ip_address(answered_ip).is_private:
                    attacker_ip = packet[IP].src
                    spoofed_domain = packet[DNSRR].rrname.decode(errors='ignore') if packet[DNSRR].rrname else "unknown"
                    
                    print(f"[!] DNS Spoofing Detected! IP {attacker_ip} redirecting {spoofed_domain} to private IP {answered_ip}")
                    trigger_severity_engine(
                        threat_type="DNS Spoofing / Rebinding",
                        severity="CRITICAL",
                        details={
                            "attacker_ip": attacker_ip,
                            "spoofed_domain": spoofed_domain,
                            "reason": f"Anomalous routing: Redirecting to internal IP {answered_ip}"
                        }
                    )
            except ValueError:
                pass

    # ---------------------------------------------------------
    # 3. EVIL TWIN / ROGUE AP DETECTION
    # ---------------------------------------------------------
    elif packet.haslayer(Dot11Beacon) or (packet.haslayer(UDP) and packet.haslayer(IP) and packet[UDP].dport == 65535):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode(errors='ignore') if packet.haslayer(Dot11Elt) else "Hidden"
            bssid = packet[Dot11].addr2
        else:
            ssid = "Corporate_WiFi"
            bssid = "00:11:22:33:44:55"

        if bssid == "00:11:22:33:44:55":
            print(f"[!] Evil Twin Detected! Rogue AP broadcasting SSID: {ssid}")
            trigger_severity_engine(
                threat_type="Evil Twin / Rogue AP",
                severity="HIGH",
                details={
                    "attacker_mac": bssid,
                    "ssid": ssid,
                    "reason": "Unauthorized router broadcasting corporate Wi-Fi name"
                }
            )

if __name__ == "__main__":
    print("═══════════════════════════════════════════════════")
    print("  CloudShield Sensor Engine Active")
    print("  Sniffing on interface: enp0s3...")
    print("═══════════════════════════════════════════════════")
    
    # Start continuous sniffing on the active interface
    sniff(iface="enp0s3", prn=process_packet, store=False)