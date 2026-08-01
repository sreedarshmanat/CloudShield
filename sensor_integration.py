"""
CloudShield HIDS — Master Sensor Integration
===================================================
Listens to the network interface, detects threats, and 
triggers the actuator for logging and firewall defense.
"""

from scapy.all import sniff, ARP
from actuator import get_actuator

# ── Initialize once at module load ──────────────────────────────
actuator = get_actuator()

# ═══════════════════════════════════════════════════════════════
# 1. INTEGRATION BRIDGE
# ═══════════════════════════════════════════════════════════════
def trigger_severity_engine(threat_type: str, severity: str, details: dict) -> None:
    # This extracts the IPs from the details dictionary
    source_ip = details.get("attacker_ip") or details.get("source_ip")
    target_ip = details.get("victim_ip")   or details.get("target_ip")

    # -------------------------------------------------------------
    # ADD THIS LINE:
    print(f"[*] BRIDGE DIAGNOSTIC -> severity: '{severity}', source_ip: '{source_ip}'")
    # -------------------------------------------------------------

    # Delegate to actuator
    actuator.trigger(
        threat_type=threat_type,
        severity=severity,
        details=details,
        source_ip=source_ip,
        target_ip=target_ip,
    )
# ═══════════════════════════════════════════════════════════════
# 2. PACKET ANALYSIS ENGINE
# ═══════════════════════════════════════════════════════════════
def process_packet(packet):
    # Looking specifically for our simulated ARP reply (op=2)
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        extracted_ip = packet[ARP].psrc
        
        print(f"[!] Suspicious ARP Reply Detected! MAC: {packet[ARP].hwsrc}")
        print(f"[*] DEBUG -> Sending to Actuator | IP: '{extracted_ip}' | Severity: 'critical'")
        
        # Trigger the lockdown dynamically
        trigger_severity_engine(
            threat_type="ARP Spoofing / MitM",
            severity="critical",
            details={
                "attacker_ip": extracted_ip,
                "attacker_mac": packet[ARP].hwsrc,
                "victim_ip": packet[ARP].pdst,
                "reason": "Unsolicited ARP reply detected on network"
            }
        )
# ═══════════════════════════════════════════════════════════════
# 3. MAIN LISTENER LOOP
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("===================================================")
    print(" CloudShield Sensor Active")
    print(" Listening on interface: lo (Loopback/Demo Mode)")
    print("===================================================")
    
    try:
        # sniff() is the core Scapy function. 
        # It runs endlessly, passing every packet to process_packet.
        sniff(iface="lo", prn=process_packet, store=False)
        
    except KeyboardInterrupt:
        print("\n[!] Sensor shutting down...")
        actuator.shutdown()