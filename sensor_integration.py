"""
CloudShield HIDS — sensor.py Integration Snippet
===================================================
Copy and paste the code below into your sensor/sniffer module.
It provides the `trigger_severity_engine()` bridge function that
connects your packet scanner to the actuator daemon.

Requirements:
  - actuator.py must be importable (same directory or on PYTHONPATH)
  - `pip install requests`  (dependency of actuator.py)
"""

from actuator import get_actuator

# ── Initialize once at module load ──────────────────────────────
# The actuator is a singleton — calling get_actuator() multiple times
# returns the same instance. The dispatcher daemon thread starts on
# the first call and runs for the lifetime of the process.
actuator = get_actuator()


# ═══════════════════════════════════════════════════════════════
# INTEGRATION FUNCTION — Paste this into sensor.py
# ═══════════════════════════════════════════════════════════════

def trigger_severity_engine(threat_type: str, severity: str, details: dict) -> None:
    """
    Bridge function — called by the packet sniffer when a threat is detected.

    This function is NON-BLOCKING. It performs exactly two operations:
      1. Appends the alert to a bounded memory queue (O(1), thread-safe).
      2. If severity is critical/high and an attacker IP is provided,
         spawns a daemon thread to execute the OS firewall block command.

    Returns immediately — zero impact on sniffing loop throughput.

    ──── Parameters ────────────────────────────────────────────

    threat_type : str
        Category of the detected threat. Examples:
          - "evil_twin"     — Rogue AP mimicking a legitimate SSID
          - "arp_spoof"     — ARP cache poisoning detected
          - "rogue_ap"      — Unauthorized access point
          - "deauth_flood"  — Deauthentication attack

    severity : str
        Threat severity level. Must be one of:
          - "critical"  → immediate firewall block + batch log
          - "high"      → immediate firewall block + batch log
          - "medium"    → batch log only (no firewall block)
          - "low"       → batch log only (no firewall block)

    details : dict
        Arbitrary key-value pairs with contextual forensic data.
        The following keys are RECOGNIZED and used by the actuator:
          - "attacker_ip"  → IP of the attacker (triggers firewall block)
          - "source_ip"    → fallback alias for attacker_ip
          - "victim_ip"    → IP of the victim (logged, not blocked)
          - "target_ip"    → fallback alias for victim_ip

        All other keys are passed through to the backend unchanged.
        Common examples:
          - "attacker_mac": "AA:BB:CC:DD:EE:FF"
          - "ssid": "EvilCorp-WiFi"
          - "bssid": "AA:BB:CC:DD:EE:FF"
          - "channel": 6
          - "rssi": -45
          - "packet_type": "Beacon"
          - "reason": "Duplicate BSSID detected on different channel"

    ──── Example Usage (from your sniffing loop) ────────────────

        # Inside your Scapy/Airodump-style packet callback:
        if is_arp_spoof(packet):
            trigger_severity_engine(
                threat_type="arp_spoof",
                severity="critical",
                details={
                    "attacker_ip": packet[ARP].psrc,
                    "attacker_mac": packet[ARP].hwsrc,
                    "victim_ip": packet[ARP].pdst,
                    "victim_mac": packet[ARP].hwdst,
                    "packet_summary": f"ARP reply: {packet[ARP].psrc} is at {packet[ARP].hwsrc}",
                },
            )

        if is_evil_twin(packet):
            trigger_severity_engine(
                threat_type="evil_twin",
                severity="high",
                details={
                    "attacker_mac": packet.addr2,
                    "ssid": packet.info,
                    "bssid": packet.addr3,
                    "channel": int(ord(packet[Dot11Elt:3].info)),
                    "rssi": packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else None,
                    "reason": "BSSID matches known AP but MAC differs",
                },
            )

    ──── Shutdown (optional, but recommended) ───────────────────

    Call `actuator.shutdown()` when your sensor exits to flush
    any remaining alerts and print final statistics:

        # At the end of your sensor script:
        actuator.shutdown()
    """
    # Extract IP addresses from the details dict for firewall targeting
    source_ip = details.get("attacker_ip") or details.get("source_ip")
    target_ip = details.get("victim_ip")   or details.get("target_ip")

    # Delegate to actuator (returns in O(1) — non-blocking)
    actuator.trigger(
        threat_type=threat_type,
        severity=severity,
        details=details,
        source_ip=source_ip,
        target_ip=target_ip,
    )
