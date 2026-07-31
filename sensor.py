import time
import threading
import requests
from scapy.all import getmacbyip, conf

# ==========================================
# CLOUDSHIELD NETWORK SENSOR (sensor.py)
# Job: Detect threats and print to stdout.
# ==========================================

# --- CONFIGURATION ---
ARP_CHECK_INTERVAL = 3  # How often to check the ARP cache (in seconds)
PORTAL_CHECK_INTERVAL = 10  # How often to ping neverssl.com (in seconds)
CAPTIVE_PORTAL_URL = "http://neverssl.com"

def get_default_gateway_ip():
    """
    Finds the default gateway IP address of the host machine.
    This is the router we want to monitor for ARP spoofing.
    """
    # scapy's conf.route object contains the local routing table.
    # route("0.0.0.0") asks for the route to the internet, 
    # and [2] grabs the gateway IP from that result.
    gateway_ip = conf.route.route("0.0.0.0")[2]
    return gateway_ip

def detect_arp_spoofing():
    """
    Background Thread 1: Monitors the local ARP cache.
    If the MAC address of the default gateway changes suddenly, 
    it means another device on the network is pretending to be the router.
    """
    gateway_ip = get_default_gateway_ip()
    
    # Get the legitimate MAC address of the gateway when the script starts
    # getmacbyip() checks the local OS ARP cache first before sending a request.
    original_mac = getmacbyip(gateway_ip)
    
    if not original_mac:
        print("[ERROR] Could not find the Gateway MAC address. Is your internet connected?")
        return

    print(f"[SENSOR] ARP Monitor Started. Watching Gateway: {gateway_ip} ({original_mac})")

    while True:
        time.sleep(ARP_CHECK_INTERVAL)
        
        # Check the cache again
        current_mac = getmacbyip(gateway_ip)
        
        # If the MAC is not None (meaning the gateway is reachable) AND it doesn't match the original...
        if current_mac and current_mac.lower() != original_mac.lower():
            # PRINT THE ALERT FOR YOUR TEAMMATE'S SCRIPT TO CATCH
            print("\n" + "="*60)
            print("[CRITICAL THREAT] ARP SPOOFING DETECTED!")
            print(f"Gateway IP: {gateway_ip}")
            print(f"Original MAC: {original_mac}")
            print(f"Fake MAC:     {current_mac}")
            print("WARNING: Another device is intercepting your traffic!")
            print("="*60 + "\n")
            
            # Note: We do NOT fix it here. We just detect and print. 
            # We reset the original_mac to the new one so we don't spam the terminal 
            # with the same alert every 3 seconds.
            original_mac = current_mac

def detect_captive_portal():
    """
    Background Thread 2: Pings a website that explicitly does NOT use SSL/HTTPS.
    Public WiFi networks use "Captive Portals" to intercept HTTP traffic and 
    force you to a login page. They usually do this by sending an HTTP 302 Redirect.
    """
    print(f"[SENSOR] Captive Portal Monitor Started. Pinging {CAPTIVE_PORTAL_URL} every {PORTAL_CHECK_INTERVAL}s.")

    while True:
        time.sleep(PORTAL_CHECK_INTERVAL)
        
        try:
            # allow_redirects=False is CRUCIAL here. 
            # If we set it to True, requests would automatically follow the 302 redirect 
            # to the login page, and we would never see the 302 status code ourselves.
            response = requests.get(CAPTIVE_PORTAL_URL, timeout=5, allow_redirects=False)
            
            # A normal connection to neverssl.com returns a 200 OK.
            # An intercepted connection returns a 302 Found (Redirect).
            if response.status_code == 302:
                # PRINT THE ALERT FOR YOUR TEAMMATE'S SCRIPT TO CATCH
                print("\n" + "="*60)
                print("[CRITICAL THREAT] CAPTIVE PORTAL DETECTED!")
                print(f"Expected: HTTP 200 OK from {CAPTIVE_PORTAL_URL}")
                print(f"Received: HTTP 302 Redirect to {response.headers.get('Location', 'Unknown URL')}")
                print("WARNING: Your connection is being intercepted by a WiFi login page!")
                print("="*60 + "\n")
                
        except requests.exceptions.RequestException as e:
            # If there is no internet at all, we just ignore it. 
            # We only care about the specific 302 interception threat.
            pass

if __name__ == "__main__":
    print("Starting CloudShield Network Sensor...")
    
    # Create Thread 1 for ARP Spoofing
    # daemon=True ensures these threads automatically die if the main script is stopped (Ctrl+C)
    arp_thread = threading.Thread(target=detect_arp_spoofing, daemon=True)
    arp_thread.start()
    
    # Create Thread 2 for Captive Portals
    portal_thread = threading.Thread(target=detect_captive_portal, daemon=True)
    portal_thread.start()
    
    # The main thread needs to stay alive to keep the background threads running.
    # We just put it to sleep infinitely.
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[SENSOR] CloudShield Sensor Shutting Down.")