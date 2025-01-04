from scapy.all import sniff, IP, ICMP, TCP
import datetime
import logging
import socket

logging.basicConfig(filename='Listing.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"\033[91mError: Cannot retrieve local IP address ........ {e}\033[0m")
        exit(1)

def get_network_prefix(ip):
    return ".".join(ip.split(".")[:3]) + "."

def detect_tool(packet):
    if ICMP in packet:
        return "Ping (ICMP)"
    elif TCP in packet:
        flags = packet[TCP].flags
        if flags == 0x12:  
            return "Nmap (SYN Scan)"
        elif flags == 0x02:  
            return "Nmap (SYN Scan)"
        elif flags == 0x04:  
            return "Nmap (RST Scan)"
        elif flags == 0x18:  
            return "Nmap (PSH Scan)"
        else:
            return " TCP Scan"
    return "Unknown Tool"

def log_event(event_message):
    logging.info(event_message)
    print(f"\033[94m{event_message}\033[0m")  

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if dst_ip == YOUR_IP and src_ip.startswith(NETWORK_PREFIX):
            tool_used = detect_tool(packet)
            if ICMP in packet:
                log_event(f"Ping to scan ip is >  {src_ip} to {dst_ip} - Tool: {tool_used}")

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                log_event(f"Port scan and ip >  {src_ip}:{src_port} to {dst_ip}:{dst_port} - Tool: {tool_used}")

YOUR_IP = get_local_ip()
NETWORK_PREFIX = get_network_prefix(YOUR_IP)
print(f"\033[92mNetwork  IP >  {YOUR_IP}\033[0m")
print("\033[93mThis script was developed by Professor Joker Dark.\033[0m")
print("\033[93mTelegram channel > @supersecu\033[0m")
try:
    sniff(prn=packet_callback, filter=f"ip dst {YOUR_IP}", store=0)
except Exception as e:
    print(f"\033[91mError: True the sniff........ {e}\033[0m")
