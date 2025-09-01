# #################################################################
#                  WiFi Deep Scanner Tool
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

#!/usr/bin/env python3
import subprocess
import threading
import ipaddress
import re
import os
import sys
import time
from termcolor import colored

def ping_ip(ip):
    try:
        subprocess.run(["ping", "-c", "1", "-W", "1", str(ip)], 
                         check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def get_default_gateway_info():
    try:
        result = subprocess.check_output("ip route | grep default", shell=True).decode()
        parts = result.split()
        gateway_ip = parts[2]
        return gateway_ip
    except Exception:
        return None

def spinner_animation(stop_event, text):
    dot_sequence = ['.  ', '.. ', '...']
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(colored(f'\r{text}{dot_sequence[i]}', 'yellow'))
        sys.stdout.flush()
        time.sleep(0.4)
        i = (i + 1) % len(dot_sequence)
    sys.stdout.write('\r' + ' ' * (len(text) + 5) + '\r')
    sys.stdout.flush()

def perform_deep_scan(network):
    threads = []
    active_hosts = []
    
    stop_spinner = threading.Event()
    spinner_thread = threading.Thread(target=spinner_animation, args=(stop_spinner, "[*] Sweeping network with pings"))
    spinner_thread.start()

    def thread_target(ip):
        if ping_ip(ip):
            active_hosts.append(ip)

    for ip in network.hosts():
        thread = threading.Thread(target=thread_target, args=(ip,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    stop_spinner.set()
    spinner_thread.join()

    print(colored(f"[*] Ping sweep completed. {len(active_hosts)} active hosts found.", 'green'))
    print(colored("[*] Querying system ARP table for MAC addresses...", 'yellow'))
    try:
        arp_result = subprocess.check_output(["arp", "-n"]).decode()
        found_devices = {}
        for line in arp_result.splitlines():
            match = re.search(r"^(\d+\.\d+\.\d+\.\d+)\s+\w+\s+([\da-fA-F:]+)", line)
            if match:
                ip_addr = match.group(1)
                mac_addr = match.group(2)
                if mac_addr != "(incomplete)" and mac_addr != "00:00:00:00:00:00":
                    found_devices[ip_addr] = mac_addr
        return found_devices
    except Exception as e:
        print(colored(f"[!] An error occurred while reading the ARP table: {e}", 'red'))
        return {}

def print_scan_results(devices):
    print(colored("\n--- Found Devices ---", 'cyan', attrs=['bold']))
    print(colored("-----------------------------------------", 'cyan'))
    print(colored("IP Address\t\tMAC Address", 'cyan'))
    print(colored("-----------------------------------------", 'cyan'))
    if not devices:
        print("No devices found.")
    else:
        for ip, mac in devices.items():
            print(f"{ip}\t\t{mac}")
    print(colored("-----------------------------------------", 'cyan'))
    print(colored(f"[*] Found {len(devices)} unique devices.", 'yellow'))

def get_mac_vendor(mac):
    if not mac:
        return "Unknown"
    print(colored(f"[*] Querying vendor for MAC {mac}...", 'yellow'))
    try:
        url = f"https://api.macvendors.com/{mac}"
        vendor = subprocess.check_output(["curl", "-s", url]).decode()
        return colored(vendor, 'green') if vendor else "Vendor not found"
    except Exception:
        return colored("Could not contact the vendor API", 'red')

def profile_device(ip, mac):
    vendor = get_mac_vendor(mac)
    print(colored("\n--- Device Profile ---", 'cyan', attrs=['bold']))
    print(f"  IP Address:\t\t{ip}")
    print(f"  MAC Address:\t{mac}")
    print(f"  Vendor:\t{vendor}")
    print(colored("------------------------------", 'cyan'))
    
    print(colored(f"\n[*] Launching aggressive Nmap scan against {ip}... This may take several minutes.", 'yellow'))
    print(colored(f"[*] Command: sudo nmap -A -T4 -Pn {ip}", 'yellow'))
    print(colored("--------------------------------------------------------------------------------", 'cyan'))
    try:
        subprocess.run(["sudo", "nmap", "-A", "-T4", "-Pn", ip], check=True)
    except FileNotFoundError:
        print(colored("[!] ERROR: 'nmap' command not found. Make sure it is installed (e.g., sudo apt-get install nmap or sudo pacman -S nmap)", 'red'))
    except subprocess.CalledProcessError as e:
        print(colored(f"[!] Nmap finished with an error: {e}", 'red'))
    print(colored("--------------------------------------------------------------------------------", 'cyan'))
    print(colored(f"[*] Profiling of {ip} finished.", 'green'))

def show_menu():
    print(colored("\n--- Network Audit Menu ---", 'cyan', attrs=['bold']))
    print("1. Scan the network again")
    print("2. Profile a device (MAC Vendor + Nmap Scan)")
    print("3. Exit")
    print(colored("----------------------------------", 'cyan'))

def main():
    try:
        subprocess.run(["nmap", "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (FileNotFoundError, subprocess.CalledProcessError):
        print(colored("[!] WARNING: Nmap is not installed or not working correctly.", 'red'))
        print(colored("[*] For device profiling (option 2), please install it.", 'yellow'))

    gateway = get_default_gateway_info()
    if not gateway:
        print(colored("[!] Could not determine the network. Exiting.", 'red'))
        return

    os.system('clear')
    network = ipaddress.ip_network(f"{gateway.rsplit('.', 1)[0]}.0/24")
    found_devices = perform_deep_scan(network)
    print_scan_results(found_devices)

    try:
        while True:
            show_menu()
            choice = input(colored("Select an option: ", 'blue')).strip()
            
            if choice == '1':
                os.system('clear')
                found_devices = perform_deep_scan(network)
                print_scan_results(found_devices)
            elif choice == '2':
                print()
                target_input = input(colored("Enter the IP or MAC of the device to profile: ", 'blue')).strip()

                target_ip = None
                target_mac = None

                if target_input in found_devices:
                    target_ip = target_input
                    target_mac = found_devices[target_ip]
                elif target_input in found_devices.values():
                    target_mac = target_input
                    for ip, mac in found_devices.items():
                        if mac == target_mac:
                            target_ip = ip
                            break
                
                os.system('clear')
                if target_ip and target_mac:
                    profile_device(target_ip, target_mac)
                else:
                    print(colored(f"[!] The entered IP or MAC ('{target_input}') was not found in the list of scanned devices.", 'red'))
                    print_scan_results(found_devices)

            elif choice == '3':
                print(colored("[*] Exiting...", 'yellow'))
                sys.exit(0)
            else:
                os.system('clear')
                print(colored(f"[!] Invalid option: '{choice}'", 'red'))
                print_scan_results(found_devices)
    except KeyboardInterrupt:
        print(colored("\n[*] Ctrl+C detected. Exiting gracefully...", 'yellow'))
        sys.exit(0)

if __name__ == "__main__":
    main()
