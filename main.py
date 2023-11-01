import socket
import subprocess
import ipaddress
import os

def scan(ip):
    # Create a list to store discovered hosts
    discovered_hosts = []

    # Run the ARP scan command using the 'arp -a' utility on Windows or 'arp -n' on Linux
    if os.name == 'nt':  # Check if the OS is Windows
        arp_command = "arp -a"
    else:  # Assume it's Linux or a Unix-like OS
        arp_command = "arp -n"

    try:
        arp_result = subprocess.check_output(arp_command, shell=True, universal_newlines=True)
        lines = arp_result.strip().split('\n')
        for line in lines[1:]:  # Skip the header line
            parts = line.split()
            if len(parts) >= 2:
                ip_address = parts[0]
                mac_address = parts[1]
                discovered_hosts.append({"ip": ip_address, "mac": mac_address})
    except subprocess.CalledProcessError:
        print("Error executing the ARP scan command. Make sure you have the necessary permissions.")

    return discovered_hosts

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "Unknown"

def main():
    # Discover hosts on the local network (ARP scan)
    discovered_hosts = scan("")

    # Resolve hostnames for discovered IP addresses
    hostname_map = {}
    for host in discovered_hosts:
        ip = host["ip"]
        hostname = resolve_hostname(ip)
        hostname_map[ip] = hostname

    # Display the results
    for host in discovered_hosts:
        ip = host["ip"]
        mac = host["mac"]
        hostname = hostname_map.get(ip, "Unknown")
        print(f"IP: {ip}\tMAC: {mac}\tHostname: {hostname}")

if __name__ == "__main__":
    main()
