import socket
import subprocess
import scapy.all as scapy
import ipaddress

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_packet = ether / arp_request
    answered_list = scapy.srp(arp_request_packet, timeout=1, verbose=False)[0]

    hosts_list = []
    for element in answered_list:
        host_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        hosts_list.append(host_dict)
    return hosts_list

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def main():
    # Discover hosts on the local network (ARP scan)
    network_range = "10.165.10.0/24"
    discovered_hosts = scan(network_range)

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
