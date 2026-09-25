#!/usr/bin/env python3
"""PCAP Packet Filter

Filter packets from a pcap file and write matching packets to a new file.
Supports filtering by IP, port, protocol, and more.

Usage:
    python tools/filter.py <input.pcap> <output.pcap> --src-ip 192.168.1.1
    python tools/filter.py <input.pcap> <output.pcap> --dst-port 443
    python tools/filter.py <input.pcap> <output.pcap> --protocol tcp
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from scapy.all import rdpcap, wrpcap, IP, TCP, UDP, ICMP
except ImportError:
    print("Error: scapy not installed. Run: pip install scapy")
    sys.exit(1)


def filter_packets(input_file, output_file, filters):
    """Filter packets and write to output file."""
    print(f"Reading {input_file}...")
    
    try:
        packets = rdpcap(input_file)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    
    print(f"Total packets: {len(packets)}")
    
    filtered = []
    for pkt in packets:
        if matches_filters(pkt, filters):
            filtered.append(pkt)
    
    print(f"Matching packets: {len(filtered)}")
    
    if filtered:
        wrpcap(output_file, filtered)
        print(f"Written to {output_file}")
    else:
        print("No matching packets found.")


def matches_filters(pkt, filters):
    """Check if packet matches all filter criteria."""
    # IP layer filters
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
        
        if 'src_ip' in filters and ip_layer.src != filters['src_ip']:
            return False
        if 'dst_ip' in filters and ip_layer.dst != filters['dst_ip']:
            return False
        if 'ip' in filters and ip_layer.src != filters['ip'] and ip_layer.dst != filters['ip']:
            return False
        
        # TCP/UDP port filters
        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            
            if 'protocol' in filters and filters['protocol'] != 'tcp':
                return False
            
            if 'src_port' in filters and tcp_layer.sport != filters['src_port']:
                return False
            if 'dst_port' in filters and tcp_layer.dport != filters['dst_port']:
                return False
            if 'port' in filters:
                if tcp_layer.sport != filters['port'] and tcp_layer.dport != filters['port']:
                    return False
        
        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            
            if 'protocol' in filters and filters['protocol'] != 'udp':
                return False
            
            if 'src_port' in filters and udp_layer.sport != filters['src_port']:
                return False
            if 'dst_port' in filters and udp_layer.dport != filters['dst_port']:
                return False
            if 'port' in filters:
                if udp_layer.sport != filters['port'] and udp_layer.dport != filters['port']:
                    return False
        
        elif pkt.haslayer(ICMP):
            if 'protocol' in filters and filters['protocol'] != 'icmp':
                return False
    else:
        # Non-IP packets
        if any(k in filters for k in ['src_ip', 'dst_ip', 'ip', 'port', 'src_port', 'dst_port']):
            return False
    
    return True


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python tools/filter.py <input.pcap> <output.pcap> [filters]")
        print("\nFilters:")
        print("  --src-ip IP       Source IP address")
        print("  --dst-ip IP       Destination IP address")
        print("  --ip IP           Either source or destination IP")
        print("  --port PORT       Either source or destination port")
        print("  --src-port PORT   Source port")
        print("  --dst-port PORT   Destination port")
        print("  --protocol PROTO  Protocol (tcp, udp, icmp)")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    filters = {}
    i = 3
    while i < len(sys.argv):
        if sys.argv[i] == '--src-ip' and i + 1 < len(sys.argv):
            filters['src_ip'] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--dst-ip' and i + 1 < len(sys.argv):
            filters['dst_ip'] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--ip' and i + 1 < len(sys.argv):
            filters['ip'] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--port' and i + 1 < len(sys.argv):
            filters['port'] = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '--src-port' and i + 1 < len(sys.argv):
            filters['src_port'] = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '--dst-port' and i + 1 < len(sys.argv):
            filters['dst_port'] = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '--protocol' and i + 1 < len(sys.argv):
            filters['protocol'] = sys.argv[i + 1].lower()
            i += 2
        else:
            print(f"Unknown argument: {sys.argv[i]}")
            i += 1
    
    filter_packets(input_file, output_file, filters)
