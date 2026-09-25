#!/usr/bin/env python3
"""PCAP File Info & Summary Statistics

Provides basic information about a pcap file including packet count,
duration, and protocol distribution.

Usage:
    python tools/pcap_info.py <file.pcap> [--json]
"""

import sys
import os
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, ARP
    try:
        from scapy.layers.http import HTTP
    except ImportError:
        # Older scapy versions have HTTP in scapy.all
        from scapy.all import HTTP
except ImportError:
    print("Error: scapy not installed. Run: pip install scapy")
    sys.exit(1)


def analyze_pcap(filepath):
    """Analyze pcap file and return summary statistics."""
    print(f"Reading {filepath}...")
    
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    
    total_packets = len(packets)
    if total_packets == 0:
        print("No packets found in file.")
        return
    
    # Calculate duration
    first_ts = float(packets[0].time)
    last_ts = float(packets[-1].time)
    duration = last_ts - first_ts
    
    # Protocol counters
    proto_counts = {
        'IP': 0, 'TCP': 0, 'UDP': 0, 'ICMP': 0, 
        'DNS': 0, 'HTTP': 0, 'ARP': 0, 'Other': 0
    }
    
    # IP address tracking
    ip_addresses = set()
    
    for pkt in packets:
        if pkt.haslayer(IP):
            proto_counts['IP'] += 1
            ip_addresses.add(pkt[IP].src)
            ip_addresses.add(pkt[IP].dst)
            
            if pkt.haslayer(TCP):
                proto_counts['TCP'] += 1
            elif pkt.haslayer(UDP):
                proto_counts['UDP'] += 1
                if pkt.haslayer(DNS):
                    proto_counts['DNS'] += 1
            elif pkt.haslayer(ICMP):
                proto_counts['ICMP'] += 1
            
            if pkt.haslayer(HTTP):
                proto_counts['HTTP'] += 1
        elif pkt.haslayer(ARP):
            proto_counts['ARP'] += 1
        else:
            proto_counts['Other'] += 1
    
    # Calculate rates
    pps = total_packets / duration if duration > 0 else 0
    
    return {
        'file': filepath,
        'total_packets': total_packets,
        'duration_seconds': duration,
        'start_time': datetime.fromtimestamp(first_ts).isoformat(),
        'end_time': datetime.fromtimestamp(last_ts).isoformat(),
        'packets_per_second': pps,
        'unique_ip_addresses': len(ip_addresses),
        'protocol_counts': proto_counts
    }


def print_summary(stats):
    """Print formatted summary."""
    print("\n" + "=" * 60)
    print("PCAP FILE SUMMARY")
    print("=" * 60)
    print(f"File:              {stats['file']}")
    print(f"Packets:           {stats['total_packets']:,}")
    print(f"Duration:          {stats['duration_seconds']:.2f} seconds")
    print(f"Start Time:        {stats['start_time']}")
    print(f"End Time:          {stats['end_time']}")
    print(f"Packets/sec:       {stats['packets_per_second']:.1f}")
    print(f"Unique IPs:        {stats['unique_ip_addresses']}")
    
    print("\nProtocol Distribution:")
    print("-" * 40)
    for proto, count in stats['protocol_counts'].items():
        if count > 0:
            pct = (count / stats['total_packets']) * 100
            bar = "█" * int(pct / 2)
            print(f"  {proto:<6} {count:>8,} ({pct:5.1f}%) {bar}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tools/pcap_info.py <file.pcap> [--json]")
        sys.exit(1)
    
    filepath = sys.argv[1]
    output_json = "--json" in sys.argv
    
    stats = analyze_pcap(filepath)
    
    if output_json:
        import json
        print(json.dumps(stats, indent=2))
    else:
        print_summary(stats)
