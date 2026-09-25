#!/usr/bin/env python3
"""Batch PCAP Analysis

Processes multiple pcap files and generates a comprehensive comparison report.

Usage:
    python tools/batch_analysis.py <directory> [--output report.csv]
"""

import sys
import os
import glob
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, ARP
except ImportError:
    print("Error: scapy not installed. Run: pip install scapy")
    sys.exit(1)


def analyze_single_pcap(filepath):
    """Analyze a single pcap file and return metrics."""
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        return {'file': filepath, 'error': str(e)}
    
    if len(packets) == 0:
        return {'file': filepath, 'packets': 0}
    
    # Basic stats
    first_ts = float(packets[0].time)
    last_ts = float(packets[-1].time)
    duration = last_ts - first_ts
    
    # Protocol counts
    ip_count = 0
    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    dns_count = 0
    arp_count = 0
    
    # TCP error tracking - byte-based retransmission rate
    # Track total bytes sent vs retransmitted bytes per connection
    retransmissions = 0
    total_tcp_bytes = 0
    retransmitted_bytes = 0
    connection_state = {}  # (src, sport, dst, dport) -> highest_seq_seen
    
    for pkt in packets:
        if pkt.haslayer(IP):
            ip_count += 1
            
            if pkt.haslayer(TCP):
                tcp_count += 1
                conn_key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                seq = pkt[TCP].seq
                
                # Calculate payload length
                ip_len = pkt[IP].len
                ip_header_len = pkt[IP].ihl * 4
                tcp_header_len = pkt[TCP].dataofs * 4
                payload_len = max(0, ip_len - ip_header_len - tcp_header_len)
                
                total_tcp_bytes += payload_len
                
                if conn_key not in connection_state:
                    connection_state[conn_key] = seq + payload_len
                else:
                    # If this packet doesn't advance the sequence space, it's a retransmission
                    if seq + payload_len <= connection_state[conn_key]:
                        retransmissions += 1
                        retransmitted_bytes += payload_len
                    else:
                        connection_state[conn_key] = seq + payload_len
            
            elif pkt.haslayer(UDP):
                udp_count += 1
                if pkt.haslayer(DNS):
                    dns_count += 1
            
            elif pkt.haslayer(ICMP):
                icmp_count += 1
        
        elif pkt.haslayer(ARP):
            arp_count += 1
    
    return {
        'file': os.path.basename(filepath),
        'path': filepath,
        'packets': len(packets),
        'duration': duration,
        'start_time': datetime.fromtimestamp(first_ts).isoformat(),
        'end_time': datetime.fromtimestamp(last_ts).isoformat(),
        'pps': len(packets) / duration if duration > 0 else 0,
        'ip_packets': ip_count,
        'tcp_packets': tcp_count,
        'udp_packets': udp_count,
        'icmp_packets': icmp_count,
        'dns_packets': dns_count,
        'arp_packets': arp_count,
        'retransmissions': retransmissions,
        'retransmission_rate': (retransmissions / tcp_count * 100) if tcp_count > 0 else 0,
        'total_tcp_bytes': total_tcp_bytes,
        'retransmitted_bytes': retransmitted_bytes,
        'byte_retransmission_rate': (retransmitted_bytes / total_tcp_bytes * 100) if total_tcp_bytes > 0 else 0
    }


def generate_report(results):
    """Generate a comprehensive comparison report."""
    print("\n" + "=" * 80)
    print("BATCH PCAP ANALYSIS REPORT")
    print("=" * 80)
    
    # Sort by filename for consistent output
    results.sort(key=lambda x: x['file'])
    
    # Summary table
    print(f"\n{'File':<50} {'Packets':>8} {'Duration':>10} {'PPS':>7} {'Retrans':>8}")
    print("-" * 93)
    
    total_packets = 0
    total_retrans = 0
    
    for r in results:
        if 'error' in r:
            print(f"{r['file']:<50} ERROR: {r['error']}")
            continue
        
        if 'duration' not in r or r.get('packets', 0) == 0:
            print(f"{r['file']:<50} No data")
            continue
        
        duration_str = f"{r['duration']:.1f}s"
        retrans_str = f"{r['retransmissions']:>8}"
        
        print(f"{r['file']:<50} {r['packets']:>8,} {duration_str:>10} "
              f"{r['pps']:>7.1f} {retrans_str}")
        
        total_packets += r['packets']
        total_retrans += r['retransmissions']
    
    print("-" * 93)
    print(f"{'TOTAL':<50} {total_packets:>8,} {'':>10} {'':>7} {total_retrans:>8}")
    
    # Detailed analysis by category
    print("\n\nDetailed Analysis:")
    print("=" * 80)
    
    # Group by AP/interface type
    wireless_files = [r for r in results if 'wireless' in r['file'].lower()]
    wired_files = [r for r in results if 'wired' in r['file'].lower() and 'wireless' not in r['file'].lower()]
    switch_files = [r for r in results if 'switch' in r['file'].lower()]
    
    print(f"\nWireless Captures: {len(wireless_files)}")
    print(f"Wired Captures: {len(wired_files)}")
    print(f"Switch Captures: {len(switch_files)}")
    
    # Analyze wireless vs wired retransmission rates
    if wireless_files and wired_files:
        avg_wireless_pkt = sum(r['retransmission_rate'] for r in wireless_files) / len(wireless_files)
        avg_wired_pkt = sum(r['retransmission_rate'] for r in wired_files) / len(wired_files)
        
        avg_wireless_byte = sum(r['byte_retransmission_rate'] for r in wireless_files) / len(wireless_files)
        avg_wired_byte = sum(r['byte_retransmission_rate'] for r in wired_files) / len(wired_files)
        
        print(f"\nAverage Packet Retransmission Rate:")
        print(f"  Wireless: {avg_wireless_pkt:.2f}%")
        print(f"  Wired:    {avg_wired_pkt:.2f}%")
        print(f"  Difference: {avg_wireless_pkt - avg_wired_pkt:.2f} percentage points")
        
        print(f"\nAverage Byte Retransmission Rate:")
        print(f"  Wireless: {avg_wireless_byte:.2f}%")
        print(f"  Wired:    {avg_wired_byte:.2f}%")
        print(f"  Difference: {avg_wireless_byte - avg_wired_byte:.2f} percentage points")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tools/batch_analysis.py <directory> [--output report.csv]")
        sys.exit(1)
    
    directory = sys.argv[1]
    
    # Find all pcap files
    pcap_files = glob.glob(os.path.join(directory, "*.pcap"))
    
    if not pcap_files:
        print(f"No .pcap files found in {directory}")
        sys.exit(1)
    
    print(f"Found {len(pcap_files)} PCAP files")
    print("Analyzing... (this may take a while)")
    
    results = []
    for i, filepath in enumerate(pcap_files):
        print(f"[{i+1}/{len(pcap_files)}] {os.path.basename(filepath)}")
        result = analyze_single_pcap(filepath)
        results.append(result)
    
    generate_report(results)
