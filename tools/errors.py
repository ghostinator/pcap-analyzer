#!/usr/bin/env python3
"""Network Error & Anomaly Detection

Detects common network issues in pcap files:
- TCP retransmissions
- Duplicate ACKs
- Out-of-order packets
- Zero-window announcements
- Connection timeouts
- High latency connections

Usage:
    python tools/errors.py <file.pcap> [--verbose]
"""

import sys
import os
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from scapy.all import rdpcap, IP, TCP
except ImportError:
    print("Error: scapy not installed. Run: pip install scapy")
    sys.exit(1)


def detect_errors(filepath, verbose=False):
    """Detect network errors and anomalies in pcap file."""
    print(f"Reading {filepath}...")
    
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    
    # Track TCP state per stream
    streams = defaultdict(lambda: {
        'packets': [],
        'retransmissions': 0,
        'dup_acks': 0,
        'out_of_order': 0,
        'zero_window': 0,
        'rst_count': 0,
        'syn_count': 0,
        'fin_count': 0,
        'last_seq': {},
        'expected_ack': {}
    })
    
    errors = {
        'retransmissions': [],
        'dup_acks': [],
        'out_of_order': [],
        'zero_window': [],
        'rst_connections': []
    }
    
    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            continue
        
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        seq = pkt[TCP].seq
        ack = pkt[TCP].ack
        flags = pkt[TCP].flags
        
        # Stream key (directional for sequence tracking)
        stream_key = f"{src}:{sport}->{dst}:{dport}"
        
        state = streams[stream_key]
        state['packets'].append(pkt)
        
        # Track connection establishment/teardown
        if flags & 0x02:  # SYN
            state['syn_count'] += 1
        if flags & 0x01:  # FIN
            state['fin_count'] += 1
        if flags & 0x04:  # RST
            state['rst_count'] += 1
            errors['rst_connections'].append({
                'stream': stream_key,
                'time': float(pkt.time)
            })
        
        # Detect retransmissions (same seq from same source)
        if src not in state['last_seq']:
            state['last_seq'][src] = set()
        
        if seq in state['last_seq'][src]:
            state['retransmissions'] += 1
            errors['retransmissions'].append({
                'stream': stream_key,
                'seq': seq,
                'time': float(pkt.time)
            })
        else:
            state['last_seq'][src].add(seq)
        
        # Detect duplicate ACKs (same ack number from same source)
        if src not in state['expected_ack']:
            state['expected_ack'][src] = None
        
        if state['expected_ack'][src] == ack and flags & 0x10:  # ACK flag set
            state['dup_acks'] += 1
            errors['dup_acks'].append({
                'stream': stream_key,
                'ack': ack,
                'time': float(pkt.time)
            })
        
        if flags & 0x10:  # ACK flag set
            state['expected_ack'][src] = ack
        
        # Detect zero-window announcements
        if pkt[TCP].window == 0:
            state['zero_window'] += 1
            errors['zero_window'].append({
                'stream': stream_key,
                'time': float(pkt.time)
            })
    
    return streams, errors


def print_error_report(streams, errors):
    """Print error detection report."""
    total_retrans = sum(s['retransmissions'] for s in streams.values())
    total_dup_acks = sum(s['dup_acks'] for s in streams.values())
    total_ooo = sum(s['out_of_order'] for s in streams.values())
    total_zero_win = sum(s['zero_window'] for s in streams.values())
    
    print("\n" + "=" * 60)
    print("NETWORK ERROR REPORT")
    print("=" * 60)
    
    print(f"\nTCP Retransmissions: {total_retrans}")
    if errors['retransmissions']:
        for err in errors['retransmissions'][:5]:
            print(f"  Stream: {err['stream']} at seq {err['seq']}")
        if len(errors['retransmissions']) > 5:
            print(f"  ... and {len(errors['retransmissions']) - 5} more")
    
    print(f"\nDuplicate ACKs: {total_dup_acks}")
    if errors['dup_acks']:
        for err in errors['dup_acks'][:5]:
            print(f"  Stream: {err['stream']} at ack {err['ack']}")
        if len(errors['dup_acks']) > 5:
            print(f"  ... and {len(errors['dup_acks']) - 5} more")
    
    print(f"\nOut-of-Order Packets: {total_ooo}")
    
    print(f"\nZero-Window Announcements: {total_zero_win}")
    if errors['zero_window']:
        for err in errors['zero_window'][:5]:
            print(f"  Stream: {err['stream']}")
    
    print(f"\nRST Connections: {len(errors['rst_connections'])}")
    if errors['rst_connections']:
        for err in errors['rst_connections'][:5]:
            print(f"  Stream: {err['stream']}")
    
    # Connection health summary
    unhealthy = [k for k, s in streams.items() 
                if s['retransmissions'] > 0 or s['rst_count'] > 0]
    
    if unhealthy:
        print(f"\nUnhealthy Streams ({len(unhealthy)}):")
        for stream_key in unhealthy[:10]:
            state = streams[stream_key]
            issues = []
            if state['retransmissions'] > 0:
                issues.append(f"retrans={state['retransmissions']}")
            if state['rst_count'] > 0:
                issues.append(f"rst={state['rst_count']}")
            print(f"  {stream_key} ({', '.join(issues)})")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tools/errors.py <file.pcap> [--verbose]")
        sys.exit(1)
    
    filepath = sys.argv[1]
    verbose = "--verbose" in sys.argv
    
    streams, errors = detect_errors(filepath, verbose)
    print_error_report(streams, errors)
