#!/usr/bin/env python3
"""TCP Stream Reassembly

Reassembles TCP stream data and outputs the payload content.
Useful for debugging application protocols, API calls, etc.

Usage:
    python tools/stream_reassemble.py <file.pcap> --ip 192.168.1.1 [--port 443]
    python tools/stream_reassemble.py <file.pcap> --src-ip 10.0.0.1 --dst-ip 10.0.0.2
"""

import sys
import os
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from scapy.all import rdpcap, IP, TCP, Raw
except ImportError:
    print("Error: scapy not installed. Run: pip install scapy")
    sys.exit(1)


def reassemble_stream(filepath, filters):
    """Reassemble TCP stream data."""
    print(f"Reading {filepath}...")
    
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    
    # Collect all TCP segments for matching streams
    stream_data = defaultdict(lambda: {'forward': [], 'reverse': []})
    
    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            continue
        
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        
        # Check filters
        if 'ip' in filters and ip_layer.src != filters['ip'] and ip_layer.dst != filters['ip']:
            continue
        if 'src_ip' in filters and ip_layer.src != filters['src_ip']:
            continue
        if 'dst_ip' in filters and ip_layer.dst != filters['dst_ip']:
            continue
        if 'port' in filters:
            if tcp_layer.sport != filters['port'] and tcp_layer.dport != filters['port']:
                continue
        
        # Determine stream direction
        stream_key = f"{ip_layer.src}:{tcp_layer.sport}->{ip_layer.dst}:{tcp_layer.dport}"
        
        # Extract payload
        payload = b""
        if tcp_layer.payload and isinstance(tcp_layer.payload, Raw):
            payload = bytes(tcp_layer.payload)
        
        if not payload:
            continue
        
        # Store with sequence number for ordering
        stream_data[stream_key]['forward'].append((tcp_layer.seq, payload))
    
    # Reassemble each stream
    print(f"\nFound {len(stream_data)} streams")
    
    for stream_key, data in stream_data.items():
        if not data['forward']:
            continue
        
        print(f"\n{'=' * 80}")
        print(f"Stream: {stream_key}")
        print(f"{'=' * 80}")
        
        # Sort by sequence number and concatenate
        segments = sorted(data['forward'], key=lambda x: x[0])
        
        reassembled = b""
        for seq, payload in segments:
            reassembled += payload
        
        # Try to decode as text
        try:
            text = reassembled.decode('utf-8')
            print(text[:2000])  # First 2000 chars
            if len(text) > 2000:
                print(f"\n... ({len(text)} total characters)")
        except UnicodeDecodeError:
            # Binary data - show hex dump of first portion
            print("Binary data:")
            print(reassembled[:512].hex())
            if len(reassembled) > 512:
                print(f"... ({len(reassembled)} total bytes)")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python tools/stream_reassemble.py <file.pcap> [filters]")
        print("\nFilters:")
        print("  --ip IP           Either source or destination IP")
        print("  --src-ip IP       Source IP address")
        print("  --dst-ip IP       Destination IP address")
        print("  --port PORT       Either source or destination port")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    filters = {}
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--ip' and i + 1 < len(sys.argv):
            filters['ip'] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--src-ip' and i + 1 < len(sys.argv):
            filters['src_ip'] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--dst-ip' and i + 1 < len(sys.argv):
            filters['dst_ip'] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--port' and i + 1 < len(sys.argv):
            filters['port'] = int(sys.argv[i + 1])
            i += 2
        else:
            print(f"Unknown argument: {sys.argv[i]}")
            i += 1
    
    reassemble_stream(filepath, filters)
