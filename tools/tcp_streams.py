#!/usr/bin/env python3
"""TCP Stream Analysis

Identifies and analyzes TCP streams in a pcap file. Can list all streams,
show stream details, or reassemble specific streams.

Usage:
    python tools/tcp_streams.py <file.pcap> [--list]
    python tools/tcp_streams.py <file.pcap> --stream <index>
    python tools/tcp_streams.py <file.pcap> --filter "src_ip:dst_ip"
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


def get_stream_key(pkt):
    """Generate a unique key for a TCP stream (bidirectional)."""
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        
        # Normalize to ensure bidirectional matching
        if (src, sport) > (dst, dport):
            return f"{dst}:{dport} <-> {src}:{sport}"
        else:
            return f"{src}:{sport} <-> {dst}:{dport}"
    return None


def analyze_streams(filepath, stream_index=None, filter_str=None):
    """Analyze TCP streams in pcap file."""
    print(f"Reading {filepath}...")
    
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    
    # Group packets by stream
    streams = defaultdict(list)
    for pkt in packets:
        key = get_stream_key(pkt)
        if key:
            streams[key].append(pkt)
    
    print(f"\nFound {len(streams)} TCP streams")
    
    if stream_index is not None:
        # Show specific stream details
        keys = list(streams.keys())
        if 0 <= stream_index < len(keys):
            key = keys[stream_index]
            show_stream_details(key, streams[key])
        else:
            print(f"Stream index {stream_index} out of range (0-{len(keys)-1})")
    elif filter_str:
        # Filter and show matching streams
        for key, pkts in streams.items():
            if all(part in key for part in filter_str.split(":")):
                show_stream_summary(key, pkts)
    else:
        # List all streams with summary
        print("\nStream Summary:")
        print("-" * 80)
        for i, (key, pkts) in enumerate(streams.items()):
            show_stream_summary(f"[{i}] {key}", pkts)


def show_stream_summary(label, packets):
    """Show summary info for a stream."""
    # Calculate bytes transferred each direction
    src_bytes = 0
    dst_bytes = 0
    
    if len(packets) > 0 and packets[0].haslayer(IP):
        first_src = packets[0][IP].src
        
        for pkt in packets:
            if pkt.haslayer(IP):
                payload_len = max(0, pkt[IP].len - pkt[IP].ihl * 4 - (pkt[TCP].dataofs * 4))
                if pkt[IP].src == first_src:
                    src_bytes += payload_len
                else:
                    dst_bytes += payload_len
    
    print(f"{label}")
    print(f"  Packets: {len(packets)} | Bytes sent: {src_bytes:,} | Bytes received: {dst_bytes:,}")


def show_stream_details(key, packets):
    """Show detailed info for a specific stream."""
    print(f"\nStream: {key}")
    print("=" * 80)
    
    # TCP flags analysis
    flags = defaultdict(int)
    retransmissions = 0
    
    seq_numbers = []
    
    for pkt in packets:
        if pkt.haslayer(TCP):
            flag_str = str(pkt[TCP].flags)
            flags[flag_str] += 1
            
            # Track sequence numbers to detect retransmissions (simplified)
            seq_numbers.append((pkt[IP].src, pkt[TCP].seq))
    
    print(f"Total packets: {len(packets)}")
    print("\nTCP Flag Distribution:")
    for flag, count in sorted(flags.items(), key=lambda x: -x[1]):
        print(f"  {flag:<10} {count}")
    
    # Detect potential retransmissions (same src+seq)
    seen_seqs = set()
    for src, seq in seq_numbers:
        if (src, seq) in seen_seqs:
            retransmissions += 1
        seen_seqs.add((src, seq))
    
    print(f"\nPotential retransmissions: {retransmissions}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tools/tcp_streams.py <file.pcap> [--list | --stream N | --filter 'ip:port']")
        sys.exit(1)
    
    filepath = sys.argv[1]
    stream_index = None
    filter_str = None
    
    if "--stream" in sys.argv:
        idx = sys.argv.index("--stream") + 1
        if idx < len(sys.argv):
            stream_index = int(sys.argv[idx])
    
    if "--filter" in sys.argv:
        idx = sys.argv.index("--filter") + 1
        if idx < len(sys.argv):
            filter_str = sys.argv[idx]
    
    analyze_streams(filepath, stream_index, filter_str)
