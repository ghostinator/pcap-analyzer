#!/usr/bin/env python3
"""Wireless (802.11) PCAP Analysis

Analyzes wireless packet captures for signal quality, channel usage,
authentication issues, and other 802.11-specific metrics.

Usage:
    python tools/wireless_analysis.py <file.pcap> [--bssid MAC] [--verbose]
"""

import sys
import os
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp
    from scapy.layers.dot11 import Dot11Elt
except ImportError:
    print("Error: scapy not installed. Run: pip install scapy")
    sys.exit(1)


def analyze_wireless(filepath, bssid_filter=None, verbose=False):
    """Analyze wireless traffic in pcap file."""
    print(f"Reading {filepath}...")
    
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    
    # Wireless metrics
    ap_info = defaultdict(lambda: {
        'beacons': 0,
        'clients': set(),
        'channels': [],
        'signal_strengths': [],
        'essid': None,
        'last_seen': 0
    })
    
    probe_requests = defaultdict(int)
    probe_responses = defaultdict(int)
    auth_frames = 0
    deauth_frames = 0
    disassoc_frames = 0
    data_frames = 0
    management_frames = 0
    
    # Client connection tracking
    client_connections = defaultdict(lambda: {
        'bssid': None,
        'first_seen': float('inf'),
        'last_seen': 0,
        'frames': 0
    })
    
    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue
        
        dot11 = pkt[Dot11]
        
        # Classify frame type
        if dot11.type == 0:  # Management
            management_frames += 1
            
            if dot11.subtype == 8:  # Beacon
                ap_mac = dot11.addr3
                if bssid_filter and ap_mac != bssid_filter:
                    continue
                
                ap_info[ap_mac]['beacons'] += 1
                ap_info[ap_mac]['last_seen'] = float(pkt.time)
                
                # Extract ESSID
                for elem in pkt[Dot11].elements:
                    if isinstance(elem, Dot11Elt) and elem.ID == 0:
                        try:
                            essid = elem.info.decode('utf-8', errors='ignore')
                            ap_info[ap_mac]['essid'] = essid
                        except Exception:
                            pass
                
                # Channel info (from DS Parameter Set element, ID=3)
                for elem in pkt[Dot11].elements:
                    if isinstance(elem, Dot11Elt) and elem.ID == 3:
                        try:
                            channel = int.from_bytes(elem.info, 'little')
                            ap_info[ap_mac]['channels'].append(channel)
                        except Exception:
                            pass
            
            elif dot11.subtype == 4:  # Probe Request
                if dot11.addr2:
                    probe_requests[dot11.addr2] += 1
            
            elif dot11.subtype == 5:  # Probe Response
                if dot11.addr3:
                    probe_responses[dot11.addr3] += 1
            
            elif dot11.subtype == 0:  # Authentication
                auth_frames += 1
            
            elif dot11.subtype == 12:  # Deauthentication
                deauth_frames += 1
                if verbose and dot11.addr1 and dot11.addr3:
                    print(f"Deauth: {dot11.addr3} -> {dot11.addr1}")
            
            elif dot11.subtype == 10:  # Disassociation
                disassoc_frames += 1
        
        elif dot11.type == 2:  # Data
            data_frames += 1
            
            # Track client connections
            if dot11.addr3 and dot11.addr2:
                bssid = dot11.addr3
                client_mac = dot11.addr2
                
                conn = client_connections[client_mac]
                conn['bssid'] = bssid
                conn['first_seen'] = min(conn['first_seen'], float(pkt.time))
                conn['last_seen'] = max(conn['last_seen'], float(pkt.time))
                conn['frames'] += 1
                
                ap_info[bssid]['clients'].add(client_mac)
    
    return {
        'ap_info': ap_info,
        'probe_requests': probe_requests,
        'probe_responses': probe_responses,
        'auth_frames': auth_frames,
        'deauth_frames': deauth_frames,
        'disassoc_frames': disassoc_frames,
        'data_frames': data_frames,
        'management_frames': management_frames,
        'client_connections': client_connections
    }


def print_wireless_summary(results):
    """Print wireless analysis summary."""
    ap_info = results['ap_info']
    
    print("\n" + "=" * 60)
    print("WIRELESS ANALYSIS SUMMARY")
    print("=" * 60)
    
    print(f"\nAccess Points Detected: {len(ap_info)}")
    print("-" * 40)
    
    for ap_mac, info in sorted(ap_info.items(), key=lambda x: -x[1]['beacons']):
        essid = info['essid'] or "Unknown"
        channels = set(info['channels'])
        channel_str = ", ".join(str(c) for c in channels) if channels else "N/A"
        
        print(f"\nAP: {ap_mac}")
        print(f"  ESSID: {essid}")
        print(f"  Beacons: {info['beacons']}")
        print(f"  Channel(s): {channel_str}")
        print(f"  Connected Clients: {len(info['clients'])}")
        
        if info['clients']:
            print("  Client MACs:")
            for client in sorted(list(info['clients']))[:10]:
                print(f"    {client}")
            if len(info['clients']) > 10:
                print(f"    ... and {len(info['clients']) - 10} more")
    
    # Frame type summary
    print("\n\nFrame Type Summary:")
    print("-" * 40)
    print(f"  Management Frames: {results['management_frames']}")
    print(f"  Data Frames:       {results['data_frames']}")
    print(f"  Probe Requests:    {sum(results['probe_requests'].values())}")
    print(f"  Probe Responses:   {sum(results['probe_responses'].values())}")
    print(f"  Auth Frames:       {results['auth_frames']}")
    print(f"  Deauth Frames:     {results['deauth_frames']}")
    print(f"  Disassoc Frames:   {results['disassoc_frames']}")
    
    # Client connection summary
    print("\n\nClient Connection Summary:")
    print("-" * 40)
    for client_mac, conn in sorted(results['client_connections'].items(), 
                                   key=lambda x: -x[1]['frames'])[:20]:
        duration = conn['last_seen'] - conn['first_seen']
        if duration < 0:
            duration = 0
        print(f"  {client_mac}")
        print(f"    AP: {conn['bssid']}")
        print(f"    Frames: {conn['frames']} | Duration: {duration:.1f}s")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tools/wireless_analysis.py <file.pcap> [--bssid MAC] [--verbose]")
        sys.exit(1)
    
    filepath = sys.argv[1]
    bssid_filter = None
    verbose = "--verbose" in sys.argv
    
    if "--bssid" in sys.argv:
        idx = sys.argv.index("--bssid") + 1
        if idx < len(sys.argv):
            bssid_filter = sys.argv[idx].upper()
    
    results = analyze_wireless(filepath, bssid_filter, verbose)
    print_wireless_summary(results)
