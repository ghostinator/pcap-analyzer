#!/usr/bin/env python3
"""HTTP Traffic Analysis

Extracts and analyzes HTTP requests and responses from pcap files.
Useful for debugging web application issues, API calls, etc.

Usage:
    python tools/http_analysis.py <file.pcap> [--requests] [--responses]
    python tools/http_analysis.py <file.pcap> --filter "api.example.com"
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


def extract_http_data(filepath, filter_str=None):
    """Extract HTTP requests and responses from pcap."""
    print(f"Reading {filepath}...")
    
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    
    http_requests = []
    http_responses = []
    
    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            continue
        
        # Check for HTTP payload
        tcp_payload = ""
        if pkt[TCP].payload and isinstance(pkt[TCP].payload, Raw):
            try:
                tcp_payload = bytes(pkt[TCP].payload).decode('utf-8', errors='ignore')
            except Exception:
                continue
        
        # Detect HTTP request
        if tcp_payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'PATCH ', 'OPTIONS ')):
            lines = tcp_payload.split('\r\n')
            method, path, version = lines[0].split(' ')[:3]
            
            # Extract host header
            host = ""
            for line in lines:
                if line.lower().startswith('host:'):
                    host = line.split(':', 1)[1].strip()
                    break
            
            request_info = {
                'method': method,
                'path': path,
                'version': version,
                'host': host,
                'src_ip': pkt[IP].src,
                'dst_ip': pkt[IP].dst,
                'dst_port': pkt[TCP].dport,
                'time': float(pkt.time),
                'raw': tcp_payload[:500]  # First 500 chars
            }
            
            if filter_str is None or filter_str in host or filter_str in path:
                http_requests.append(request_info)
        
        # Detect HTTP response
        elif tcp_payload.startswith('HTTP/'):
            lines = tcp_payload.split('\r\n')
            parts = lines[0].split(' ')
            
            if len(parts) >= 2:
                status_code = int(parts[1]) if parts[1].isdigit() else 0
                
                response_info = {
                    'version': parts[0],
                    'status_code': status_code,
                    'reason': ' '.join(parts[2:]) if len(parts) > 2 else '',
                    'src_ip': pkt[IP].src,
                    'dst_ip': pkt[IP].dst,
                    'time': float(pkt.time),
                    'raw': tcp_payload[:500]
                }
                
                http_responses.append(response_info)
    
    return http_requests, http_responses


def print_http_summary(requests, responses):
    """Print HTTP traffic summary."""
    print(f"\nHTTP Requests: {len(requests)}")
    print(f"HTTP Responses: {len(responses)}")
    
    if requests:
        print("\nRequest Methods:")
        methods = defaultdict(int)
        for req in requests:
            methods[req['method']] += 1
        for method, count in sorted(methods.items(), key=lambda x: -x[1]):
            print(f"  {method}: {count}")
    
    if responses:
        print("\nResponse Status Codes:")
        statuses = defaultdict(int)
        for resp in responses:
            status_class = f"{resp['status_code'] // 100}xx"
            statuses[status_class] += 1
        for status, count in sorted(statuses.items()):
            print(f"  {status}: {count}")


def print_http_requests(requests, limit=20):
    """Print HTTP request details."""
    print("\nHTTP Requests:")
    print("-" * 80)
    
    for i, req in enumerate(requests[:limit]):
        host = req['host'] or req['dst_ip']
        print(f"[{i}] {req['method']} {req['path']}")
        print(f"     Host: {host}")
        print(f"     From: {req['src_ip']} -> To: {req['dst_ip']}:{req['dst_port']}")
        
        if i >= 19 and len(requests) > 20:
            print(f"\n... and {len(requests) - 20} more requests")
            break


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tools/http_analysis.py <file.pcap> [--filter 'domain']")
        sys.exit(1)
    
    filepath = sys.argv[1]
    filter_str = None
    
    if "--filter" in sys.argv:
        idx = sys.argv.index("--filter") + 1
        if idx < len(sys.argv):
            filter_str = sys.argv[idx]
    
    requests, responses = extract_http_data(filepath, filter_str)
    print_http_summary(requests, responses)
    print_http_requests(requests)
