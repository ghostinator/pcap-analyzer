#!/usr/bin/env python3
"""DNS Traffic Analysis

Analyzes DNS queries and responses in pcap files. Useful for debugging
name resolution issues, slow lookups, or DNS-based attacks.

Usage:
    python tools/dns_analysis.py <file.pcap> [--filter 'domain']
"""

import sys
import os
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from scapy.all import rdpcap, IP, UDP, DNS, DNSQR, DNSRR
except ImportError:
    print("Error: scapy not installed. Run: pip install scapy")
    sys.exit(1)


def analyze_dns(filepath, filter_str=None):
    """Analyze DNS traffic in pcap file."""
    print(f"Reading {filepath}...")
    
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    
    queries = []
    responses = []
    
    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(DNS)):
            continue
        
        dns_layer = pkt[DNS]
        
        # DNS Query
        if dns_layer.qr == 0 and dns_layer.qd is not None:
            qname = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            
            query_info = {
                'qname': qname,
                'qtype': dns_layer.qd.qtype,
                'src_ip': pkt[IP].src,
                'dst_ip': pkt[IP].dst,  # DNS server
                'time': float(pkt.time),
                'id': dns_layer.id
            }
            
            if filter_str is None or filter_str in qname:
                queries.append(query_info)
        
        # DNS Response
        elif dns_layer.qr == 1 and dns_layer.an is not None:
            # Get query name from question section
            qname = ""
            if dns_layer.qd is not None:
                qname = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            
            # Extract answers
            answers = []
            rr = dns_layer.an
            while rr is not None:
                try:
                    rdata = rr.rdata.decode('utf-8', errors='ignore') if isinstance(rr.rdata, bytes) else str(rr.rdata)
                except Exception:
                    rdata = "unknown"
                
                answers.append({
                    'type': rr.type,
                    'rdata': rdata,
                    'ttl': rr.ttl
                })
                
                rr = rr.next
            
            response_info = {
                'qname': qname,
                'answers': answers,
                'rcode': dns_layer.rcode,
                'src_ip': pkt[IP].src,  # DNS server
                'dst_ip': pkt[IP].dst,
                'time': float(pkt.time),
                'id': dns_layer.id
            }
            
            if filter_str is None or filter_str in qname:
                responses.append(response_info)
    
    return queries, responses


def print_dns_summary(queries, responses):
    """Print DNS traffic summary."""
    print(f"\nDNS Queries: {len(queries)}")
    print(f"DNS Responses: {len(responses)}")
    
    if queries:
        # Top queried domains
        domain_counts = defaultdict(int)
        for q in queries:
            domain_counts[q['qname']] += 1
        
        print("\nTop Queried Domains:")
        for domain, count in sorted(domain_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"  {domain}: {count}")
        
        # DNS servers used
        server_counts = defaultdict(int)
        for q in queries:
            server_counts[q['dst_ip']] += 1
        
        print("\nDNS Servers Used:")
        for server, count in sorted(server_counts.items(), key=lambda x: -x[1]):
            print(f"  {server}: {count} queries")


def print_dns_details(queries, responses, limit=20):
    """Print detailed DNS query/response info."""
    print("\nDNS Query/Response Details:")
    print("-" * 80)
    
    # Match queries with responses by ID (simplified)
    response_map = {r['id']: r for r in responses}
    
    shown = 0
    for q in queries:
        if shown >= limit:
            break
        
        resp = response_map.get(q['id'])
        
        print(f"Query: {q['qname']}")
        print(f"  From: {q['src_ip']} -> Server: {q['dst_ip']}")
        
        if resp:
            status = "OK" if resp['rcode'] == 0 else f"Error ({resp['rcode']})"
            print(f"  Response: {status}")
            
            for ans in resp['answers']:
                type_name = "A" if ans['type'] == 1 else ("AAAA" if ans['type'] == 28 else str(ans['type']))
                print(f"    {type_name}: {ans['rdata']} (TTL: {ans['ttl']})")
        else:
            print("  Response: Not found in capture")
        
        shown += 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tools/dns_analysis.py <file.pcap> [--filter 'domain']")
        sys.exit(1)
    
    filepath = sys.argv[1]
    filter_str = None
    
    if "--filter" in sys.argv:
        idx = sys.argv.index("--filter") + 1
        if idx < len(sys.argv):
            filter_str = sys.argv[idx]
    
    queries, responses = analyze_dns(filepath, filter_str)
    print_dns_summary(queries, responses)
    print_dns_details(queries, responses)
