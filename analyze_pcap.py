#!/usr/bin/env python3
"""
PCAP Analysis Tool - Extract and analyze network traffic
"""

from scapy.all import *
import binascii

def analyze_pcap(filename):
    print("="*70)
    print("PCAP Analysis Tool")
    print("="*70)
    
    # Read the PCAP file
    print(f"\n[*] Reading {filename}...")
    packets = rdpcap(filename)
    
    print(f"[+] Total packets: {len(packets)}")
    
    # Analyze packet types
    protocols = {}
    for pkt in packets:
        proto = pkt.name
        protocols[proto] = protocols.get(proto, 0) + 1
    
    print("\n[*] Protocol distribution:")
    for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
        print(f"  {proto}: {count}")
    
    # Extract payloads
    print("\n[*] Extracting payloads...")
    payloads = []
    
    for i, pkt in enumerate(packets):
        # Check for Raw layer (payload data)
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            payloads.append({
                'index': i,
                'data': payload,
                'hex': binascii.hexlify(payload).decode(),
                'ascii': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload)
            })
    
    print(f"[+] Found {len(payloads)} packets with payloads")
    
    # Display payloads
    if payloads:
        print("\n[*] Payload data:")
        for p in payloads[:20]:  # Show first 20
            print(f"\n  Packet {p['index']}:")
            print(f"    Hex: {p['hex'][:100]}{'...' if len(p['hex']) > 100 else ''}")
            print(f"    ASCII: {p['ascii'][:100]}{'...' if len(p['ascii']) > 100 else ''}")
    
    # Look for flags
    print("\n[*] Searching for flags...")
    all_data = b''.join([p['data'] for p in payloads])
    
    # Search for common flag formats
    flag_patterns = [b'DeepSec{', b'FLAG{', b'CTF{', b'flag{', b'DEEPSEC{']
    for pattern in flag_patterns:
        if pattern in all_data:
            idx = all_data.find(pattern)
            flag_data = all_data[idx:idx+100]
            print(f"  [+] Found {pattern.decode()}: {flag_data[:100]}")
    
    # Check for TCP streams
    print("\n[*] Analyzing TCP streams...")
    tcp_streams = {}
    for pkt in packets:
        if TCP in pkt and Raw in pkt:
            stream_id = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
            if stream_id not in tcp_streams:
                tcp_streams[stream_id] = []
            tcp_streams[stream_id].append(bytes(pkt[Raw].load))
    
    print(f"[+] Found {len(tcp_streams)} TCP streams")
    
    for i, (stream_id, data_list) in enumerate(tcp_streams.items()):
        stream_data = b''.join(data_list)
        print(f"\n  Stream {i}: {stream_id[0]}:{stream_id[1]} -> {stream_id[2]}:{stream_id[3]}")
        print(f"    Total data: {len(stream_data)} bytes")
        
        # Check if it's printable
        printable = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in stream_data[:200])
        print(f"    Data: {printable}")
        
        # Look for flags in this stream
        for pattern in flag_patterns:
            if pattern in stream_data:
                idx = stream_data.find(pattern)
                flag_end = stream_data.find(b'}', idx)
                if flag_end != -1:
                    potential_flag = stream_data[idx:flag_end+1]
                    print(f"    [!] POTENTIAL FLAG: {potential_flag.decode(errors='ignore')}")
    
    # Check for HTTP
    print("\n[*] Checking for HTTP traffic...")
    for pkt in packets:
        if TCP in pkt and Raw in pkt:
            payload = bytes(pkt[Raw].load)
            if b'HTTP' in payload or b'GET' in payload or b'POST' in payload:
                print(f"\n  HTTP Packet found:")
                print(f"    {payload[:500].decode(errors='ignore')}")
    
    # Check for DNS
    print("\n[*] Checking for DNS traffic...")
    dns_queries = []
    for pkt in packets:
        if DNS in pkt and pkt[DNS].qr == 0:  # Query
            qname = pkt[DNS].qd.qname.decode() if pkt[DNS].qd else 'N/A'
            dns_queries.append(qname)
    
    if dns_queries:
        print(f"[+] Found {len(dns_queries)} DNS queries:")
        for q in dns_queries[:10]:
            print(f"    {q}")
    
    # Check for ICMP
    print("\n[*] Checking for ICMP traffic...")
    for pkt in packets:
        if ICMP in pkt and Raw in pkt:
            payload = bytes(pkt[Raw].load)
            print(f"\n  ICMP Payload:")
            print(f"    Hex: {binascii.hexlify(payload).decode()[:100]}")
            print(f"    ASCII: {''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload[:100])}")
    
    return packets, payloads, tcp_streams

if __name__ == "__main__":
    analyze_pcap("capture.pcap")
