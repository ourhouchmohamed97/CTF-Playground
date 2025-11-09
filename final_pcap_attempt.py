#!/usr/bin/env python3
"""
Final comprehensive attempt - try all combinations and patterns.
"""
from scapy.all import rdpcap
import base64
import hashlib
from itertools import permutations

packets = rdpcap('capture.pcap')

# Extract HTTP packets with all metadata
http_data = []
for i, pkt in enumerate(packets):
    if pkt.haslayer('Raw'):
        payload = bytes(pkt['Raw'].load)
        if b'GET /' in payload and b' HTTP' in payload:
            try:
                start = payload.index(b'GET /') + 5
                end = payload.index(b' HTTP', start)
                path = payload[start:end].decode('ascii')
                
                meta = {
                    'index': i,
                    'path': path,
                    'timestamp': float(pkt.time),
                    'src_port': pkt['TCP'].sport if pkt.haslayer('TCP') else 0,
                    'dst_port': pkt['TCP'].dport if pkt.haslayer('TCP') else 0,
                    'ip_id': pkt['IP'].id if pkt.haslayer('IP') else 0,
                }
                
                http_data.append(meta)
            except:
                pass

print(f"Found {len(http_data)} HTTP packets\n")

# Function to decode with a given order
def decode_with_order(ordered_data):
    paths = [d['path'] for d in ordered_data]
    concat = ''.join(paths).upper()
    padding = (8 - len(concat) % 8) % 8
    try:
        return base64.b32decode(concat + '=' * padding)
    except:
        return None

# Function to test decryption methods
def test_decrypt(decoded):
    if not decoded:
        return None
    
    # Try single-byte XOR
    for key in range(256):
        result = bytes([b ^ key for b in decoded])
        if b'DeepSec{' in result:
            return ('Single-byte XOR', key, result)
    
    # Try multi-byte XOR with common keys
    common_keys = [
        b'DeepSec', b'capture', b'pcap', b'CTF', b'FLAG', 
        b'port', b'packet', b'network', b'http'
    ]
    
    for key in common_keys:
        result = bytes([decoded[i] ^ key[i % len(key)] for i in range(len(decoded))])
        if b'DeepSec{' in result:
            return ('Multi-byte XOR', key, result)
    
    # Try RC4
    try:
        from Crypto.Cipher import ARC4
        for key in common_keys:
            cipher = ARC4.new(key)
            result = cipher.decrypt(decoded)
            if b'DeepSec{' in result:
                return ('RC4', key, result)
    except:
        pass
    
    return None

# Test different orderings
orderings = [
    ('packet index', lambda x: x['index']),
    ('timestamp', lambda x: x['timestamp']),
    ('source port', lambda x: x['src_port']),
    ('reverse packet index', lambda x: -x['index']),
    ('reverse timestamp', lambda x: -x['timestamp']),
    ('reverse source port', lambda x: -x['src_port']),
]

print("=" * 70)
print("TESTING DIFFERENT ORDERINGS")
print("=" * 70)

for order_name, sort_func in orderings:
    ordered = sorted(http_data, key=sort_func)
    decoded = decode_with_order(ordered)
    
    if decoded:
        print(f"\n{order_name}:")
        print(f"  First 32 bytes: {decoded[:32].hex()}")
        
        result = test_decrypt(decoded)
        if result:
            method, key, flag = result
            print(f"  [+] FOUND with {method}, key={key}:")
            print(f"      {flag}")
            print("\n" + "=" * 70)
            print("FLAG FOUND!")
            print("=" * 70)
            break

# Try extracting key from port numbers themselves
print("\n" + "=" * 70)
print("EXTRACTING KEY FROM PORT NUMBERS")
print("=" * 70)

# Sort by timestamp (chronological)
ordered = sorted(http_data, key=lambda x: x['timestamp'])
decoded = decode_with_order(ordered)

if decoded:
    # Use source ports as XOR key
    ports = [d['src_port'] for d in ordered]
    
    # Try port modulo 256 as key
    port_key = bytes([p % 256 for p in ports])
    result = bytes([decoded[i] ^ port_key[i % len(port_key)] for i in range(len(decoded))])
    
    if b'DeepSec{' in result:
        print(f"[+] FOUND using port numbers as key:")
        print(result)
    else:
        print(f"Port key (first 30 bytes): {port_key.hex()}")
        print(f"Result (first 100): {result[:100]}")
        
        # Try XORing port key itself with something
        for offset in range(256):
            adjusted_key = bytes([((p % 256) + offset) % 256 for p in ports])
            result = bytes([decoded[i] ^ adjusted_key[i % len(adjusted_key)] for i in range(len(decoded))])
            if b'DeepSec{' in result:
                print(f"\n[+] FOUND with port offset {offset}:")
                print(result)
                break

# Try using packet LENGTH as part of the key
print("\n" + "=" * 70)
print("USING PACKET/PATH LENGTHS")
print("=" * 70)

ordered = sorted(http_data, key=lambda x: x['timestamp'])
decoded = decode_with_order(ordered)

if decoded:
    # Get path lengths
    path_lens = [len(d['path']) for d in ordered]
    len_key = bytes(path_lens)
    
    result = bytes([decoded[i] ^ len_key[i % len(len_key)] for i in range(len(decoded))])
    
    if b'DeepSec{' in result:
        print(f"[+] FOUND using path lengths as key:")
        print(result)
    else:
        print(f"Path lengths: {path_lens}")
        print(f"Result (first 100): {result[:100]}")

# Save different orderings to files for manual inspection
print("\n" + "=" * 70)
print("SAVING DATA FOR MANUAL ANALYSIS")
print("=" * 70)

for order_name, sort_func in orderings[:3]:
    ordered = sorted(http_data, key=sort_func)
    decoded = decode_with_order(ordered)
    if decoded:
        filename = f"/tmp/pcap_{order_name.replace(' ', '_')}.bin"
        with open(filename, 'wb') as f:
            f.write(decoded)
        print(f"Saved {order_name} to {filename}")

print("\nDone. If no flag found, the challenge may require:")
print("  - A specific key from challenge description/organizers")
print("  - Non-standard cipher or custom algorithm")
print("  - Additional data not present in the PCAP")
