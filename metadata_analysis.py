#!/usr/bin/env python3
"""
Analyze source ports, sequence numbers, and other packet metadata.
"""
from scapy.all import rdpcap
import base64

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
                }
                
                if pkt.haslayer('IP'):
                    meta['src_ip'] = pkt['IP'].src
                    meta['dst_ip'] = pkt['IP'].dst
                    meta['ip_id'] = pkt['IP'].id
                
                if pkt.haslayer('TCP'):
                    meta['src_port'] = pkt['TCP'].sport
                    meta['dst_port'] = pkt['TCP'].dport
                    meta['seq'] = pkt['TCP'].seq
                    meta['ack'] = pkt['TCP'].ack
                
                http_data.append(meta)
            except:
                pass

print(f"Found {len(http_data)} HTTP GET packets\n")
print("=" * 100)
print("PACKET METADATA")
print("=" * 100)

# Show all metadata
for d in http_data:
    print(f"Pkt #{d['index']:3d} | Port: {d.get('src_port', 'N/A'):5d} | IP ID: {d.get('ip_id', 0):5d} | "
          f"Seq: {d.get('seq', 0):10d} | Path: {d['path'][:40]}...")

# Try sorting by different fields
print("\n" + "=" * 100)
print("TRYING DIFFERENT SORT ORDERS")
print("=" * 100)

sort_methods = [
    ('source port', lambda x: x.get('src_port', 0)),
    ('IP ID', lambda x: x.get('ip_id', 0)),
    ('sequence number', lambda x: x.get('seq', 0)),
    ('timestamp', lambda x: x['timestamp']),
]

from scapy.all import rdpcap
import base64

for method_name, sort_key in sort_methods:
    sorted_data = sorted(http_data, key=sort_key)
    paths = [d['path'] for d in sorted_data]
    concat = ''.join(paths).upper()
    padding = (8 - len(concat) % 8) % 8
    
    try:
        decoded = base64.b32decode(concat + '=' * padding)
        print(f"\nSort by {method_name}:")
        print(f"  Decoded: {len(decoded)} bytes")
        print(f"  Hex: {decoded[:32].hex()}")
        
        # Try simple XOR
        flag_found = False
        for key in range(256):
            result = bytes([b ^ key for b in decoded])
            if b'DeepSec{' in result:
                print(f"  [+] FLAG FOUND with XOR key {key}: {result}")
                flag_found = True
                break
        
        if not flag_found:
            # Check if mostly printable
            printable = sum(32 <= b < 127 for b in decoded)
            if printable > len(decoded) * 0.8:
                print(f"  [?] Highly printable ({printable}/{len(decoded)}): {decoded[:100]}")
    except Exception as e:
        print(f"\nSort by {method_name}: Failed - {e}")

# Check if source ports have a pattern
print("\n" + "=" * 100)
print("SOURCE PORT ANALYSIS")
print("=" * 100)

ports = [d.get('src_port', 0) for d in http_data]
print(f"Ports: {ports}")
print(f"Min: {min(ports)}, Max: {max(ports)}, Range: {max(ports) - min(ports)}")

# Check if ports encode anything
print("\nPort bytes (mod 256):")
port_bytes = bytes([p % 256 for p in ports])
print(f"  Hex: {port_bytes.hex()}")
print(f"  ASCII: {port_bytes.decode('ascii', errors='ignore')}")

if b'Deep' in port_bytes or b'FLAG' in port_bytes:
    print(f"  [+] FOUND FLAG IN PORTS!")

# Check IP IDs
print("\n" + "=" * 100)
print("IP ID ANALYSIS")
print("=" * 100)

ip_ids = [d.get('ip_id', 0) for d in http_data]
print(f"IP IDs: {ip_ids}")

# Try using IP IDs as XOR key
if ip_ids and all(id < 256 for id in ip_ids):
    # Use chronological decode
    sorted_data = sorted(http_data, key=lambda x: x['timestamp'])
    paths = [d['path'] for d in sorted_data]
    concat = ''.join(paths).upper()
    padding = (8 - len(concat) % 8) % 8
    decoded = base64.b32decode(concat + '=' * padding)
    
    print("\nTrying IP IDs as XOR keys:")
    # XOR with repeating IP IDs
    result = bytes([decoded[i] ^ ip_ids[i % len(ip_ids)] for i in range(len(decoded))])
    if b'DeepSec{' in result:
        print(f"  [+] FLAG FOUND: {result}")
    else:
        print(f"  First 100 bytes: {result[:100]}")

# Check HTTP path lengths
print("\n" + "=" * 100)
print("PATH LENGTH ANALYSIS")
print("=" * 100)

path_lens = [len(d['path']) for d in http_data]
print(f"Path lengths: {path_lens}")
print(f"Min: {min(path_lens)}, Max: {max(path_lens)}")

# Maybe path length encodes something?
len_bytes = bytes(path_lens)
print(f"\nPath lengths as bytes:")
print(f"  Hex: {len_bytes.hex()}")
print(f"  ASCII: {len_bytes.decode('ascii', errors='ignore')}")

if b'Deep' in len_bytes or b'FLAG' in len_bytes:
    print(f"  [+] FOUND FLAG IN PATH LENGTHS!")
