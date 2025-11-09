#!/usr/bin/env python3
"""
Deep dive into PCAP structure - maybe we're missing something.
"""
from scapy.all import rdpcap, IP, TCP, UDP, Raw
import base64

packets = rdpcap('capture.pcap')

print("=" * 70)
print("PCAP DEEP ANALYSIS")
print("=" * 70)
print(f"Total packets: {len(packets)}\n")

# Analyze ALL packets in detail
http_packets = []
for i, pkt in enumerate(packets):
    if pkt.haslayer(Raw):
        payload = bytes(pkt['Raw'].load)
        if b'GET /' in payload:
            http_packets.append((i, pkt, payload))

print(f"Found {len(http_packets)} HTTP GET packets\n")

# Extract paths using multiple methods
paths_method1 = []
paths_method2 = []

for idx, pkt, payload in http_packets:
    # Method 1: Extract between GET / and HTTP
    try:
        start = payload.index(b'GET /') + 5
        end = payload.index(b' HTTP', start)
        path = payload[start:end].decode('ascii')
        paths_method1.append(path)
    except:
        pass
    
    # Method 2: Look for anything between / and space
    try:
        lines = payload.decode('ascii', errors='ignore').split('\r\n')
        for line in lines:
            if line.startswith('GET /'):
                parts = line.split()
                if len(parts) >= 2:
                    path = parts[1][1:]  # Remove leading /
                    paths_method2.append(path)
                    break
    except:
        pass

print(f"Method 1 extracted {len(paths_method1)} paths")
print(f"Method 2 extracted {len(paths_method2)} paths")

# Check if methods match
if paths_method1 == paths_method2:
    print("✓ Both methods match")
else:
    print("✗ Methods differ!")
    print(f"  Method 1 first path: {paths_method1[0] if paths_method1 else 'None'}")
    print(f"  Method 2 first path: {paths_method2[0] if paths_method2 else 'None'}")

paths = paths_method1

# Show all paths
print(f"\nAll {len(paths)} paths:")
for i, path in enumerate(paths, 1):
    print(f"  {i:2d}. {path[:60]}{'...' if len(path) > 60 else ''}")

# Concatenate and decode
concat = ''.join(paths)
print(f"\nConcatenated length: {len(concat)} chars")
print(f"First 100 chars: {concat[:100]}")
print(f"Last 100 chars: {concat[-100:]}")

# Try base32 decode
concat_upper = concat.upper()
print(f"\nBase32 decode attempts:")

# Try without padding
try:
    decoded_no_pad = base64.b32decode(concat_upper)
    print(f"  No padding: {len(decoded_no_pad)} bytes")
    print(f"    Hex: {decoded_no_pad[:32].hex()}")
except Exception as e:
    print(f"  No padding: Failed - {e}")

# Try with padding
padding_needed = (8 - len(concat_upper) % 8) % 8
concat_padded = concat_upper + '=' * padding_needed
try:
    decoded_padded = base64.b32decode(concat_padded)
    print(f"  With {padding_needed} padding: {len(decoded_padded)} bytes")
    print(f"    Hex: {decoded_padded[:32].hex()}")
    
    # Save to file
    with open('/tmp/decoded.bin', 'wb') as f:
        f.write(decoded_padded)
    print(f"    Saved to /tmp/decoded.bin")
except Exception as e:
    print(f"  With padding: Failed - {e}")

# Try casefold (mixed case)
try:
    decoded_mixed = base64.b32decode(concat + '=' * padding_needed, casefold=True)
    print(f"  Casefold: {len(decoded_mixed)} bytes")
    print(f"    Hex: {decoded_mixed[:32].hex()}")
except Exception as e:
    print(f"  Casefold: Failed - {e}")

# Check if any HTTP response packets exist
print("\n" + "=" * 70)
print("HTTP RESPONSES")
print("=" * 70)

response_count = 0
for pkt in packets:
    if pkt.haslayer(Raw):
        payload = bytes(pkt['Raw'].load)
        if b'HTTP/1.' in payload and (b'200 OK' in payload or b'404' in payload):
            response_count += 1
            print(f"\nResponse packet found:")
            print(f"  Status: {payload[:100]}")
            # Check if response body contains flag
            if b'\r\n\r\n' in payload:
                body_start = payload.index(b'\r\n\r\n') + 4
                body = payload[body_start:]
                if body:
                    print(f"  Body ({len(body)} bytes): {body[:200]}")
                    if b'DeepSec{' in body or b'FLAG{' in body:
                        print(f"  [+] FLAG IN RESPONSE BODY: {body}")

print(f"\nTotal HTTP responses: {response_count}")

# Check packet order - maybe paths are not in sequential order?
print("\n" + "=" * 70)
print("PACKET TIMING AND ORDER")
print("=" * 70)

packet_times = []
for idx, pkt, payload in http_packets:
    if hasattr(pkt, 'time'):
        packet_times.append((idx, float(pkt.time), payload))

if packet_times:
    packet_times.sort(key=lambda x: x[1])
    print("Packets in chronological order:")
    for idx, timestamp, payload in packet_times[:5]:
        path_start = payload.index(b'GET /') + 5 if b'GET /' in payload else 0
        path_end = payload.index(b' HTTP', path_start) if b' HTTP' in payload[path_start:] else len(payload)
        path = payload[path_start:path_end].decode('ascii', errors='ignore')
        print(f"  Packet {idx} @ {timestamp}: {path[:50]}...")

print("\n" + "=" * 70)
print("ALTERNATIVE INTERPRETATIONS")
print("=" * 70)

# What if the paths themselves encode the flag directly?
full_concat = ''.join(paths)
print(f"\nDirect search in concatenated paths:")
if 'DeepSec' in full_concat or 'FLAG' in full_concat:
    print(f"  [+] Found flag pattern in paths!")
else:
    print(f"  No flag pattern in paths")

# What if we should use base64 instead of base32?
try:
    # Add padding for base64
    while len(concat) % 4 != 0:
        concat += '='
    b64_decoded = base64.b64decode(concat)
    print(f"\nBase64 decode: {len(b64_decoded)} bytes")
    print(f"  Hex: {b64_decoded[:32].hex()}")
    if b'DeepSec{' in b64_decoded:
        print(f"  [+] FOUND IN BASE64: {b64_decoded}")
except Exception as e:
    print(f"\nBase64 decode failed: {e}")
