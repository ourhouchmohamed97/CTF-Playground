#!/usr/bin/env python3
"""
Brute force XOR on chronologically ordered data.
"""
from scapy.all import rdpcap
import base64

packets = rdpcap('capture.pcap')

# Extract and sort by timestamp
http_packets = []
for i, pkt in enumerate(packets):
    if pkt.haslayer('Raw'):
        payload = bytes(pkt['Raw'].load)
        if b'GET /' in payload and b' HTTP' in payload:
            try:
                start = payload.index(b'GET /') + 5
                end = payload.index(b' HTTP', start)
                path = payload[start:end].decode('ascii')
                timestamp = float(pkt.time)
                http_packets.append((timestamp, path))
            except:
                pass

http_packets.sort(key=lambda x: x[0])
paths = [path for _, path in http_packets]
concat = ''.join(paths).upper()
padding = (8 - len(concat) % 8) % 8
decoded = base64.b32decode(concat + '=' * padding)

print(f"Decoded {len(decoded)} bytes from chronologically ordered paths")
print(f"Hex: {decoded[:32].hex()}\n")

# Try ALL single-byte XOR keys
print("=" * 70)
print("BRUTE FORCE XOR (ALL 256 KEYS)")
print("=" * 70)

found = False
for key in range(256):
    result = bytes([b ^ key for b in decoded])
    
    if b'DeepSec{' in result or b'FLAG{' in result or b'CTF{' in result:
        print(f"\n[+] FOUND with key {key} (0x{key:02x}):")
        print(f"    {result}")
        found = True
        break
    
    # Also check if result is mostly printable
    printable = sum(32 <= b < 127 for b in result)
    if printable > len(result) * 0.9:
        # Check if it contains DeepSec-like patterns
        result_str = result.decode('ascii', errors='ignore')
        if 'deep' in result_str.lower() or 'sec' in result_str.lower() or '{' in result_str:
            print(f"\n[?] Highly printable with key {key} (0x{key:02x}):")
            print(f"    First 200 chars: {result[:200]}")

if not found:
    print("\nNo flag found with single-byte XOR")

# Try multi-byte XOR with common keys
print("\n" + "=" * 70)
print("MULTI-BYTE XOR")
print("=" * 70)

keys_to_try = [
    b'DeepSec', b'capture', b'pcap', b'CTF', b'FLAG', b'key',
    b'password', b'secret', b'http', b'network', b'wireshark',
    b'example.net', b'base32', b'timestamp', b'chronological'
]

for key in keys_to_try:
    result = bytes([decoded[i] ^ key[i % len(key)] for i in range(len(decoded))])
    if b'DeepSec{' in result or b'FLAG{' in result:
        print(f"\n[+] FOUND with key {key}:")
        print(f"    {result}")
        found = True
        break

# Try MD5 hashes as keys
print("\n" + "=" * 70)
print("XOR WITH MD5 HASHES")
print("=" * 70)

import hashlib

hash_bases = ['capture', 'pcap', 'chronological', 'timestamp', 'ordered', 'DeepSec', 'flag']
for base in hash_bases:
    key = hashlib.md5(base.encode()).digest()
    result = bytes([decoded[i] ^ key[i % len(key)] for i in range(len(decoded))])
    if b'DeepSec{' in result or b'FLAG{' in result:
        print(f"\n[+] FOUND with MD5('{base}'):")
        print(f"    {result}")
        found = True
        break

# Try interpreting raw bytes as ASCII
print("\n" + "=" * 70)
print("RAW DATA INTERPRETATION")
print("=" * 70)

# Check if it's directly readable
printable = sum(32 <= b < 127 for b in decoded)
print(f"Printable bytes: {printable}/{len(decoded)} ({100*printable/len(decoded):.1f}%)")

if printable > len(decoded) * 0.7:
    print(f"\nRaw data (as ASCII):")
    print(decoded.decode('ascii', errors='ignore'))

# Save chronological data
with open('/tmp/chrono_decoded.bin', 'wb') as f:
    f.write(decoded)
print(f"\nSaved to /tmp/chrono_decoded.bin")

# Try looking at specific byte patterns
print("\n" + "=" * 70)
print("BYTE PATTERN ANALYSIS")
print("=" * 70)

# Check for repeating patterns
print("First 16 bytes: ", ' '.join(f'{b:02x}' for b in decoded[:16]))
print("Last 16 bytes:  ", ' '.join(f'{b:02x}' for b in decoded[-16:]))

# Check byte frequency
from collections import Counter
freq = Counter(decoded)
print(f"\nMost common bytes:")
for byte, count in freq.most_common(10):
    print(f"  0x{byte:02x} ({chr(byte) if 32 <= byte < 127 else '?'}): {count} times ({100*count/len(decoded):.1f}%)")

if not found:
    print("\n[!] No flag found yet. The encryption may require:")
    print("    - A specific key from challenge description")
    print("    - Different cipher (AES, RC4, etc.)")
    print("    - Additional transformation steps")
