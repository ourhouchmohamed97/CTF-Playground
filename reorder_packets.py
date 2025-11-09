#!/usr/bin/env python3
"""
Try reordering packets by timestamp before concatenating.
"""
from scapy.all import rdpcap
import base64

packets = rdpcap('capture.pcap')

# Extract HTTP packets with timestamps
http_packets = []
for i, pkt in enumerate(packets):
    if pkt.haslayer('Raw'):
        payload = bytes(pkt['Raw'].load)
        if b'GET /' in payload and b' HTTP' in payload:
            try:
                start = payload.index(b'GET /') + 5
                end = payload.index(b' HTTP', start)
                path = payload[start:end].decode('ascii')
                timestamp = float(pkt.time) if hasattr(pkt, 'time') else i
                http_packets.append((timestamp, i, path))
            except:
                pass

print(f"Found {len(http_packets)} HTTP GET requests\n")

# Sort by timestamp
http_packets.sort(key=lambda x: x[0])

print("Packets in chronological order:")
for ts, idx, path in http_packets:
    print(f"  Packet #{idx:3d} @ {ts:.6f}: {path}")

# Concatenate in chronological order
paths_chrono = [path for _, _, path in http_packets]
concat_chrono = ''.join(paths_chrono)

print(f"\nChronological concatenation: {len(concat_chrono)} chars")
print(f"First 100: {concat_chrono[:100]}")

# Try base32 decode
concat_upper = concat_chrono.upper()
padding = (8 - len(concat_upper) % 8) % 8
concat_padded = concat_upper + '=' * padding

try:
    decoded_chrono = base64.b32decode(concat_padded)
    print(f"\nBase32 decoded (chronological): {len(decoded_chrono)} bytes")
    print(f"Hex: {decoded_chrono[:32].hex()}")
    
    # Search for flag
    if b'DeepSec{' in decoded_chrono:
        print(f"\n[+] FOUND FLAG: {decoded_chrono}")
    else:
        # Try XOR with simple key
        for key in range(256):
            result = bytes([b ^ key for b in decoded_chrono])
            if b'DeepSec{' in result:
                print(f"\n[+] FOUND with XOR key {key}: {result}")
                break
except Exception as e:
    print(f"Base32 decode failed: {e}")

# Now try concatenating in PACKET NUMBER order (as they appear in PCAP)
print("\n" + "=" * 70)
print("TRYING PACKET NUMBER ORDER")
print("=" * 70)

http_packets.sort(key=lambda x: x[1])  # Sort by packet index
paths_pkt_order = [path for _, _, path in http_packets]
concat_pkt = ''.join(paths_pkt_order)

print(f"Packet order concatenation: {len(concat_pkt)} chars")
print(f"First 100: {concat_pkt[:100]}")

if concat_pkt == concat_chrono:
    print("⚠ Packet order same as chronological!")
else:
    print("✓ Different from chronological order")
    
    # Try base32 decode
    concat_upper = concat_pkt.upper()
    padding = (8 - len(concat_upper) % 8) % 8
    concat_padded = concat_upper + '=' * padding
    
    try:
        decoded_pkt = base64.b32decode(concat_padded)
        print(f"\nBase32 decoded (packet order): {len(decoded_pkt)} bytes")
        print(f"Hex: {decoded_pkt[:32].hex()}")
        
        if b'DeepSec{' in decoded_pkt:
            print(f"\n[+] FOUND FLAG: {decoded_pkt}")
        else:
            # Try simple XOR
            for key in range(256):
                result = bytes([b ^ key for b in decoded_pkt])
                if b'DeepSec{' in result:
                    print(f"\n[+] FOUND with XOR key {key}: {result}")
                    break
    except Exception as e:
        print(f"Base32 decode failed: {e}")

# Maybe we should look at IP addresses or ports?
print("\n" + "=" * 70)
print("SOURCE/DEST ANALYSIS")
print("=" * 70)

for ts, idx, path in http_packets[:5]:
    pkt = packets[idx]
    if pkt.haslayer('IP'):
        src = pkt['IP'].src
        dst = pkt['IP'].dst
        print(f"Packet #{idx}: {src} -> {dst}")
    if pkt.haslayer('TCP'):
        sport = pkt['TCP'].sport
        dport = pkt['TCP'].dport
        print(f"  Ports: {sport} -> {dport}")
