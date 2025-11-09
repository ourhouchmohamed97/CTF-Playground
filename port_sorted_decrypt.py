#!/usr/bin/env python3
"""
Test XOR on port-sorted data - this looks promising!
"""
from scapy.all import rdpcap
import base64

packets = rdpcap('capture.pcap')

# Extract HTTP packets with ports
http_data = []
for i, pkt in enumerate(packets):
    if pkt.haslayer('Raw'):
        payload = bytes(pkt['Raw'].load)
        if b'GET /' in payload and b' HTTP' in payload:
            try:
                start = payload.index(b'GET /') + 5
                end = payload.index(b' HTTP', start)
                path = payload[start:end].decode('ascii')
                src_port = pkt['TCP'].sport if pkt.haslayer('TCP') else 0
                http_data.append((src_port, path))
            except:
                pass

# Sort by source port
http_data.sort(key=lambda x: x[0])

print("Sorted by source port:")
for port, path in http_data:
    print(f"  Port {port:5d}: {path}")

# Concatenate paths
paths = [path for _, path in http_data]
concat = ''.join(paths).upper()
padding = (8 - len(concat) % 8) % 8
decoded = base64.b32decode(concat + '=' * padding)

print(f"\nDecoded {len(decoded)} bytes")
print(f"Hex: {decoded[:64].hex()}\n")

# Try ALL single-byte XOR keys
print("=" * 70)
print("BRUTE FORCE SINGLE-BYTE XOR")
print("=" * 70)

found = False
for key in range(256):
    result = bytes([b ^ key for b in decoded])
    
    if b'DeepSec{' in result or b'FLAG{' in result or b'CTF{' in result:
        print(f"\n[+] FOUND with XOR key {key} (0x{key:02x}):")
        print(result.decode('ascii', errors='ignore'))
        found = True
        break

if not found:
    print("No flag with single-byte XOR\n")

# Try multi-byte XOR
print("=" * 70)
print("MULTI-BYTE XOR")
print("=" * 70)

keys_to_try = [
    b'DeepSec', b'capture', b'pcap', b'CTF', b'FLAG', 
    b'port', b'sorted', b'order', b'key', b'password',
    b'example.net', b'http', b'network', b'wireshark'
]

for key in keys_to_try:
    result = bytes([decoded[i] ^ key[i % len(key)] for i in range(len(decoded))])
    if b'DeepSec{' in result or b'FLAG{' in result:
        print(f"\n[+] FOUND with key {key}:")
        print(result.decode('ascii', errors='ignore'))
        found = True
        break

# Try RC4
print("\n" + "=" * 70)
print("RC4 DECRYPTION")
print("=" * 70)

try:
    from Crypto.Cipher import ARC4
    
    rc4_keys = [b'port', b'sorted', b'capture', b'DeepSec', b'pcap']
    
    for key in rc4_keys:
        cipher = ARC4.new(key)
        result = cipher.decrypt(decoded)
        if b'DeepSec{' in result or b'FLAG{' in result:
            print(f"\n[+] FOUND with RC4 key {key}:")
            print(result.decode('ascii', errors='ignore'))
            found = True
            break
except:
    pass

# Try AES
print("\n" + "=" * 70)
print("AES DECRYPTION")
print("=" * 70)

try:
    from Crypto.Cipher import AES
    import hashlib
    
    aes_key_bases = ['port', 'sorted', 'capture', 'DeepSec', 'pcap']
    
    for base in aes_key_bases:
        key = hashlib.md5(base.encode()).digest()  # 16 bytes for AES-128
        
        for mode_name, mode in [('ECB', AES.MODE_ECB), ('CBC', AES.MODE_CBC)]:
            try:
                if mode == AES.MODE_ECB:
                    cipher = AES.new(key, mode)
                else:
                    cipher = AES.new(key, mode, iv=b'\x00' * 16)
                
                decrypted = cipher.decrypt(decoded[:len(decoded) - len(decoded) % 16])
                
                if b'DeepSec{' in decrypted or b'FLAG{' in decrypted:
                    print(f"\n[+] FOUND with AES-{mode_name}, MD5('{base}'):")
                    print(decrypted.decode('ascii', errors='ignore'))
                    found = True
                    break
            except:
                pass
        
        if found:
            break
except:
    pass

if not found:
    print("\n[!] No flag found with standard methods")
    print("Trying direct ASCII interpretation...")
    
    # Check if it's partially readable
    printable = sum(32 <= b < 127 for b in decoded)
    print(f"\nPrintable bytes: {printable}/{len(decoded)} ({100*printable/len(decoded):.1f}%)")
    
    if printable > 50:
        print(f"\nDirect ASCII:")
        print(decoded.decode('ascii', errors='ignore'))
