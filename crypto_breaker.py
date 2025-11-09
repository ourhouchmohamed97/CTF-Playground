#!/usr/bin/env python3
"""
Advanced cryptanalysis for PCAP challenge.
Tries multiple approaches including AES, frequency analysis, and pattern matching.
"""
from scapy.all import rdpcap
import base64
import hashlib
from itertools import cycle

# Read PCAP and extract HTTP paths
packets = rdpcap('capture.pcap')
paths = []
for pkt in packets:
    if pkt.haslayer('Raw'):
        payload = bytes(pkt['Raw'].load)
        if b'GET /' in payload and b' HTTP' in payload:
            try:
                start = payload.index(b'GET /') + 5
                end = payload.index(b' HTTP', start)
                path = payload[start:end].decode('ascii')
                paths.append(path)
            except:
                pass

# Decode base32
concat = ''.join(paths).upper()
padding = (8 - len(concat) % 8) % 8
decoded = base64.b32decode(concat + '=' * padding)

print(f"Decoded {len(decoded)} bytes from base32")
print(f"First 32 bytes (hex): {decoded[:32].hex()}")
print()

# Method 1: Try AES with common keys
print("=" * 70)
print("METHOD 1: Trying AES decryption with common keys")
print("=" * 70)

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

common_keys = [
    b'DeepSec' + b'\x00' * 10,  # 16 bytes
    b'CTF' + b'\x00' * 13,
    b'capture.pcap\x00\x00\x00\x00',
    b'1234567890123456',
    b'ABCDEFGHIJKLMNOP',
    hashlib.md5(b'DeepSec').digest(),
    hashlib.md5(b'capture').digest(),
    hashlib.md5(b'pcap').digest(),
    hashlib.md5(b'flag').digest(),
]

for key in common_keys:
    for mode_name, mode in [('ECB', AES.MODE_ECB), ('CBC', AES.MODE_CBC)]:
        try:
            if mode == AES.MODE_ECB:
                cipher = AES.new(key, mode)
                decrypted = cipher.decrypt(decoded[:len(decoded) - len(decoded) % 16])
            else:
                # Try with zero IV
                cipher = AES.new(key, mode, iv=b'\x00' * 16)
                decrypted = cipher.decrypt(decoded[:len(decoded) - len(decoded) % 16])
            
            if b'DeepSec{' in decrypted or b'FLAG{' in decrypted or b'CTF{' in decrypted:
                print(f"[+] FOUND with AES-{mode_name}, key={key.hex()}: {decrypted}")
            
            # Also check if it's mostly printable ASCII
            printable = sum(32 <= b < 127 for b in decrypted)
            if printable > len(decrypted) * 0.7:
                print(f"[?] Possible match with AES-{mode_name}, key={key[:16].hex()}: {decrypted[:100]}")
        except Exception as e:
            pass

# Method 2: Try treating the data as already partially correct
print("\n" + "=" * 70)
print("METHOD 2: Pattern search in decoded data")
print("=" * 70)

# Search for any substring that looks like it could be part of a flag
for i in range(len(decoded) - 10):
    chunk = decoded[i:i+10]
    # Check if it's mostly printable
    printable_count = sum(32 <= b < 127 for b in chunk)
    if printable_count >= 8:
        print(f"Offset {i}: {chunk}")

# Method 3: Try XOR with MD5/SHA hashes of common strings
print("\n" + "=" * 70)
print("METHOD 3: XOR with hashed keys")
print("=" * 70)

hash_bases = [
    'DeepSec', 'capture', 'pcap', 'flag', 'CTF', 'network', 
    'example.net', 'http', 'base32', '2024', '2023'
]

for base in hash_bases:
    # Try MD5 hash as key
    key = hashlib.md5(base.encode()).digest()
    result = bytes([decoded[i] ^ key[i % len(key)] for i in range(len(decoded))])
    if b'DeepSec{' in result:
        print(f"[+] FOUND with MD5({base}): {result}")
    
    # Try SHA1 hash as key
    key = hashlib.sha1(base.encode()).digest()
    result = bytes([decoded[i] ^ key[i % len(key)] for i in range(len(decoded))])
    if b'DeepSec{' in result:
        print(f"[+] FOUND with SHA1({base}): {result}")

# Method 4: Try RC4 with common keys
print("\n" + "=" * 70)
print("METHOD 4: Trying RC4 decryption")
print("=" * 70)

from Crypto.Cipher import ARC4

rc4_keys = [
    b'DeepSec', b'CTF', b'capture', b'pcap', b'flag', 
    b'key', b'password', b'secret', b'example.net', b'network',
    b'wireshark', b'packet', b'http', b'base32'
]

for key in rc4_keys:
    cipher = ARC4.new(key)
    decrypted = cipher.decrypt(decoded)
    if b'DeepSec{' in decrypted or b'FLAG{' in decrypted or b'CTF{' in decrypted:
        print(f"[+] FOUND with RC4, key={key}: {decrypted}")
    
    # Check if mostly printable
    printable = sum(32 <= b < 127 for b in decrypted)
    if printable > len(decrypted) * 0.7:
        print(f"[?] Possible RC4 match, key={key}: {decrypted[:100]}")

# Method 5: Try interpreting bytes differently
print("\n" + "=" * 70)
print("METHOD 5: Alternative interpretations")
print("=" * 70)

# Try base64 decode of the base32 result
try:
    base64_decoded = base64.b64decode(decoded)
    print(f"Base64 decode result ({len(base64_decoded)} bytes): {base64_decoded[:50]}")
    if b'DeepSec{' in base64_decoded:
        print(f"[+] FOUND in base64: {base64_decoded}")
except:
    print("Base64 decode failed")

# Try hex decode
try:
    hex_decoded = bytes.fromhex(decoded.decode('ascii', errors='ignore'))
    print(f"Hex decode result ({len(hex_decoded)} bytes): {hex_decoded[:50]}")
    if b'DeepSec{' in hex_decoded:
        print(f"[+] FOUND in hex: {hex_decoded}")
except:
    print("Hex decode failed")

# Method 6: Frequency analysis to guess key length
print("\n" + "=" * 70)
print("METHOD 6: Frequency analysis for key length detection")
print("=" * 70)

# Test key lengths from 1 to 50
for keylen in range(2, 51):
    # For each position in the key, collect bytes
    columns = [[] for _ in range(keylen)]
    for i, byte in enumerate(decoded):
        columns[i % keylen].append(byte)
    
    # Calculate variance for each column
    variances = []
    for col in columns:
        if len(col) > 1:
            mean = sum(col) / len(col)
            variance = sum((b - mean) ** 2 for b in col) / len(col)
            variances.append(variance)
    
    if variances:
        avg_variance = sum(variances) / len(variances)
        # Low variance might indicate repeating key
        if avg_variance < 100:  # Threshold for low variance
            print(f"Key length {keylen}: avg variance = {avg_variance:.2f}")
            
            # Try to brute force the key for this length
            if keylen <= 4:
                print(f"  Attempting brute force for key length {keylen}...")

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"Total bytes analyzed: {len(decoded)}")
print(f"Hex preview: {decoded[:64].hex()}")
print("\nIf no flag found, the encryption may require a specific key from the challenge description")
print("or use an uncommon cipher algorithm.")
