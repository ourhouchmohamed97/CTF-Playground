#!/usr/bin/env python3
"""
Advanced PCAP flag extractor - try various decoding methods
"""

from scapy.all import *
import base64

def try_all_methods():
    packets = rdpcap('capture.pcap')
    
    # Method 1: Extract from HTTP GET paths and decode with rolling XOR
    print("="*70)
    print("Method 1: Base32 + Rolling XOR")
    print("="*70)
    
    paths = []
    for pkt in packets:
        if TCP in pkt and Raw in pkt:
            payload = bytes(pkt[Raw].load)
            if b'GET /' in payload and b'example.net' in payload:
                try:
                    start = payload.find(b'GET /') + 5
                    end = payload.find(b' HTTP', start)
                    path = payload[start:end].decode()
                    paths.append(path)
                except:
                    pass
    
    concat = ''.join(paths).upper()
    padding = (8 - len(concat) % 8) % 8
    decoded = base64.b32decode(concat + '=' * padding)
    
    # Try rolling XOR with different start keys
    for start_key in [0x00, 0x42, 0x99, 0xAA, 0xFF]:
        key = start_key
        result = bytearray()
        for b in decoded:
            result.append(b ^ key)
            key = (key + 1) % 256
        
        if b'DeepSec{' in result:
            idx = result.find(b'DeepSec{')
            end = result.find(b'}', idx)
            if end != -1:
                flag = result[idx:end+1].decode()
                print(f"\n[+] FOUND with rolling XOR (start={start_key:#x}): {flag}")
                return flag
    
    # Method 2: XOR with packet-based key
    print("\n" + "="*70)
    print("Method 2: Packet sequence XOR")
    print("="*70)
    
    result = bytearray(decoded)
    for i, b in enumerate(decoded):
        result[i] = b ^ (i % 256)
    
    if b'DeepSec{' in result:
        idx = result.find(b'DeepSec{')
        end = result.find(b'}', idx)
        if end != -1:
            flag = result[idx:end+1].decode()
            print(f"\n[+] FOUND: {flag}")
            return flag
    
    # Method 3: Multi-byte key XOR
    print("\n" + "="*70)
    print("Method 3: Multi-byte key XOR")
    print("="*70)
    
    common_keys = [b'DeepSec', b'CTF', b'flag', b'key', b'password', b'secret']
    for key in common_keys:
        result = bytearray()
        for i, b in enumerate(decoded):
            result.append(b ^ key[i % len(key)])
        
        if b'DeepSec{' in result:
            idx = result.find(b'DeepSec{')
            end = result.find(b'}', idx)
            if end != -1:
                flag = result[idx:end+1].decode()
                print(f"\n[+] FOUND with key {key}: {flag}")
                return flag
    
    print("\n[-] Flag not found with standard methods")
    print(f"\nDecoded data sample (first 200 bytes as hex):")
    print(decoded[:200].hex())
    
    return None

if __name__ == "__main__":
    try_all_methods()
