#!/usr/bin/env python3
"""
Extract and decode flag from PCAP HTTP requests
"""

from scapy.all import *
import base64

def extract_http_paths(filename):
    print("="*70)
    print("PCAP HTTP Path Extractor")
    print("="*70)
    
    packets = rdpcap(filename)
    
    # Extract all HTTP GET paths
    http_paths = []
    
    for pkt in packets:
        if TCP in pkt and Raw in pkt:
            payload = bytes(pkt[Raw].load)
            if b'GET /' in payload and b'example.net' in payload:
                # Extract the path
                try:
                    start = payload.find(b'GET /') + 5
                    end = payload.find(b' HTTP', start)
                    path = payload[start:end].decode()
                    http_paths.append(path)
                except:
                    pass
    
    print(f"\n[+] Found {len(http_paths)} HTTP GET requests")
    print("\nPaths:")
    for i, path in enumerate(http_paths):
        print(f"  [{i:2d}] {path}")
    
    # Try to decode as base32
    print("\n[*] Attempting Base32 decode of concatenated paths...")
    concatenated = ''.join(http_paths)
    print(f"Concatenated length: {len(concatenated)}")
    print(f"First 100 chars: {concatenated[:100]}")
    
    try:
        # Try base32 decode with padding
        concat_upper = concatenated.upper()
        # Add padding if needed
        padding_needed = (8 - len(concat_upper) % 8) % 8
        concat_padded = concat_upper + '=' * padding_needed
        
        decoded = base64.b32decode(concat_padded)
        print(f"\n[+] Base32 decoded (with padding):")
        print(f"  Hex: {decoded.hex()}")
        print(f"  ASCII: {decoded.decode(errors='ignore')}")
        
        if b'DeepSec{' in decoded or b'FLAG{' in decoded or b'CTF{' in decoded:
            print(f"\n{'='*70}")
            print(f"FLAG FOUND: {decoded.decode(errors='ignore')}")
            print(f"{'='*70}")
    except Exception as e:
        print(f"[-] Base32 decode failed: {e}")
    
    # Try other encodings
    print("\n[*] Trying other encoding schemes...")
    
    # Try hex
    try:
        hex_str = ''.join(http_paths)
        decoded = bytes.fromhex(hex_str)
        print(f"\n[+] Hex decoded: {decoded.decode(errors='ignore')[:100]}")
    except:
        print("[-] Not valid hex")
    
    # Try base64
    try:
        decoded = base64.b64decode(concatenated)
        print(f"\n[+] Base64 decoded: {decoded.decode(errors='ignore')[:100]}")
    except:
        print("[-] Not valid base64")
    
    # Check if it's already the flag
    if 'DeepSec{' in concatenated or 'FLAG{' in concatenated:
        print(f"\n{'='*70}")
        print(f"FLAG IN PATHS: {concatenated}")
        print(f"{'='*70}")
    
    return http_paths

if __name__ == "__main__":
    extract_http_paths("capture.pcap")
