#!/usr/bin/env python3
"""
PCAP Challenge Summary and Interactive Explorer

Based on analysis, the PCAP contains:
- 30 HTTP GET requests to example.net with base32-encoded paths
- The concatenated paths decode to 459 bytes of encrypted data
- The data doesn't decrypt with common XOR keys

Next steps to try:
1. The ARM decompiled code might contain a hint about the XOR algorithm
2. There might be a specific packet that contains the key
3. The encryption might use AES/RC4 instead of XOR
4. The DNS or other protocol data might contain the key
"""

from scapy.all import *
import base64

def explore_pcap():
    print("="*70)
    print("PCAP Interactive Explorer")
    print("="*70)
    
    packets = rdpcap('capture.pcap')
    
    # Get base32 decoded data
    paths = []
    for pkt in packets:
        if TCP in pkt and Raw in pkt:
            payload = bytes(pkt[Raw].load)
            if b'GET /' in payload and b'example.net' in payload:
                start = payload.find(b'GET /') + 5
                end = payload.find(b' HTTP', start)
                paths.append(payload[start:end].decode())
    
    concat = ''.join(paths).upper()
    padding = (8 - len(concat) % 8) % 8
    decoded = base64.b32decode(concat + '=' * padding)
    
    print(f"\n[*] Base32 decoded data: {len(decoded)} bytes")
    print(f"[*] Hex: {decoded[:50].hex()}...")
    
    # Save to file for external analysis
    with open('/tmp/pcap_decoded.bin', 'wb') as f:
        f.write(decoded)
    print(f"\n[*] Saved to /tmp/pcap_decoded.bin for analysis")
    
    # Interactive XOR tester
    print("\n" + "="*70)
    print("Interactive XOR Key Tester")
    print("="*70)
    print("\nEnter XOR keys to test (or 'quit' to exit):")
    print("Examples: 'test', '0x42', 'hex:41424344'\n")
    
    while True:
        try:
            user_input = input("XOR key> ").strip()
            if user_input.lower() in ['quit', 'exit', 'q']:
                break
            
            # Parse input
            if user_input.startswith('0x'):
                # Single byte hex
                key = bytes([int(user_input, 16)])
            elif user_input.startswith('hex:'):
                # Multi-byte hex
                key = bytes.fromhex(user_input[4:])
            else:
                # String
                key = user_input.encode()
            
            # XOR
            result = bytes([decoded[i] ^ key[i % len(key)] for i in range(len(decoded))])
            
            # Check for flag
            if b'DeepSec{' in result:
                idx = result.find(b'DeepSec{')
                end = result.find(b'}', idx)
                if end != -1:
                    print(f"\n[!!!] FLAG FOUND: {result[idx:end+1].decode()}\n")
                    return result[idx:end+1].decode()
            
            # Show preview
            printable = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in result[:100]])
            print(f"Result (first 100 chars): {printable}\n")
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e}\n")
    
    print("\nExiting explorer.")

if __name__ == "__main__":
    explore_pcap()
