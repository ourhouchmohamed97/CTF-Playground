#!/usr/bin/env python3
"""
Deep analysis of PCAP - check ICMP and other protocols for hidden data
"""

from scapy.all import *
import binascii

def deep_analyze(filename):
    print("="*70)
    print("Deep PCAP Analysis - ICMP and Hidden Channels")
    print("="*70)
    
    packets = rdpcap(filename)
    
    # Analyze ICMP packets specifically
    print("\n[*] Analyzing ICMP packets...")
    icmp_data = []
    
    for i, pkt in enumerate(packets):
        if ICMP in pkt:
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
                icmp_data.append({
                    'index': i,
                    'type': pkt[ICMP].type,
                    'code': pkt[ICMP].code,
                    'data': payload
                })
    
    print(f"[+] Found {len(icmp_data)} ICMP packets with payload")
    
    if icmp_data:
        # Concatenate all ICMP payloads
        all_icmp = b''.join([p['data'] for p in icmp_data])
        print(f"\n[*] Total ICMP payload: {len(all_icmp)} bytes")
        print(f"Hex: {all_icmp[:100].hex()}")
        print(f"ASCII: {''.join(chr(b) if 32 <= b <= 126 else '.' for b in all_icmp[:100])}")
        
        # Check for flag
        if b'DeepSec{' in all_icmp or b'FLAG{' in all_icmp:
            print(f"\n[!] FLAG IN ICMP:")
            idx = all_icmp.find(b'DeepSec{') if b'DeepSec{' in all_icmp else all_icmp.find(b'FLAG{')
            flag_end = all_icmp.find(b'}', idx)
            if flag_end != -1:
                flag = all_icmp[idx:flag_end+1]
                print(f"\n{'='*70}")
                print(f"FLAG: {flag.decode()}")
                print(f"{'='*70}")
                return flag.decode()
    
    # Check UDP packets
    print("\n[*] Analyzing UDP packets...")
    udp_data = []
    
    for pkt in packets:
        if UDP in pkt and Raw in pkt:
            payload = bytes(pkt[Raw].load)
            udp_data.append(payload)
    
    if udp_data:
        all_udp = b''.join(udp_data)
        print(f"[+] Found {len(udp_data)} UDP packets with payload")
        print(f"Total UDP payload: {len(all_udp)} bytes")
        
        if b'DeepSec{' in all_udp or b'FLAG{' in all_udp:
            print(f"\n[!] FLAG IN UDP:")
            idx = all_udp.find(b'DeepSec{') if b'DeepSec{' in all_udp else all_udp.find(b'FLAG{')
            flag_end = all_udp.find(b'}', idx)
            if flag_end != -1:
                flag = all_udp[idx:flag_end+1]
                print(f"\n{'='*70}")
                print(f"FLAG: {flag.decode()}")
                print(f"{'='*70}")
                return flag.decode()
    
    # Check for DNS TXT records or unusual DNS
    print("\n[*] Analyzing DNS packets in detail...")
    for pkt in packets:
        if DNS in pkt:
            # Check answer section
            if pkt[DNS].an:
                for i in range(pkt[DNS].ancount):
                    answer = pkt[DNS].an[i]
                    if hasattr(answer, 'rdata'):
                        rdata = str(answer.rdata)
                        if 'DeepSec' in rdata or 'FLAG' in rdata:
                            print(f"[!] FLAG IN DNS: {rdata}")
            
            # Check additional/authority sections
            if pkt[DNS].ns:
                print(f"NS record: {pkt[DNS].ns}")
            if pkt[DNS].ar:
                print(f"AR record: {pkt[DNS].ar}")
    
    # Try extracting based on packet sequence
    print("\n[*] Checking for LSB or packet ordering...")
    
    # Extract first byte from each packet
    first_bytes = []
    for pkt in packets:
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            if len(payload) > 0:
                first_bytes.append(payload[0])
    
    if first_bytes:
        first_bytes_str = bytes(first_bytes)
        print(f"\nFirst bytes from packets: {first_bytes_str[:50]}")
        if b'DeepSec{' in first_bytes_str:
            idx = first_bytes_str.find(b'DeepSec{')
            flag_end = first_bytes_str.find(b'}', idx)
            if flag_end != -1:
                flag = first_bytes_str[idx:flag_end+1]
                print(f"\n{'='*70}")
                print(f"FLAG (from first bytes): {flag.decode()}")
                print(f"{'='*70}")
                return flag.decode()
    
    # Check packet sizes
    print("\n[*] Analyzing packet sizes...")
    packet_sizes = [len(pkt) for pkt in packets if Raw in pkt]
    print(f"Packet sizes (first 50): {packet_sizes[:50]}")
    
    # Convert sizes to ASCII if they're in printable range
    size_chars = ''.join([chr(s) if 32 <= s <= 126 else '.' for s in packet_sizes])
    print(f"As ASCII: {size_chars[:100]}")
    
    if 'DeepSec{' in size_chars or 'FLAG{' in size_chars:
        print(f"\n[!] FLAG IN PACKET SIZES: {size_chars}")
    
    return None

if __name__ == "__main__":
    deep_analyze("capture.pcap")
