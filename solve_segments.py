#!/usr/bin/env python3
"""
Segment-by-segment solver for KeyForge
Based on actual disassembly analysis
"""

import itertools
import string

# Constants from disassembly
TARGET_ROLLING_XOR = 0x61227b3b  # Bytes 8-12 (5 bytes)
TARGET_FNV1A = 0x2ca413b2  # Bytes 13-18 (6 bytes)
TARGET_ARITHMETIC = 0x6a09  # Bytes 19-24 (6 bytes) 
TARGET_SBOX = 0x83129d2a  # Bytes 25-34 (10 bytes)

def rolling_xor_check(data):
    """Rolling XOR validation for 5 bytes"""
    key = 0x42
    result = 0
    
    for byte_val in data:
        # ROL key by 1
        key = ((key << 1) | (key >> 7)) & 0xFF
        
        # XOR byte with key
        xored = byte_val ^ key
        
        # Shift result left 8 bits and XOR
        result = ((result << 8) | xored) & 0xFFFFFFFFFFFFFFFF
    
    return result == TARGET_ROLLING_XOR

def fnv1a_hash(data):
    """FNV-1a hash"""
    hash_val = 0x811c9dc5
    prime = 0x1000193
    
    for byte_val in data:
        hash_val ^= byte_val
        hash_val = (hash_val * prime) & 0xFFFFFFFF
    
    return hash_val

def fnv1a_check(data):
    """Check FNV-1a hash for 6 bytes"""
    return fnv1a_hash(data) == TARGET_FNV1A

def arithmetic_check(data):
    """Arithmetic validation for 6 bytes"""
    prod = 1
    sum_val = 0
    xor_val = 0
    
    for byte_val in data:
        prod = (prod * byte_val) & 0xFFFF  # Modulo 65537
        sum_val += byte_val
        xor_val ^= byte_val
    
    final = ((sum_val + prod) ^ xor_val + 0x5555) & 0xFFFF
    return final == TARGET_ARITHMETIC

def sbox_check(data):
    """S-box transformation for 10 bytes"""
    sbox = [ord(c) for c in "123456789abcdef0"]
    
    state = 0xabcdef00
    
    for byte_val in data:
        high_nibble = (byte_val >> 4) & 0x0F
        low_nibble = byte_val & 0x0F
        
        low_val = sbox[low_nibble]
        high_val = sbox[high_nibble]
        
        # state = ROL((low_val + state), 3) ^ high_val
        temp = (low_val + state) & 0xFFFFFFFF
        rotated = ((temp << 3) | (temp >> 29)) & 0xFFFFFFFF
        state = rotated ^ high_val
    
    return state == TARGET_SBOX

# Character sets to try
CHARSET = string.ascii_letters + string.digits + '_-!'

print("[*] KeyForge Segment Solver")
print("="*60)

# SEGMENT 1: Bytes 8-12 (5 bytes) - Rolling XOR
print("\n[*] Solving segment 1: Bytes 8-12 (Rolling XOR)")
print(f"    Target: 0x{TARGET_ROLLING_XOR:x}")

found_seg1 = None
count = 0
for combo in itertools.product(CHARSET, repeat=5):
    test_bytes = bytes([ord(c) for c in combo])
    if rolling_xor_check(test_bytes):
        found_seg1 = ''.join(combo)
        print(f"[+] FOUND Segment 1: '{found_seg1}'")
        break
    count += 1
    if count % 100000 == 0:
        print(f"    Tested {count} combinations...")
    if count > 5000000:
        print(f"[!] Stopping after {count} attempts")
        break

if not found_seg1:
    print("[!] Could not find segment 1")
    print("[*] Trying with lowercase only...")
    count = 0
    for combo in itertools.product(string.ascii_lowercase, repeat=5):
        test_bytes = bytes([ord(c) for c in combo])
        if rolling_xor_check(test_bytes):
            found_seg1 = ''.join(combo)
            print(f"[+] FOUND Segment 1: '{found_seg1}'")
            break
        count += 1
        if count % 50000 == 0:
            print(f"    Tested {count} combinations...")

# SEGMENT 2: Bytes 13-18 (6 bytes) - FNV-1a
print("\n[*] Solving segment 2: Bytes 13-18 (FNV-1a hash)")
print(f"    Target: 0x{TARGET_FNV1A:08x}")

found_seg2 = None
count = 0

# Try common patterns first
patterns = ["Secur3", "K3yF0r", "Licens", "Passw0", "Secret"]
for pattern in patterns:
    test_bytes = bytes(pattern, 'ascii')
    if fnv1a_check(test_bytes):
        found_seg2 = pattern
        print(f"[+] FOUND Segment 2: '{found_seg2}'")
        break

if not found_seg2:
    print("[*] Patterns didn't work, trying brute force...")
    for length in range(4, 7):
        print(f"    Trying {length}-char combinations...")
        for combo in itertools.product(CHARSET[:20], repeat=length):  # Limited charset
            test_str = ''.join(combo)
            if len(test_str) < 6:
                test_str += '_' * (6 - len(test_str))
            test_bytes = bytes(test_str[:6], 'ascii')
            
            if fnv1a_check(test_bytes):
                found_seg2 = test_str[:6]
                print(f"[+] FOUND Segment 2: '{found_seg2}'")
                break
            
            count += 1
            if count % 50000 == 0:
                print(f"    Tested {count} combinations...")
            if count > 1000000:
                break
        if found_seg2:
            break

if not found_seg2:
    print("[!] Could not find segment 2")

print("\n" + "="*60)
print("[*] Results:")
print(f"    Segment 1 (bytes 8-12):  {found_seg1 or 'NOT FOUND'}")
print(f"    Segment 2 (bytes 13-18): {found_seg2 or 'NOT FOUND'}")

if found_seg1 and found_seg2:
    partial_flag = f"DeepSec{{{found_seg1}{found_seg2}"
    print(f"\n[*] Partial flag so far: {partial_flag}...}}")
