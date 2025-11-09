#!/usr/bin/env python3
"""
KeyForge CTF Challenge Solver

This binary validates a 36-character license key with the format:
DeepSec{XXXXXXXXXXXXXXXXXXXXXXXXXXX}

The key is validated through 4 different algorithms on different segments.
"""

import struct
import string
from itertools import product

# ============================================================================
# Extracted Constants
# ============================================================================

TARGET_40567A = 0x6a0983129d2a  # Rolling XOR check
TARGET_4056DA = 0x2ca413b2      # FNV-1a hash
TARGET_40574A = 0x61227b3b      # Complex arithmetic  
TARGET_4057FA = 0  # S-box substitution (need to find or brute-force)

SBOX = bytes.fromhex('123456789abcdef01122334455667788')

# ============================================================================
# Helper Functions
# ============================================================================

def rol_byte(val, shift):
    """Rotate left for 8-bit value"""
    val &= 0xFF
    shift %= 8
    return ((val << shift) | (val >> (8 - shift))) & 0xFF

def rol_dword(val, shift):
    """Rotate left for 32-bit value"""
    val &= 0xFFFFFFFF
    shift %= 32
    return ((val << shift) | (val >> (32 - shift))) & 0xFFFFFFFF

# ============================================================================
# Validation Functions (Reverse Engineered)
# ============================================================================

def check_40567a(data):
    """
    Rolling XOR check on bytes 8-12 (5 bytes after 'DeepSec{')
    Algorithm:
      rsi_1 = 0x42
      rax = 0
      for each byte:
          rsi_1 = ROL(rsi_1, 1)
          rax = byte ^ rsi_1 ^ (rax << 8)
      return rax == TARGET_40567A
    """
    rsi = 0x42
    rax = 0
    
    for byte in data:
        rsi = rol_byte(rsi, 1)
        rax = byte ^ rsi ^ ((rax << 8) & 0xFFFFFFFFFFFF)
    
    return rax == TARGET_40567A

def check_4056da(data):
    """
    FNV-1a hash on bytes 13-18 (6 bytes)
    Algorithm:
      hash = 0x811c9dc5  (FNV offset basis)
      for each byte:
          hash = (hash ^ byte) * 0x1000193
      return hash == TARGET_4056DA
    """
    hash_val = 0x811c9dc5  # FNV-1a offset basis (32-bit)
    
    for byte in data:
        hash_val = ((hash_val ^ byte) * 0x1000193) & 0xFFFFFFFF
    
    return hash_val == TARGET_4056DA

def check_40574a(data):
    """
    Complex arithmetic on bytes 19-24 (6 bytes)
    Algorithm:
      sum = 0
      product = 1
      xor_val = 0
      for each byte:
          sum += byte
          product = (product * byte) % 0xFFFF
          xor_val ^= byte
      result = ((sum + product) ^ xor_val) + 0x5555
      return result == TARGET_40574A
    """
    sum_val = 0
    product = 1
    xor_val = 0
    
    for byte in data:
        sum_val += byte
        product = (product * byte) % 0xFFFF
        xor_val ^= byte
    
    result = ((sum_val + product) ^ xor_val) + 0x5555
    return result == TARGET_40574A

def check_4057fa(data):
    """
    S-box substitution on bytes 25-34 (10 bytes)
    This is complex - for now return True to skip
    """
    # Complex S-box operation - would need to reverse or brute-force
    return True  # Skip for now

# ============================================================================
# Brute Force Solvers for Each Segment
# ============================================================================

def solve_segment_40567a():
    """Brute force 5 characters for the rolling XOR check"""
    print("[+] Solving segment 8-12 (Rolling XOR)...")
    
    charset = string.ascii_letters + string.digits + '_'
    
    # Try common patterns first
    common_words = ['l1c3n', 'k3yg3', 'cr4ck', 'h4ck3', 'c0d3_']
    
    for word in common_words:
        if len(word) == 5 and check_40567a(word.encode()):
            print(f"  Found: {word}")
            return word
    
    # Full brute force (this could take a while for 5 chars)
    print("  Trying brute force...")
    from itertools import product
    
    # Start with shorter patterns and build up
    for chars in product(charset, repeat=5):
        test = ''.join(chars)
        if check_40567a(test.encode()):
            print(f"  Found: {test}")
            return test
    
    print("  [!] Not found")
    return None

def solve_segment_4056da():
    """Brute force or reverse FNV hash for 6 characters"""
    print("[+] Solving segment 13-18 (FNV-1a hash)...")
    
    # FNV hashes are one-way, but with small input space we can brute force
    charset = string.ascii_letters + string.digits + '_'
    
    # Try common patterns
    common = ['v3rs10', 'gen3r8', 'c0d1ng', 'r3v3rs']
    
    for word in common:
        if len(word) == 6 and check_4056da(word.encode()):
            print(f"  Found: {word}")
            return word
    
    print("  Trying brute force...")
    # This is computationally expensive for 6 chars
    # Limit search space or use rainbow table
    
    return None  # Placeholder

def solve_segment_40574a():
    """Solve the arithmetic constraint for 6 characters"""
    print("[+] Solving segment 19-24 (Arithmetic)...")
    
    charset = string.ascii_letters + string.digits + '_'
    
    # Try patterns
    for chars in product(charset, repeat=6):
        test = ''.join(chars)
        if check_40574a(test.encode()):
            print(f"  Found: {test}")
            return test
    
    return None

# ============================================================================
# Main Solver
# ============================================================================

def main():
    print("=" * 70)
    print("KeyForge License Key Solver")
    print("=" * 70)
    
    # Flag structure: DeepSec{XXXXXXXXXXXXXXXXXXXXXXXXXXX}
    # Total: 36 chars
    # Prefix: DeepSec{ (8 chars)
    # Suffix: } (1 char)
    # Middle: 27 chars split into segments
    
    print("\nFlag structure:")
    print("  DeepSec{[8-12][13-18][19-24][25-34]}")
    print("          ^^^^^ ^^^^^^ ^^^^^^ ^^^^^^^^^^")
    print("          5ch   6ch    6ch    10ch")
    print()
    
    # For now, let's try a smart approach:
    # Test with known patterns or dictionary
    
    # Based on the strings in the binary, try variations
    test_keys = [
        "DeepSec{l1c3ns3_v3rs10n_1s_v4l1d_n0w}",
        "DeepSec{k3y_g3n3r4t10n_1s_fun_h3r3!}",
        "DeepSec{r3v3rs3_3ng1n33r1ng_m4st3r}",
    ]
    
    print("[+] Testing known patterns...")
    for key in test_keys:
        if len(key) == 36:
            seg1 = key[8:13].encode()
            seg2 = key[13:19].encode()
            seg3 = key[19:25].encode()
            
            results = [
                check_40567a(seg1),
                check_4056da(seg2),
                check_40574a(seg3),
            ]
            
            if all(results):
                print(f"\n[SUCCESS] Found key: {key}")
                return key
            elif any(results):
                print(f"  Partial match: {key} - {results}")
    
    print("\n[+] Attempting segment-by-segment solve...")
    
    # Try to solve each segment
    seg1 = solve_segment_40567a()
    # seg2 = solve_segment_4056da()  # Too expensive
    # seg3 = solve_segment_40574a()  # Too expensive
    
    print("\n[!] Full brute force would take too long.")
    print("[!] Recommendation: Use a hybrid approach or more targeted search")
    
    return None

if __name__ == "__main__":
    main()
