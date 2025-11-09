#!/usr/bin/env python3
"""
Direct constraint solver for KeyForge using manual reverse engineering
This approach manually solves each validation check
"""

import subprocess
import string
from itertools import product

# Validation targets extracted from binary
TARGET_40567A = 0x6a0983129d2a  
TARGET_4056DA = 0x2ca413b2     
TARGET_40574A = 0x61227b3b

def rol_byte(val, shift=1):
    """Rotate left 8-bit value"""
    val &= 0xFF
    return ((val << shift) | (val >> (8 - shift))) & 0xFF

def validate_seg1(chars):
    """Segment 1: Rolling XOR (bytes 8-12, 5 chars)"""
    data = chars.encode() if isinstance(chars, str) else chars
    rsi = 0x42
    rax = 0
    
    for byte in data:
        rsi = rol_byte(rsi, 1)
        rax = byte ^ rsi ^ ((rax << 8) & 0xFFFFFFFFFFFF)
    
    return rax == TARGET_40567A

def validate_seg2(chars):
    """Segment 2: FNV-1a hash (bytes 13-18, 6 chars)"""
    data = chars.encode() if isinstance(chars, str) else chars
    hash_val = 0x811c9dc5
    
    for byte in data:
        hash_val = ((hash_val ^ byte) * 0x1000193) & 0xFFFFFFFF
    
    return hash_val == TARGET_4056DA

def validate_seg3(chars):
    """Segment 3: Arithmetic (bytes 19-24, 6 chars)"""
    data = chars.encode() if isinstance(chars, str) else chars
    sum_val = 0
    product = 1
    xor_val = 0
    
    for byte in data:
        sum_val += byte
        product = (product * byte) % 0xFFFF
        xor_val ^= byte
    
    result = ((sum_val + product) ^ xor_val) + 0x5555
    return result == TARGET_40574A

def test_flag_with_binary(flag):
    """Test a candidate flag with the actual binary"""
    try:
        result = subprocess.run(
            ['./KeyForge_unpacked'],
            input=flag.encode(),
            capture_output=True,
            timeout=2,
            cwd='/workspaces/CTF-Playground'
        )
        output = result.stdout.decode(errors='replace').lower()
        
        # Check for success
        if 'valid!' in output or ('valid' in output and 'failed' not in output):
            return True, output
        return False, output
    except Exception as e:
        return False, str(e)

def smart_search_segment(length, validator, name, max_attempts=10000000):
    """Smart search with common patterns and partial brute force"""
    print(f"\n[+] Searching for {name} ({length} chars)...")
    
    # Character set: lowercase, digits, underscore (most common in CTF flags)
    charset = string.ascii_lowercase + string.digits + '_'
    
    # Try common dictionary words first
    if length == 5:
        patterns = [
            'l1c3n', 'v4l1d', 'ch3ck', 'cr4ck', 'h4ck_',
            'p4ss_', 'k3y_g', 'fl4g_', 'c0d3_', 'b1n4r',
            '3ng1n', 't3st_', 'pr00f', 'm4st3', 'us3r_'
        ]
    elif length == 6:
        patterns = [
            'v3rs10', 'l1c3ns', 'v4l1d8', 'ch3ck3', 'cr4ck3',
            'h4ck3r', 'p4ss3d', 'k3yg3n', 'c0d1ng', 'r3v3rs',
            'm4st3r', 'syst3m', 'b1n4ry', 't3st1n', 'pr00f_'
        ]
    else:
        patterns = []
    
    # Test patterns
    for pattern in patterns:
        if validator(pattern):
            print(f"  ✓ Found: '{pattern}'")
            return pattern
    
    # Progressive brute force with progress reporting
    print(f"  Brute forcing... (max {max_attempts:,} attempts)")
    tested = 0
    
    for combo in product(charset, repeat=length):
        test = ''.join(combo)
        
        if validator(test):
            print(f"  ✓ Found: '{test}' (after {tested:,} attempts)")
            return test
        
        tested += 1
        if tested >= max_attempts:
            print(f"  ✗ Stopped after {tested:,} attempts")
            break
        
        if tested % 100000 == 0:
            print(f"    Progress: {tested:,} attempts...")
    
    print(f"  ✗ Not found")
    return None

def main():
    print("="*70)
    print("KeyForge Manual Constraint Solver")
    print("="*70)
    
    # Solve each segment
    print("\n[*] Solving segments individually...")
    
    seg1 = smart_search_segment(5, validate_seg1, "Segment 1 (Rolling XOR)", max_attempts=500000)
    
    if not seg1:
        print("\n[!] Could not solve Segment 1. Trying with expanded charset...")
        # Try with uppercase too
        charset = string.ascii_letters + string.digits + '_'
        tested = 0
        for combo in product(charset, repeat=5):
            test = ''.join(combo)
            if validate_seg1(test):
                seg1 = test
                print(f"  ✓ Found: '{seg1}'")
                break
            tested += 1
            if tested >= 1000000:
                break
    
    seg2 = smart_search_segment(6, validate_seg2, "Segment 2 (FNV-1a)", max_attempts=500000)
    seg3 = smart_search_segment(6, validate_seg3, "Segment 3 (Arithmetic)", max_attempts=500000)
    
    # Display results
    print("\n" + "="*70)
    print("Results:")
    print("="*70)
    print(f"Segment 1 (bytes 8-12):  {seg1 or 'NOT FOUND'}")
    print(f"Segment 2 (bytes 13-18): {seg2 or 'NOT FOUND'}")
    print(f"Segment 3 (bytes 19-24): {seg3 or 'NOT FOUND'}")
    
    if seg1 and seg2 and seg3:
        # Try to find segment 4 by testing with binary
        print(f"\n[+] Found 3/4 segments! Testing possible combinations for segment 4...")
        
        # Common 10-character endings
        seg4_candidates = [
            '1234567890',
            '_h3r3_n0w_',
            '_1s_fun!!!',
            '_cr4ck3d!!',
            '0123456789',
            'abcdefghij',
            'test123456',
            '_l33t_h4x_',
            '_v4l1d_k3y',
            '!@#$%^&*()',
        ]
        
        for seg4_try in seg4_candidates:
            if len(seg4_try) != 10:
                continue
            
            # Last char before } is at position 34 (0-indexed)
            # So segment 4 is 10 chars but the last one is before the }
            flag = f"DeepSec{{{seg1}{seg2}{seg3}{seg4_try[:-1]}}}"
            
            if len(flag) == 36:
                print(f"\n  Testing: {flag}")
                success, output = test_flag_with_binary(flag)
                
                if success:
                    print(f"\n{'='*70}")
                    print(f"🎉 SUCCESS! FLAG FOUND: {flag}")
                    print(f"{'='*70}")
                    print(f"\nBinary output:\n{output}")
                    return flag
                else:
                    print(f"    Failed: {output[:50]}")
        
        print(f"\n[!] None of the common patterns worked for segment 4")
        print(f"[!] Partial flag: DeepSec{{{seg1}{seg2}{seg3}XXXXXXXXX}}")
    else:
        print("\n[!] Could not solve all segments")
        print("[!] Try running with more attempts or different character sets")

if __name__ == "__main__":
    main()
