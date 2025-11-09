#!/usr/bin/env python3
"""
KeyForge Hybrid Solver - Uses smart brute force with optimizations
"""

import string
from itertools import product
import multiprocessing as mp

# ============================================================================
# Extracted Constants
# ============================================================================

TARGET_40567A = 0x6a0983129d2a  
TARGET_4056DA = 0x2ca413b2     
TARGET_40574A = 0x61227b3b     

# ============================================================================
# Validation Functions
# ============================================================================

def rol_byte(val, shift):
    """Rotate left for 8-bit value"""
    val &= 0xFF
    shift %= 8
    return ((val << shift) | (val >> (8 - shift))) & 0xFF

def check_seg1(data):
    """Rolling XOR on 5 bytes"""
    rsi = 0x42
    rax = 0
    
    for byte in data:
        rsi = rol_byte(rsi, 1)
        rax = byte ^ rsi ^ ((rax << 8) & 0xFFFFFFFFFFFF)
    
    return rax == TARGET_40567A

def check_seg2(data):
    """FNV-1a hash on 6 bytes"""
    hash_val = 0x811c9dc5
    
    for byte in data:
        hash_val = ((hash_val ^ byte) * 0x1000193) & 0xFFFFFFFF
    
    return hash_val == TARGET_4056DA

def check_seg3(data):
    """Arithmetic on 6 bytes"""
    sum_val = 0
    product = 1
    xor_val = 0
    
    for byte in data:
        sum_val += byte
        product = (product * byte) % 0xFFFF
        xor_val ^= byte
    
    result = ((sum_val + product) ^ xor_val) + 0x5555
    return result == TARGET_40574A

# ============================================================================
# Smart Brute Force with Patterns
# ============================================================================

def solve_with_patterns(length, check_func, segment_name):
    """Try common patterns before full brute force"""
    print(f"[+] Solving {segment_name} ({length} chars)...")
    
    # Common CTF patterns
    patterns = []
    
    if length == 5:
        patterns = [
            'l1c3n', 'k3y_g', 'cr4ck', 'h4ck3', 'c0d3_',
            'p4ss_', 'fl4g_', 'r3v3r', 'b1n4r', '3ng1n',
            'v4l1d', 'ch3ck', 't3st_', 'd3bug'
        ]
    elif length == 6:
        patterns = [
            'v3rs10', 'gen3r8', 'c0d1ng', 'r3v3rs',
            'l1c3ns', 'v4l1d8', 'ch3ck3', 't3st1n',
            'cr4ck3', 'h4ck3r', 'p4ss3d', 'k3yg3n'
        ]
    
    # Try patterns first
    for pat in patterns:
        if check_func(pat.encode()):
            print(f"  ✓ Found with pattern: {pat}")
            return pat
    
    # Try with common substitutions
    leet_map = {'a':'4', 'e':'3', 'i':'1', 'o':'0', 's':'5', 't':'7'}
    
    # Try dictionary words with leet speak
    common_words = []
    if length == 5:
        common_words = ['valid', 'crack', 'check', 'admin', 'login']
    elif length == 6:
        common_words = ['master', 'system', 'binary', 'coding', 'hacker']
    
    for word in common_words:
        # Try as-is
        if len(word) == length and check_func(word.encode()):
            print(f"  ✓ Found: {word}")
            return word
        
        # Try with leet speak
        leet_word = ''.join(leet_map.get(c, c) for c in word)
        if len(leet_word) == length and check_func(leet_word.encode()):
            print(f"  ✓ Found: {leet_word}")
            return leet_word
    
    # Limited brute force with progress
    charset = string.ascii_lowercase + string.digits + '_'
    
    print(f"  Trying brute force (charset size: {len(charset)}, combinations: {len(charset)**length:,})...")
    
    # For length 5, that's 37^5 = ~69M - manageable
    # For length 6, that's 37^6 = ~2.5B - will take a while
    
    tested = 0
    for combo in product(charset, repeat=length):
        test = ''.join(combo)
        if check_func(test.encode()):
            print(f"  ✓ Found: {test} (after {tested:,} attempts)")
            return test
        
        tested += 1
        if tested % 1000000 == 0:
            print(f"    Progress: {tested//(len(charset)**length)*100:.1f}% ({tested:,} tested)")
    
    print(f"  ✗ Not found after {tested:,} attempts")
    return None

def main():
    print("="*70)
    print("KeyForge Hybrid Solver")
    print("="*70)
    print()
    
    # Solve segments
    seg1 = solve_with_patterns(5, check_seg1, "Segment 1 (bytes 8-12)")
    seg2 = solve_with_patterns(6, check_seg2, "Segment 2 (bytes 13-18)")  
    seg3 = solve_with_patterns(6, check_seg3, "Segment 3 (bytes 19-24)")
    
    if seg1 and seg2 and seg3:
        print(f"\n{'='*70}")
        print(f"Solved 3/4 segments!")
        print(f"{'='*70}")
        print(f"Segment 1: {seg1}")
        print(f"Segment 2: {seg2}")
        print(f"Segment 3: {seg3}")
        print(f"\nPartial flag: DeepSec{{{seg1}{seg2}{seg3}XXXXXXXXXX}}")
        print(f"\n[!] Segment 4 (bytes 25-34, 10 chars) still needs solving")
        print(f"[!] This segment uses S-box substitution which is complex to reverse")
        
        # Try common endings
        endings = [
            '_h3r3_n0w}',
            '1234567890',
            '_1s_fun!!!',
            '_cr4ck3d!}',
        ]
        
        for end in endings:
            if len(end) == 10:
                flag = f"DeepSec{{{seg1}{seg2}{seg3}{end[:-1]}}}"
                print(f"\nTrying: {flag}")
    else:
        print(f"\n[!] Could not solve all segments")
        if seg1:
            print(f"Segment 1: {seg1}")
        if seg2:
            print(f"Segment 2: {seg2}")
        if seg3:
            print(f"Segment 3: {seg3}")

if __name__ == "__main__":
    main()
