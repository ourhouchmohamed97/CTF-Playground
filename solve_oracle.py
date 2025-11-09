#!/usr/bin/env python3
"""
Use the binary itself as an oracle for solving each segment
"""

import subprocess
import itertools
import string
from multiprocessing import Pool, cpu_count

# Character set (lowercase, digits, underscore)
CHARSET = string.ascii_lowercase + string.digits + '_'

def test_flag(flag):
    """Test a flag against the binary"""
    try:
        result = subprocess.run(
            ['./KeyForge_unpacked'],
            input=flag.encode() + b'\n',
            capture_output=True,
            timeout=1,
            cwd='/workspaces/CTF-Playground'
        )
        output = result.stdout.decode()
        return 'License valid!' in output
    except:
        return False

def bruteforce_segment(segment_num, start_pos, length, prefix=""):
    """Brute force a specific segment"""
    print(f"\n[*] Bruteforcing segment {segment_num} (positions {start_pos}-{start_pos+length-1})")
    print(f"[*] Character set: {CHARSET} ({len(CHARSET)} chars)")
    print(f"[*] Max combinations: {len(CHARSET)**length:,}")
    
    # Fill the rest with dummy values for testing
    dummy_rest = 'x' * (36 - start_pos - length - 1)
    
    tested = 0
    for combo in itertools.product(CHARSET, repeat=length):
        segment = ''.join(combo)
        test_input = prefix + segment + dummy_rest + '}'
        
        if test_flag(test_input):
            print(f"\n[+] FOUND! Segment {segment_num}: {segment}")
            print(f"[+] Full flag so far: {prefix + segment + '???' * len(dummy_rest) + '}'}")
            return segment
        
        tested += 1
        if tested % 10000 == 0:
            print(f"  Tested {tested:,} combinations... Current: {segment}", end='\r')
    
    print(f"\n[-] No solution found after {tested:,} attempts")
    return None

def smart_search():
    """
    Smart approach: Try to find patterns in valid flags
    """
    print("[*] Starting smart pattern search...")
    
    # Common CTF patterns
    common_words = [
        'key', 'flag', 'pass', 'code', 'hash', 'secret', 'admin', 
        'root', 'user', 'test', 'demo', 'crack', 'break', 'solve',
        'pwn', 'rev', 'bin', 'hex', 'ascii', 'xor', 'rot', 'base64',
        'license', 'valid', 'check', 'verify', 'forge', 'deep', 'sec'
    ]
    
    # Try combinations of common words
    for word1 in common_words:
        for word2 in common_words:
            for suffix in ['', '1', '2', '3', '_', '123', '456']:
                # Construct potential flags with different patterns
                patterns = [
                    f"DeepSec{{{word1}_{word2}{suffix}}}",
                    f"DeepSec{{{word1}{word2}{suffix}}}",
                    f"DeepSec{{{word1}_{word2}_{suffix}}}",
                ]
                
                for pattern in patterns:
                    # Pad to 36 chars if needed
                    if len(pattern) < 36:
                        pattern = pattern[:-1] + '_' * (36 - len(pattern)) + '}'
                    elif len(pattern) > 36:
                        continue
                    
                    if test_flag(pattern):
                        print(f"\n🎉 FOUND FLAG: {pattern}")
                        return pattern
                    
                print(f"  Trying: {word1}_{word2}{suffix}...", end='\r')
    
    print("\n[-] Smart search did not find solution")
    return None

def main():
    print("="*70)
    print(" KeyForge Oracle-Based Solver")
    print("="*70)
    
    # First try smart search
    result = smart_search()
    if result:
        return
    
    # If that fails, try brute force segment by segment
    # This assumes segments can be validated independently (they might not be)
    print("\n[!] Falling back to brute force...")
    print("[!] Warning: This may take a very long time!")
    
    # Start with shortest segment first
    prefix = "DeepSec{"
    
    # Try segment 1 (5 chars: positions 8-12)
    seg1 = bruteforce_segment(1, 8, 5, prefix)
    if seg1:
        prefix += seg1
    else:
        print("[!] Could not find segment 1")
        return

if __name__ == "__main__":
    main()
