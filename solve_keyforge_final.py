#!/usr/bin/env python3
"""
Final KeyForge solver based on actual disassembly analysis
"""

import subprocess
import string
import itertools

def test_flag(flag):
    """Test a flag against the KeyForge binary"""
    try:
        result = subprocess.run(
            ['./KeyForge_unpacked'],
            input=flag.encode() + b'\n',
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=2
        )
        output = result.stdout.decode() + result.stderr.decode()
        if "License valid!" in output:
            return "VALID"
        elif "validation failed" in output:
            return "FAILED"
        else:
            return "INVALID"
    except:
        return "ERROR"

def fnv1a_hash(data):
    """FNV-1a hash implementation"""
    hash_val = 0x811c9dc5
    prime = 0x1000193
    for byte in data:
        hash_val ^= byte
        hash_val = (hash_val * prime) & 0xFFFFFFFF
    return hash_val

# Based on disassembly, the validation checks:
# 1. Format check (length 36, starts with "DeepSec{", ends with "}")
# 2. FNV-1a hash of bytes 13-18 (6 bytes) must equal 0x2ca413b2
# 3. Other checks on different segments

# Let's brute force the 6-byte segment at position 13-18
target_hash = 0x2ca413b2

print("[*] Brute forcing FNV-1a hash for bytes 13-18...")
print(f"[*] Target hash: 0x{target_hash:08x}")

# Try common character sets
charset = string.ascii_letters + string.digits + '_-!'

# Since brute forcing all 6 characters is too slow, let's try common patterns
patterns = [
    # Common CTF patterns
    "K3yF0r",
    "k3yf0r",
    "KEYFOR",
    "keyfor",
    "L1c3ns",
    "l1c3ns",
    "V4l1d4",
    "v4l1d4",
]

print("\n[*] Testing common patterns...")
for pattern in patterns:
    if len(pattern) == 6:
        h = fnv1a_hash(pattern.encode())
        if h == target_hash:
            print(f"[+] FOUND! Pattern: {pattern} (hash: 0x{h:08x})")
            # Now build full flag and test
            # We don't know the other parts yet, but we can try
            for prefix in ["DeepSec{", "DeepSec{"]:
                for middle1 in ["test", "flag", "ctf_", "key_"]:
                    flag = prefix + middle1 + "_" + pattern + "_" + "X" * (36 - len(prefix) - len(middle1) - 1 - len(pattern) - 2) + "}"
                    if len(flag) == 36:
                        result = test_flag(flag)
                        if result == "VALID":
                            print(f"\n[+] FLAG FOUND: {flag}")
                            exit(0)
        if (patterns.index(pattern) + 1) % 10 == 0:
            print(f"[*] Tested {patterns.index(pattern) + 1} patterns...")

print("\n[*] Common patterns didn't work. Trying brute force...")
print("[*] This will take a while. Trying 4-character combinations first...")

# Try shorter combinations with common suffixes
for length in range(3, 7):
    print(f"\n[*] Trying {length}-character combinations...")
    count = 0
    for combo in itertools.product(charset, repeat=length):
        test_str = ''.join(combo)
        test_bytes = test_str.encode()
        
        # Pad to 6 bytes if needed
        if len(test_bytes) < 6:
            # Try different padding
            for pad_char in ['_', '0', 'X', 'A']:
                padded = (test_str + pad_char * (6 - len(test_str))).encode()
                h = fnv1a_hash(padded)
                if h == target_hash:
                    print(f"\n[+] FOUND! String: {padded.decode()} (hash: 0x{h:08x})")
                    # Try to build full flags
                    for rest in ["test", "flag", "key"]:
                        flag_content = rest + "_" + padded.decode() + "_" + "X" * 10
                        flag_content = flag_content[:27]  # 36 - 8 ("DeepSec{") - 1 ("}")
                        flag = f"DeepSec{{{flag_content}}}"
                        if len(flag) == 36:
                            result = test_flag(flag)
                            print(f"Testing: {flag} -> {result}")
                            if result == "VALID":
                                print(f"\n[+] FLAG FOUND: {flag}")
                                exit(0)
        else:
            h = fnv1a_hash(test_bytes[:6])
            if h == target_hash:
                print(f"\n[+] FOUND! String: {test_str} (hash: 0x{h:08x})")
                exit(0)
        
        count += 1
        if count % 100000 == 0:
            print(f"[*] Tested {count} combinations...")
        
        if count > 1000000:  # Limit to prevent running forever
            break

print("\n[!] Brute force taking too long. Need different approach.")
