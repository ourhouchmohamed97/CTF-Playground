#!/usr/bin/env python3
"""
Test corrected rolling XOR implementation
"""

def rolling_xor_correct(data):
    """Corrected rolling XOR - handles sign extension"""
    key = 0x42
    result = 0
    
    for byte_val in data:
        result = result << 8  # Shift result left 8 bits
        
        # ROL key by 1
        key = ((key << 1) | (key >> 7)) & 0xFF
        
        # XOR byte with key
        xored = byte_val ^ key
        
        # Sign extend if high bit is set
        if xored & 0x80:
            xored_ext = xored | 0xFFFFFFFFFFFFFF00
        else:
            xored_ext = xored
        
        # XOR with result
        result = result ^ xored_ext
    
    # Mask to 64 bits
    result = result & 0xFFFFFFFFFFFFFFFF
    return result

# Test with a known input
test = b"ABCDE"
result = rolling_xor_correct(test)
print(f"Test input: {test}")
print(f"Result: 0x{result:016x}")

# Try to find what produces 0x61227b3b
target = 0x61227b3b

# The upper 32 bits might be 0 or 0xFFFFFFFF depending on sign extension
# Let's try both targets
targets = [
    0x0000000061227b3b,
    0x00000000f61227b3b,  # With extra F
    0xFFFFFFFF61227b3b,
]

import itertools
import string

found = False
charset = string.ascii_lowercase + string.digits

print(f"\nSearching for target: 0x{target:08x}")
print("Trying different interpretations...")

for full_target in targets:
    if found:
        break
    print(f"\nTrying full target: 0x{full_target:016x}")
    
    count = 0
    for combo in itertools.product(charset, repeat=5):
        test_bytes = bytes([ord(c) for c in combo])
        result = rolling_xor_correct(test_bytes)
        
        if result == full_target:
            print(f"[+] FOUND: {''.join(combo)}")
            print(f"    Result: 0x{result:016x}")
            found = True
            break
        
        # Also check if lower 32 bits match
        if (result & 0xFFFFFFFF) == target:
            print(f"[+] Possible match (lower 32 bits): {''.join(combo)}")
            print(f"    Full result: 0x{result:016x}")
        
        count += 1
        if count % 100000 == 0:
            print(f"  Tested {count}...")
        if count > 500000:
            break

if not found:
    print("\n[!] Not found in limited search")
    print("[*] The algorithm might still be incorrect")
