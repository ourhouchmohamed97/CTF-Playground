#!/usr/bin/env python3
"""
CTF Challenge Solver - Reverse Engineering Flag Extraction

ANALYSIS:
---------
The binary validation works as follows:

1. User inputs a flag (must be 36 characters)
2. validate_flag() performs XOR encoding:
   - For each position i: encoded[i] = flag[i] ^ key[i % len(key)]
   - Compares result against ENCODED_FLAG stored in binary
3. If match, calls dummy functions (caesar_shift, verify_checksum, rot13_decode, etc.)
   - These are red herrings! They're called AFTER validation succeeds

SOLUTION:
---------
Since XOR is reversible (A ^ B ^ B = A), we can recover the flag:
   flag[i] = ENCODED_FLAG[i] ^ key[i % len(key)]

TO EXTRACT DATA FROM BINARY:
-----------------------------
Method 1 - Using strings:
    strings <binary> | grep -i <pattern>

Method 2 - Using Ghidra/IDA:
    - Open binary in disassembler
    - Find 'key' symbol - it's a pointer to a string
    - Find 'ENCODED_FLAG' symbol - it's a 36-byte array
    
Method 3 - Using radare2/rizin:
    r2 <binary>
    aaa              # analyze
    iz               # list strings
    px 36 @ sym.ENCODED_FLAG   # print 36 bytes at ENCODED_FLAG
    ps @ sym.key     # print string at key

Method 4 - Using Python with pwntools:
    from pwn import *
    elf = ELF('./binary')
    key = elf.read(elf.symbols['key'], <length>)
    encoded = elf.read(elf.symbols['ENCODED_FLAG'], 36)
"""

# ============================================================================
# STEP 1: Replace these with actual values from the binary
# ============================================================================

# Extracted from Obfusca binary
key = b"LEET!"  # Found at offset 0x2008 in .rodata section
ENCODED_FLAG = bytes([
    0x08, 0x20, 0x20, 0x24, 0x72, 0x29, 0x26, 0x3e, 0x26, 0x12, 0x3a, 0x76,
    0x37, 0x27, 0x12, 0x13, 0x76, 0x2b, 0x33, 0x10, 0x22, 0x76, 0x76, 0x26,
    0x10, 0x22, 0x22, 0x1a, 0x65, 0x52, 0x13, 0x23, 0x30, 0x3a, 0x00, 0x31
])  # Found at offset 0x4060 in .data section


# ============================================================================
# STEP 2: Decode the flag
# ============================================================================

def decode_flag(encoded_flag, key):
    """
    Reverse the XOR encoding to get the original flag.
    
    Args:
        encoded_flag: bytes - The encoded flag from the binary
        key: bytes - The XOR key from the binary
    
    Returns:
        str - The decoded flag
    """
    if not key:
        raise ValueError("Key cannot be empty")
    
    flag = []
    key_len = len(key)
    
    for i, byte in enumerate(encoded_flag):
        # XOR with repeating key
        decoded_char = byte ^ key[i % key_len]
        flag.append(chr(decoded_char))
    
    return ''.join(flag)


# ============================================================================
# STEP 3: Main solver
# ============================================================================

def main():
    print("=" * 70)
    print("CTF Reverse Engineering Challenge Solver")
    print("=" * 70)
    
    # Check if we have real data
    if key == b"REPLACE_WITH_ACTUAL_KEY" or len(ENCODED_FLAG) == 0:
        print("\n[!] You need to extract the actual data from the binary first!")
        print("\nINSTRUCTIONS:")
        print("-" * 70)
        print("1. Open the binary in Ghidra, IDA, or radare2")
        print("2. Find the 'key' symbol and extract the string value")
        print("3. Find the 'ENCODED_FLAG' symbol and extract 36 bytes")
        print("4. Update this script with the actual values")
        print("\nQuick extraction with radare2:")
        print("  $ r2 <binary>")
        print("  [0x00000000]> aaa")
        print("  [0x00000000]> ps @ sym.key")
        print("  [0x00000000]> px 36 @ sym.ENCODED_FLAG")
        print("\nOr use strings:")
        print("  $ strings <binary>")
        print("  $ objdump -s -j .rodata <binary>")
        return
    
    print(f"\n[+] Key length: {len(key)}")
    print(f"[+] Key: {key}")
    print(f"[+] Encoded flag length: {len(ENCODED_FLAG)}")
    print(f"[+] Encoded flag (hex): {ENCODED_FLAG.hex()}")
    
    # Decode the flag
    flag = decode_flag(ENCODED_FLAG, key)
    
    print("\n" + "=" * 70)
    print("FLAG FOUND!")
    print("=" * 70)
    print(f"\n{flag}\n")
    
    # Verify it's printable ASCII
    if all(32 <= ord(c) <= 126 for c in flag):
        print("[✓] Flag contains only printable ASCII characters")
    else:
        print("[!] Warning: Flag contains non-printable characters")
        print("    This might indicate incorrect key/encoded_flag values")
    
    return flag


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
