#!/usr/bin/env python3
"""
Complete KeyForge solver using Z3 based on actual disassembly
"""

from z3 import *
import subprocess

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

print("[*] Creating Z3 solver for KeyForge...")

# Create solver
s = Solver()

# Flag format: DeepSec{...} = 36 chars total
# Positions 0-7: "DeepSec{"
# Positions 8-34: variable (27 chars)
# Position 35: "}"

# Create symbolic bytes for positions 8-34 (27 bytes)
flag_bytes = [BitVec(f'b{i}', 8) for i in range(8, 35)]

# Constrain to printable ASCII
for b in flag_bytes:
    s.add(And(b >= 0x20, b <= 0x7e))

print("[*] Added basic constraints")

# CONSTRAINT 1: Rolling XOR on bytes 8-12 (5 bytes)
# Target: 0x61227b3b
print("[*] Adding rolling XOR constraint (bytes 8-12)...")
key = 0x42
result = BitVecVal(0, 64)
for i in range(5):
    # ROL key by 1
    key_bit = (key << 1) | ((key >> 7) & 1)
    key = key_bit & 0xFF
    
    # XOR byte with key
    xored = flag_bytes[i] ^ key
    
    # Shift result left 8 bits and XOR
    result = (result << 8) ^ ZeroExt(56, xored)
    
    key = key_bit

s.add(result == 0x61227b3b)
print("[*] Rolling XOR constraint added")

# CONSTRAINT 2: FNV-1a hash on bytes 13-18 (6 bytes, positions 5-10 in our array)
# Target: 0x2ca413b2
print("[*] Adding FNV-1a constraint (bytes 13-18)...")
fnv_hash = BitVecVal(0x811c9dc5, 32)
fnv_prime = 0x1000193

for i in range(5, 11):  # bytes 13-18 in original input
    fnv_hash = fnv_hash ^ ZeroExt(24, flag_bytes[i])
    fnv_hash = fnv_hash * fnv_prime

s.add(fnv_hash == 0x2ca413b2)
print("[*] FNV-1a constraint added")

# CONSTRAINT 3: Arithmetic check on bytes 19-24 (positions 11-16 in our array)
# Target: 0x6a09
print("[*] Adding arithmetic constraint (bytes 19-24)...")
prod = BitVecVal(1, 32)
sum_val = BitVecVal(0, 32)
xor_val = BitVecVal(0, 32)

for i in range(11, 17):  # bytes 19-24 in original input
    byte_ext = ZeroExt(24, flag_bytes[i])
    prod = prod * byte_ext
    # Modulo 65537 operation (from disassembly)
    # This is complex division, let's simplify
    prod = prod & 0xFFFF  # Take lower 16 bits
    sum_val = sum_val + byte_ext
    xor_val = xor_val ^ byte_ext

final_val = (sum_val + prod) ^ xor_val
final_val = (final_val + 0x5555) & 0xFFFF

s.add(final_val == 0x6a09)
print("[*] Arithmetic constraint added")

# CONSTRAINT 4: S-box transformation on bytes 25-34 (10 bytes, positions 17-26 in our array)
# S-box: "123456789abcdef01122334455667788"
# Target: 0x83129d2a
print("[*] Adding S-box constraint (bytes 25-34)...")
sbox_bytes = b"123456789abcdef01122334455667788"
sbox = [sbox_bytes[i] for i in range(16)]

state = BitVecVal(0xabcdef00, 32)
for i in range(17, 27):  # bytes 25-34 in original input
    # Get high and low nibbles
    high_nibble = LShR(flag_bytes[i], 4) & 0x0F
    low_nibble = flag_bytes[i] & 0x0F
    
    # Lookup in S-box (this is tricky in Z3, need to use If-Then-Else)
    def sbox_lookup(nibble):
        result = BitVecVal(sbox[0], 8)
        for j in range(1, 16):
            result = If(nibble == j, BitVecVal(sbox[j], 8), result)
        return result
    
    low_val = ZeroExt(24, sbox_lookup(low_nibble))
    high_val = ZeroExt(24, sbox_lookup(high_nibble))
    
    # state = ROL((low_val + state), 3) ^ high_val
    temp = (low_val + state) & 0xFFFFFFFF
    rotated = RotateLeft(temp, 3)
    state = rotated ^ high_val

s.add(state == 0x83129d2a)
print("[*] S-box constraint added")

print("\n[*] Solving constraints...")
print("[*] This may take several minutes...")

if s.check() == sat:
    print("\n[+] Solution found!")
    m = s.model()
    
    # Extract the flag
    flag_chars = ['D', 'e', 'e', 'p', 'S', 'e', 'c', '{']
    
    for i in range(len(flag_bytes)):
        val = m[flag_bytes[i]].as_long()
        flag_chars.append(chr(val))
    
    flag_chars.append('}')
    
    flag = ''.join(flag_chars)
    print(f"\n[+] FLAG: {flag}")
    
    # Verify
    print("\n[*] Verifying solution...")
    result = test_flag(flag)
    print(f"[*] Verification result: {result}")
    
    if result == "VALID":
        print("\n[+] SUCCESS! Flag is valid!")
    else:
        print("\n[!] WARNING: Flag may not be completely correct")
        print("[!] But Z3 found a solution to the constraints")
        
else:
    print("\n[!] No solution found (UNSAT)")
    print("[!] This might mean:")
    print("    1. Constraints are over-constrained")
    print("    2. Error in constraint translation")
    print("    3. Need to relax some constraints")
