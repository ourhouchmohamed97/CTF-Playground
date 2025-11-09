#!/usr/bin/env python3
"""
Reverse engineering approach: Use Z3 to solve each segment independently
"""
from z3 import *
import subprocess

def test_flag(flag):
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
        return "INVALID"
    except:
        return "ERROR"

print("[*] Solving KeyForge using Z3 segment-by-segment")
print("="*60)

# ===== SEGMENT 1: Bytes 8-12 (5 bytes) - Rolling XOR =====
print("\n[1] Solving Rolling XOR (bytes 8-12)...")
s1 = Solver()
seg1 = [BitVec(f'b{i}', 8) for i in range(5)]

# Constrain to printable
for b in seg1:
    s1.add(And(b >= 0x20, b <= 0x7e))

# Rolling XOR algorithm
key = BitVecVal(0x42, 8)
result = BitVecVal(0, 64)

for b in seg1:
    result = result << 8
    # ROL key by 1
    key_rotated = Concat(Extract(6, 0, key), Extract(7, 7, key))
    key = key_rotated
    # XOR and sign extend
    xored = b ^ key
    # Sign extension
    xored_ext = If(
        Extract(7, 7, xored) == 1,
        Concat(BitVecVal(0xFFFFFFFFFFFFFF, 56), xored),
        ZeroExt(56, xored)
    )
    result = result ^ xored_ext

s1.add(result == 0x000000f361227b3b)

if s1.check() == sat:
    m1 = s1.model()
    seg1_str = ''.join(chr(m1[b].as_long()) for b in seg1)
    print(f"[+] Segment 1: '{seg1_str}'")
else:
    print("[!] Segment 1: UNSAT")
    seg1_str = "?????"

# ===== SEGMENT 2: Bytes 13-18 (6 bytes) - FNV-1a =====
print("\n[2] Solving FNV-1a (bytes 13-18)...")
s2 = Solver()
seg2 = [BitVec(f'b{i}', 8) for i in range(6)]

for b in seg2:
    s2.add(And(b >= 0x20, b <= 0x7e))

# FNV-1a
fnv = BitVecVal(0x811c9dc5, 32)
for b in seg2:
    fnv = fnv ^ ZeroExt(24, b)
    fnv = fnv * 0x1000193

s2.add(fnv == 0x2ca413b2)

if s2.check() == sat:
    m2 = s2.model()
    seg2_str = ''.join(chr(m2[b].as_long()) for b in seg2)
    print(f"[+] Segment 2: '{seg2_str}'")
else:
    print("[!] Segment 2: UNSAT")
    seg2_str = "??????"

# ===== SEGMENT 3: Bytes 19-24 (6 bytes) - Arithmetic =====
print("\n[3] Solving Arithmetic (bytes 19-24)...")
s3 = Solver()
seg3 = [BitVec(f'b{i}', 8) for i in range(6)]

for b in seg3:
    s3.add(And(b >= 0x20, b <= 0x7e))

prod_r = BitVecVal(1, 16)
sum_r = BitVecVal(0, 16)
xor_r = BitVecVal(0, 16)

for b in seg3:
    b_ext = ZeroExt(8, b)
    prod_r = (prod_r * b_ext) & 0xFFFF
    sum_r = (sum_r + b_ext) & 0xFFFF
    xor_r = xor_r ^ b_ext

final_r = ((sum_r + prod_r) ^ xor_r + 0x5555) & 0xFFFF
s3.add(final_r == 0x6a09)

if s3.check() == sat:
    m3 = s3.model()
    seg3_str = ''.join(chr(m3[b].as_long()) for b in seg3)
    print(f"[+] Segment 3: '{seg3_str}'")
else:
    print("[!] Segment 3: UNSAT")
    seg3_str = "??????"

seg4_str = "??????????"

# Construct the flag
flag = f"DeepSec{{{seg1_str}{seg2_str}{seg3_str}{seg4_str}}}"
print(f"\n[*] Partial flag: {flag}")
result = test_flag(flag)
print(f"[*] Test result: {result}")

