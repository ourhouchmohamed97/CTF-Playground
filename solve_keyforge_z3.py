#!/usr/bin/env python3
"""
KeyForge Z3-based Solver - Uses constraint solving instead of brute force
"""

from z3 import *
import string

# ============================================================================
# Extracted Constants
# ============================================================================

TARGET_40567A = 0x6a0983129d2a  # Rolling XOR check (bytes 8-12, 5 chars)
TARGET_4056DA = 0x2ca413b2      # FNV-1a hash (bytes 13-18, 6 chars)
TARGET_40574A = 0x61227b3b      # Arithmetic (bytes 19-24, 6 chars)

# ============================================================================
# Z3 Helper Functions
# ============================================================================

def z3_rol_byte(val, shift):
    """Z3 rotate left for 8-bit value"""
    # Ensure val is 8-bit
    val = val & 0xFF
    # For constant shift of 1
    if shift == 1:
        return ((val << 1) | LShR(val, 7)) & 0xFF
    return ((val << shift) | LShR(val, 8 - shift)) & 0xFF

def solve_rolling_xor_z3():
    """
    Use Z3 to solve: bytes 8-12 (5 bytes)
    rsi = 0x42
    rax = 0
    for each byte:
        rsi = ROL(rsi, 1)
        rax = byte ^ rsi ^ (rax << 8)
    rax == TARGET_40567A
    """
    print("[+] Solving segment 8-12 with Z3 (Rolling XOR)...")
    
    s = Solver()
    
    # Create 5 byte variables
    chars = [BitVec(f'c{i}', 8) for i in range(5)]
    
    # Constrain to printable ASCII (letters, digits, underscore)
    charset_constraints = []
    for c in chars:
        # Allow a-z, A-Z, 0-9, _
        valid = Or(
            And(c >= ord('a'), c <= ord('z')),
            And(c >= ord('A'), c <= ord('Z')),
            And(c >= ord('0'), c <= ord('9')),
            c == ord('_')
        )
        s.add(valid)
    
    # Implement the rolling XOR algorithm
    rsi = BitVec('rsi_init', 8)
    s.add(rsi == 0x42)
    rax = BitVec('rax_init', 64)
    s.add(rax == 0)
    
    for i, char in enumerate(chars):
        # rsi = ROL(rsi, 1)
        rsi_new = BitVec(f'rsi_{i}', 8)
        s.add(rsi_new == ((rsi << 1) | LShR(rsi, 7)) & 0xFF)
        # rax = char ^ rsi_new ^ (rax << 8)
        rax_new = BitVec(f'rax_{i}', 64)
        s.add(rax_new == (ZeroExt(56, char) ^ ZeroExt(56, rsi_new) ^ (rax << 8)))
        rsi = rsi_new
        rax = rax_new
    
    # Add final constraint
    s.add(rax == TARGET_40567A)
    
    # Solve
    if s.check() == sat:
        m = s.model()
        result = ''.join(chr(m[c].as_long()) for c in chars)
        print(f"  ✓ Found: {result}")
        return result
    else:
        print("  ✗ No solution found")
        return None

def solve_fnv_hash_z3():
    """
    Use Z3 to solve: bytes 13-18 (6 bytes)
    FNV-1a hash algorithm
    """
    print("[+] Solving segment 13-18 with Z3 (FNV-1a)...")
    
    s = Solver()
    
    # Create 6 byte variables
    chars = [BitVec(f'c{i}', 8) for i in range(6)]
    
    # Constrain to printable ASCII
    for c in chars:
        valid = Or(
            And(c >= ord('a'), c <= ord('z')),
            And(c >= ord('A'), c <= ord('Z')),
            And(c >= ord('0'), c <= ord('9')),
            c == ord('_')
        )
        s.add(valid)
    
    # Implement FNV-1a
    hash_val = BitVecVal(0x811c9dc5, 32)
    
    for char in chars:
        # hash = (hash ^ byte) * 0x1000193
        hash_val = (hash_val ^ ZeroExt(24, char)) * 0x1000193
    
    s.add(hash_val == TARGET_4056DA)
    
    # Solve
    if s.check() == sat:
        m = s.model()
        result = ''.join(chr(m[c].as_long()) for c in chars)
        print(f"  ✓ Found: {result}")
        return result
    else:
        print("  ✗ No solution found")
        return None

def solve_arithmetic_z3():
    """
    Use Z3 to solve: bytes 19-24 (6 bytes)
    sum, product mod 0xFFFF, xor
    result = ((sum + product) ^ xor) + 0x5555 == TARGET
    """
    print("[+] Solving segment 19-24 with Z3 (Arithmetic)...")
    
    s = Solver()
    
    # Create 6 byte variables
    chars = [BitVec(f'c{i}', 8) for i in range(6)]
    
    # Constrain to printable ASCII
    for c in chars:
        valid = Or(
            And(c >= ord('a'), c <= ord('z')),
            And(c >= ord('A'), c <= ord('Z')),
            And(c >= ord('0'), c <= ord('9')),
            c == ord('_')
        )
        s.add(valid)
    
    # Implement the algorithm
    sum_val = BitVec('sum_init', 32)
    product = BitVec('prod_init', 32)
    xor_val = BitVec('xor_init', 8)
    s.add(sum_val == 0)
    s.add(product == 1)
    s.add(xor_val == 0)
    
    for i, char in enumerate(chars):
        # sum += byte
        sum_new = BitVec(f'sum_{i}', 32)
        s.add(sum_new == sum_val + ZeroExt(24, char))
        sum_val = sum_new
        
        # product = (product * byte) % 0xFFFF
        prod_new = BitVec(f'prod_{i}', 32)
        s.add(prod_new == URem(product * ZeroExt(24, char), 0xFFFF))
        product = prod_new
        
        # xor ^= byte
        xor_new = BitVec(f'xor_{i}', 8)
        s.add(xor_new == xor_val ^ char)
        xor_val = xor_new
    
    # result = ((sum + product) ^ xor) + 0x5555
    result = ((sum_val + product) ^ ZeroExt(24, xor_val)) + 0x5555
    
    s.add(result == TARGET_40574A)
    
    # Solve
    if s.check() == sat:
        m = s.model()
        result = ''.join(chr(m[c].as_long()) for c in chars)
        print(f"  ✓ Found: {result}")
        return result
    else:
        print("  ✗ No solution found")
        return None

def main():
    print("=" * 70)
    print("KeyForge Z3 Constraint Solver")
    print("=" * 70)
    print()
    
    # Solve each segment
    seg1 = solve_rolling_xor_z3()
    seg2 = solve_fnv_hash_z3()
    seg3 = solve_arithmetic_z3()
    
    if seg1 and seg2 and seg3:
        # We still need the last 10 characters (bytes 25-34)
        # For now, assume we can brute-force or it's padding
        
        # Try common patterns for the last segment
        last_segments = [
            "0_1n_pl41n",
            "_w1th_l0v3",
            "_cr4ck3d!}",
            "1234567890",
        ]
        
        for last in last_segments:
            if len(last) == 10:
                flag = f"DeepSec{{{seg1}{seg2}{seg3}{last[:-1]}}}"
                if len(flag) == 36:
                    print(f"\n{'='*70}")
                    print(f"Candidate FLAG: {flag}")
                    print(f"{'='*70}")
                    print(f"\nTest this with: echo '{flag}' | ./KeyForge_unpacked")
                    
                    # Test it
                    import subprocess
                    try:
                        result = subprocess.run(
                            ['/workspaces/CTF-Playground/KeyForge_unpacked'],
                            input=flag.encode(),
                            capture_output=True,
                            timeout=2
                        )
                        output = result.stdout.decode()
                        if 'valid' in output.lower() and 'failed' not in output.lower():
                            print(f"\n🎉 SUCCESS! Flag validated by binary: {flag}")
                            return flag
                        else:
                            print(f"Binary output: {output.strip()}")
                    except Exception as e:
                        print(f"Error testing: {e}")
        
        # If still not found, we need to solve the S-box constraint too
        print("\n[!] Last segment needs additional solving")
        print(f"Partial flag: DeepSec{{{seg1}{seg2}{seg3}XXXXXXXXXX}}")
    else:
        print("\n[!] Failed to solve all segments")
        if seg1:
            print(f"  Segment 1: {seg1}")
        if seg2:
            print(f"  Segment 2: {seg2}")
        if seg3:
            print(f"  Segment 3: {seg3}")

if __name__ == "__main__":
    main()
