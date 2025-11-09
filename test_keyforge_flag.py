#!/usr/bin/env python3
"""
KeyForge Flag Validator and Fixer
Tests candidate flags and helps debug issues
"""

import subprocess

def test_flag(flag):
    """Test a flag with the actual binary"""
    if len(flag) != 36:
        return False, f"Wrong length: {len(flag)} (expected 36)"
    
    try:
        result = subprocess.run(
            ['/workspaces/CTF-Playground/KeyForge_unpacked'],
            input=flag.encode() + b'\n',
            capture_output=True,
            timeout=2
        )
        output = result.stdout.decode(errors='replace')
        stderr = result.stderr.decode(errors='replace')
        
        print(f"\nTesting: {flag}")
        print(f"Length: {len(flag)}")
        print(f"Stdout: {output}")
        if stderr:
            print(f"Stderr: {stderr}")
        
        # Check for success
        if 'License valid!' in output:
            return True, output
        return False, output
        
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)

def analyze_flag(flag):
    """Analyze the structure of a flag"""
    print(f"\nFlag Analysis:")
    print(f"="*60)
    print(f"Full flag: {flag}")
    print(f"Length: {len(flag)}")
    
    if len(flag) >= 8:
        print(f"Prefix (0-7): '{flag[:8]}'")
    if len(flag) >= 13:
        print(f"Seg 1 (8-12): '{flag[8:13]}'")
    if len(flag) >= 19:
        print(f"Seg 2 (13-18): '{flag[13:19]}'")
    if len(flag) >= 25:
        print(f"Seg 3 (19-24): '{flag[19:25]}'")
    if len(flag) >= 35:
        print(f"Seg 4 (25-34): '{flag[25:35]}'")
    if len(flag) == 36:
        print(f"Suffix (35): '{flag[35]}'")
    
    # Check for non-printable characters
    non_printable = []
    for i, c in enumerate(flag):
        if ord(c) < 32 or ord(c) > 126:
            non_printable.append((i, ord(c), repr(c)))
    
    if non_printable:
        print(f"\nNon-printable characters found:")
        for pos, code, rep in non_printable:
            print(f"  Position {pos}: {rep} (0x{code:02x})")

def main():
    print("="*70)
    print("KeyForge Flag Validator")
    print("="*70)
    
    # Test what Angr gave you
    angr_result = "DeepSec{|??????????????????????????}"
    print(f"\n[*] Testing Angr's result...")
    analyze_flag(angr_result)
    success, output = test_flag(angr_result)
    
    if success:
        print(f"\n🎉 Angr result is CORRECT!")
        return
    else:
        print(f"\n✗ Angr result is incorrect: {output[:100]}")
    
    # Test some manual candidates
    print(f"\n[*] Testing manual candidates...")
    
    candidates = [
        "DeepSec{test1_test2_test3_0123456789}",  # all lowercase
        "DeepSec{Test1_Test2_Test3_0123456789}",  # mixed case
        "DeepSec{TEST1_TEST2_TEST3_0123456789}",  # all uppercase
        "DeepSec{abcde_fghijk_lmnopq_rstuvwxyz}",  # alphabetic
    ]
    
    for candidate in candidates:
        if len(candidate) == 36:
            success, output = test_flag(candidate)
            if success:
                print(f"\n🎉 FOUND: {candidate}")
                return
    
    # Provide recommendations
    print(f"\n{'='*70}")
    print("RECOMMENDATIONS:")
    print(f"{'='*70}")
    print("""
The issue with Angr getting '|?????????...' suggests:

1. **Symbolic Memory Issues**: Angr might be hitting unconstrained symbolic memory
   - Solution: Add more constraints, especially on input characters

2. **State Explosion**: Too many paths being explored
   - Solution: Use more targeted hooks or veritesting

3. **Wrong Target**: Looking for wrong success condition
   - Binary outputs: "License valid!" for success
   
NEXT STEPS:

A) Fix the Angr script:
   - Ensure stdin is properly constrained
   - Look for exact string "License valid!" not just "valid"
   - Add character constraints (printable ASCII only)

B) Use GDB for dynamic analysis:
   ```bash
   gdb ./KeyForge_unpacked
   (gdb) break *0x4055da  # break at validation function
   (gdb) run
   # Enter test input
   (gdb) x/36c $rdi  # examine the input buffer
   (gdb) info registers
   ```

C) Try the hybrid solver with more attempts:
   ```bash
   # Edit solve_keyforge_manual.py and increase max_attempts to 10000000
   python3 solve_keyforge_manual.py
   ```

D) Use radare2 for analysis:
   ```bash
   r2 -A ./KeyForge_unpacked
   [0x00001160]> afl | grep -i valid
   [0x00001160]> pdf @ sym.validate_flag
   ```
""")

if __name__ == "__main__":
    main()
