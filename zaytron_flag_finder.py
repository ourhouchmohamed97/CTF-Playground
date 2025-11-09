#!/usr/bin/env python3
"""
Zaytron Flag Generator Reverse Engineering
Extract or replicate the flag generation algorithm
"""

import subprocess
import os
import string

def run_zaytron_with_input(key, flag_guess):
    """Run Zaytron with ptrace bypass"""
    # Use LD_PRELOAD to bypass ptrace
    env = os.environ.copy()
    env['LD_PRELOAD'] = '/tmp/ptrace_hook.so'
    
    input_data = f"{key}\n{flag_guess}\n"
    
    try:
        result = subprocess.run(
            ['/workspaces/CTF-Playground/Zaytron'],
            input=input_data.encode(),
            capture_output=True,
            env=env,
            timeout=2
        )
        
        return result.stdout.decode(errors='replace')
    except:
        return ""

def test_flag_format():
    """Test different flag formats"""
    print("[*] Testing common CTF flag formats...")
    
    key = 3735928559  # 0xdeadbeef
    
    # Common CTF formats
    prefixes = ['DeepSec{', 'FLAG{', 'CTF{', 'flag{', 'ZAYTRON{', '']
    content_patterns = [
        'test',
        '1234567890',
        'deadbeef',
        'seeded_flag',
        'generated',
        'advanced_seed',
    ]
    
    for prefix in prefixes:
        for content in content_patterns:
            if prefix:
                flag = f"{prefix}{content}}}"
            else:
                flag = content
            
            output = run_zaytron_with_input(key, flag)
            
            if 'Congratulations' in output:
                print(f"\n🎉 FOUND THE FLAG: {flag}")
                print(output)
                return flag
            elif 'Sorry' not in output and output:
                print(f"  Interesting response for '{flag}': {output[:100]}")
    
    return None

def brute_force_flag_length():
    """Determine the flag length by testing"""
    print("\n[*] Determining flag length...")
    
    key = 3735928559
    
    for length in range(5, 50):
        flag = 'A' * length
        output = run_zaytron_with_input(key, flag)
        
        # Look for hints in the output
        if output and 'Congratulations' in output:
            print(f"[+] Found flag length: {length}")
            return length
    
    print("[-] Could not determine flag length")
    return None

def analyze_with_ltrace():
    """Use ltrace to see library calls"""
    print("\n[*] Running with ltrace to see comparisons...")
    
    key = 3735928559
    test_flag = "DeepSec{test_flag_here}"
    input_data = f"{key}\n{test_flag}\n"
    
    env = os.environ.copy()
    env['LD_PRELOAD'] = '/tmp/ptrace_hook.so'
    
    try:
        result = subprocess.run(
            ['ltrace', '-s', '100', '/workspaces/CTF-Playground/Zaytron'],
            input=input_data.encode(),
            capture_output=True,
            env=env,
            timeout=5
        )
        
        ltrace_output = result.stderr.decode(errors='replace')
        
        print("\n[*] Relevant library calls:")
        for line in ltrace_output.split('\n'):
            if 'strcmp' in line or 'strncmp' in line or 'memcmp' in line:
                print(f"  {line}")
        
        return ltrace_output
    except Exception as e:
        print(f"[!] ltrace failed: {e}")
        return None

def main():
    print("="*70)
    print("Zaytron Flag Generator Analysis")
    print("="*70)
    print(f"\n[+] Valid seed found: 0xdeadbeef (3735928559)")
    
    # Test flag formats
    flag = test_flag_format()
    
    if not flag:
        # Try ltrace analysis
        analyze_with_ltrace()
        
        # Try brute force on length
        brute_force_flag_length()
    
    print("\n" + "="*70)
    print("Alternative Approach: Static Analysis")
    print("="*70)
    print("""
Since we have the valid seed (0xdeadbeef), the binary generates a flag.
We can:

1. Use Ghidra/Binary Ninja to decompile the flag generation function
2. Use angr to symbolically execute from the seed validation point
3. Use gdb with the ptrace bypass to step through flag generation
4. Extract the algorithm and replicate it in Python

Recommended next step: Decompile with Ghidra to see the flag generation logic
    """)

if __name__ == "__main__":
    main()
