#!/usr/bin/env python3
"""
Zaytron CTF Challenge Solver
Anti-debugging bypass and flag finder
"""

import subprocess
import os

def bypass_ptrace():
    """
    The binary calls ptrace(PTRACE_TRACEME, 0, 0, 0)
    We can bypass this by using LD_PRELOAD to hook ptrace
    """
    
    # Create a simple ptrace hook library
    hook_code = """
#include <sys/types.h>

long ptrace(int request, pid_t pid, void *addr, void *data) {
    // Always return 0 (success) to bypass anti-debug
    return 0;
}
"""
    
    # Write and compile the hook
    with open('/tmp/ptrace_hook.c', 'w') as f:
        f.write(hook_code)
    
    result = subprocess.run(
        ['gcc', '-shared', '-fPIC', '-o', '/tmp/ptrace_hook.so', '/tmp/ptrace_hook.c'],
        capture_output=True
    )
    
    if result.returncode != 0:
        print(f"[!] Failed to compile ptrace hook: {result.stderr.decode()}")
        return None
    
    return '/tmp/ptrace_hook.so'

def run_with_bypass(binary_path, input_data=None):
    """Run the binary with ptrace bypassed"""
    hook_lib = bypass_ptrace()
    
    if not hook_lib:
        print("[!] Could not create bypass library")
        return None
    
    env = os.environ.copy()
    env['LD_PRELOAD'] = hook_lib
    
    try:
        result = subprocess.run(
            [binary_path],
            input=input_data.encode() if input_data else None,
            capture_output=True,
            env=env,
            timeout=5
        )
        
        return result.stdout.decode(errors='replace'), result.stderr.decode(errors='replace')
    except subprocess.TimeoutExpired:
        return None, "Timeout"
    except Exception as e:
        return None, str(e)

def analyze_zaytron():
    """Analyze the Zaytron binary"""
    binary = '/workspaces/CTF-Playground/Zaytron'
    
    print("="*70)
    print("Zaytron Challenge Analyzer")
    print("="*70)
    
    # First, bypass and see what the program does
    print("\n[*] Bypassing anti-debugging...")
    
    # Test with no input
    stdout, stderr = run_with_bypass(binary, "")
    
    if stdout:
        print(f"\n[*] Output with no input:")
        print(stdout)
    
    # The program expects:
    # 1. A key (decimal number)
    # 2. A flag guess
    
    # Let's try different keys
    print("\n[*] Testing different keys...")
    
    test_keys = [0, 1, 42, 100, 1337, 12345, 0xdeadbeef, 0x1234, 0xabcd]
    
    for key in test_keys:
        input_data = f"{key}\ntest_flag\n"
        stdout, stderr = run_with_bypass(binary, input_data)
        
        if stdout and "valid" in stdout.lower():
            print(f"\n[+] Key {key} (0x{key:x}) shows interesting output:")
            print(stdout)
            
            if "Checking key" in stdout:
                # Extract the checked value
                import re
                match = re.search(r'Checking key: (0x[0-9a-fA-F]+)', stdout)
                if match:
                    checked_val = match.group(1)
                    print(f"  Binary is checking: {checked_val}")

def main():
    analyze_zaytron()
    
    print("\n" + "="*70)
    print("Next Steps:")
    print("="*70)
    print("""
1. The binary uses seeded flag generation
2. We need to find the correct seed value
3. Once we have the seed, it generates the flag
4. We can either:
   a) Brute force the seed value
   b) Reverse engineer the seed validation
   c) Extract the flag generation algorithm
    """)

if __name__ == "__main__":
    main()
