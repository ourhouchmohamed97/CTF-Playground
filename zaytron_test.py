#!/usr/bin/env python3
"""
Test flag character by character
"""
import subprocess
import os

def test_flag(flag):
    """Test a flag with the binary"""
    if not os.path.exists('/tmp/ptrace_hook.so'):
        print("[!] ptrace_hook.so not found")
        return False
    
    env = os.environ.copy()
    env['LD_PRELOAD'] = '/tmp/ptrace_hook.so'
    input_data = f"3735928559\n{flag}\n"
    
    try:
        result = subprocess.run(
            ['./Zaytron'],
            input=input_data.encode(),
            capture_output=True,
            env=env,
            timeout=5
        )
        output = result.stdout.decode(errors='replace')
        return 'Congratulations' in output
    except:
        return False

def generate_flag(seed):
    """Generate flag from seed"""
    flag = []
    
    b0 = (seed >> 24) & 0xFF  # 0xde = 222
    b1 = (seed >> 16) & 0xFF  # 0xad = 173
    b2 = (seed >> 8) & 0xFF   # 0xbe = 190
    b3 = seed & 0xFF           # 0xef = 239
    
    flag.append((b0 + 0x66) & 0xFF)  # [0] 'D'
    flag.append((b1 - 0x48) & 0xFF)  # [1] 'e'
    flag.append(flag[1])              # [2] 'e'
    flag.append((b2 - 0x4E) & 0xFF)  # [3] 'p'
    flag.append((b0 + 0x75) & 0xFF)  # [4] 'S'
    flag.append(flag[1])              # [5] 'e'
    flag.append((b1 - 0x4A) & 0xFF)  # [6] 'c'
    flag.append((b3 - 0x74) & 0xFF)  # [7] '{'
    flag.append(flag[6])              # [8] 'c'
    flag.append((seed % 100) - 0x0B)  # [9] '0'
    flag.append((b1 - 0x40) & 0xFF)  # [10] 'm'
    flag.append(flag[3])              # [11] 'p'
    flag.append((b2 - 0x52) & 0xFF)  # [12] 'l'
    flag.append((seed % 10) + 0x2A)  # [13] '3'
    flag.append((b1 - 0x35) & 0xFF)  # [14] 'x'
    flag.append((seed % 100) + 0x24)  # [15] '_'
    flag.append((b2 - 0x5C) & 0xFF)  # [16] 'b'
    flag.append((seed % 50) + 0x28)  # [17] '1'
    flag.append((b2 - 0x4A) & 0xFF)  # [18] 't'
    flag.append((b2 - 0x47) & 0xFF)  # [19] 'w'
    flag.append(flag[17])             # [20] '1'
    flag.append((b1 - 0x3A) & 0xFF)  # [21] 's'
    flag.append(flag[13])             # [22] '3'
    flag.append(flag[15])             # [23] '_'
    flag.append(flag[9])              # [24] '0'
    flag.append(flag[3])              # [25] 'p'
    flag.append(flag[13])             # [26] '3'
    flag.append((b2 - 0x4C) & 0xFF)  # [27] 'r'
    flag.append((seed % 10) + 0x2C)  # [28] '5'
    flag.append((b0 + 0x76) & 0xFF)  # [29] 'T'
    flag.append(flag[17])             # [30] '1'
    flag.append(flag[28])             # [31] '5'
    flag.append((b1 - 0x41) & 0xFF)  # [32] 'l'
    flag.append(flag[9])              # [33] '0'
    flag.append(flag[28])             # [34] '5'
    flag.append((seed % 20) + 0x23)  # [35] '6'
    flag.append((b0 + 0x70) & 0xFF)  # [36] 'N'
    flag.append(flag[28])             # [37] '5'
    flag.append(flag[15])             # [38] '_'
    flag.append(flag[18])             # [39] 't'
    flag.append((b2 - 0x4B) & 0xFF)  # [40] 's'
    flag.append(flag[28])             # [41] '5'
    flag.append((seed % 100) + 0x1D)  # [42] 'X'
    flag.append((b1 - 0x46) & 0xFF)  # [43] 'g'
    flag.append(flag[28])             # [44] '5'
    flag.append(flag[35])             # [45] '6'
    flag.append((seed % 20) + 0x26)  # [46] '9'
    flag.append(flag[32])             # [47] 'l'
    flag.append((b2 - 0x48) & 0xFF)  # [48] 'v'
    flag.append(flag[13])             # [49] '3'
    flag.append(flag[27])             # [50] 'r'
    flag.append(flag[21])             # [51] 's'
    flag.append(flag[13])             # [52] '3'
    flag.append((seed % 100) - 0x1A)  # [53] '!'
    flag.append((b3 - 0x72) & 0xFF)  # [54] '}'
    
    return ''.join(chr(c) for c in flag)

# Main
flag = generate_flag(0xdeadbeef)
print(f"Generated: {flag}")
print(f"Length: {len(flag)}")

if test_flag(flag):
    print(f"\n{'='*70}")
    print(f"✓ FLAG: {flag}")
    print(f"{'='*70}")
else:
    print("\n[-] Not correct")
