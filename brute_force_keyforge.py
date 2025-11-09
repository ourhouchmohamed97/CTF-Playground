#!/usr/bin/env python3
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
            timeout=1
        )
        output = result.stdout.decode() + result.stderr.decode()
        return output
    except:
        return ""

# We know:
# - Format: DeepSec{...} (36 chars total, so 28 chars inside braces)
# - Last char is }
# - Internal chars are validated

print("Testing known format...")
test = "DeepSec{AAAAAAAAAAAAAAAAAAAAAAAAAAAA}"
output = test_flag(test)
print(f"Test input: {test}")
print(f"Output: {output}")

# Try some common patterns
patterns = [
    "DeepSec{test_flag_here_1234567890123}",  # Numbers
    "DeepSec{AAAAAAAAAAAAAAAAAAAAAAAAAAAAA}",  # All A
    "DeepSec{flag_goes_here_xxxxxxxxxxxx}",   # Underscores
]

for pattern in patterns:
    if len(pattern) != 36:
        pattern = pattern[:36].ljust(36, 'X')
        pattern = pattern[:35] + '}'
    output = test_flag(pattern)
    print(f"\nPattern: {pattern}")
    print(f"Output: {output}")
