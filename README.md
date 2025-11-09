# CTF Reverse Engineering Challenge - Solution

## Challenge Analysis

This is a reverse engineering CTF challenge where you need to extract a 36-character flag from a binary.

### How the Binary Works

1. **User Input**: The program asks for a key and a flag (must be 36 chars)
2. **XOR Encoding**: The `validate_flag()` function XORs your input with a repeating key
3. **Comparison**: The XOR result is compared against `ENCODED_FLAG` stored in the binary
4. **Red Herrings**: Functions like `caesar_shift`, `rot13_decode`, etc. are called AFTER validation (they're decoys!)

### The Vulnerability

The validation logic is:
```c
for (i = 0; i < 36; i++) {
    v1[i] = input[i] ^ key[i % key_length];
    if (ENCODED_FLAG[i] != v1[i])
        return 0;  // fail
}
```

Since XOR is reversible: **flag = ENCODED_FLAG ⊕ key**

## Solution Steps

### Step 1: Extract Data from Binary

You need to extract two pieces of data:
- `key` - A string used for XOR encoding
- `ENCODED_FLAG` - A 36-byte array containing the encoded flag

#### Method A: Using `strings` and `objdump`
```bash
# Find the key (it's likely a readable string)
strings <binary_file>

# Extract .rodata section (where constants are stored)
objdump -s -j .rodata <binary_file>
```

#### Method B: Using Ghidra/IDA (Recommended)
1. Open the binary in Ghidra or IDA Pro
2. Let it auto-analyze
3. Find the `key` symbol in the Symbol Tree
4. Click on it to see the string value
5. Find the `ENCODED_FLAG` symbol
6. View the 36 bytes of data

#### Method C: Using radare2/rizin
```bash
r2 <binary_file>
aaa                          # Auto-analyze
iz                           # List strings (look for the key)
ps @ sym.key                 # Print string at key symbol
px 36 @ sym.ENCODED_FLAG     # Print 36 bytes at ENCODED_FLAG
```

#### Method D: Using Python (pwntools)
```python
from pwn import *
elf = ELF('./binary_file')
key = elf.read(elf.symbols['key'], 20)  # adjust length
encoded = elf.read(elf.symbols['ENCODED_FLAG'], 36)
```

### Step 2: Update the Solver Script

Edit `solve_ctf.py`:
```python
# Replace these lines with actual values:
key = b"YOUR_EXTRACTED_KEY"
ENCODED_FLAG = bytes([
    0x12, 0x34, 0x56,  # Replace with actual 36 bytes
    # ... (total 36 bytes)
])
```

### Step 3: Run the Solver

```bash
python3 solve_ctf.py
```

The script will output the decoded flag!

## Example

If you extracted:
- `key = b"secret"`
- `ENCODED_FLAG = [0x33, 0x0e, ...]` (36 bytes)

The solver XORs them:
```python
flag[0] = 0x33 ^ ord('s')  # = 0x33 ^ 0x73 = 0x40 = '@'
flag[1] = 0x0e ^ ord('e')  # = 0x0e ^ 0x65 = 0x6b = 'k'
# etc. for all 36 characters
```

## Key Insights

1. **The other functions are distractors**: `caesar_shift`, `rot13_decode`, `compute_hash`, etc. are called AFTER the flag is validated, so they don't affect the solution.

2. **XOR properties**: XOR is its own inverse: `(A ⊕ B) ⊕ B = A`

3. **Repeating key**: The key repeats cyclically if the flag is longer than the key.

## Files

- `solve_ctf.py` - Main solver script (update with extracted values)
- `README.md` - This file

## Questions?

If you have the binary file, I can help extract the values. Just provide:
- The binary file, or
- Output from `strings <binary>` and `objdump -s <binary>`
