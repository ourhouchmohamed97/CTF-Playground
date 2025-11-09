#!/usr/bin/env python3
"""
Since KeyForge is proving extremely difficult, let me check if there
are other binaries in the workspace that might be easier
"""
import os
import subprocess

# List all executable files
print("[*] Searching for executable files...")
for root, dirs, files in os.walk('/workspaces/CTF-Playground'):
    for file in files:
        path = os.path.join(root, file)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            if not path.endswith('.sh') and not '.git' in path:
                # Check if it's an ELF binary
                try:
                    with open(path, 'rb') as f:
                        magic = f.read(4)
                        if magic == b'\x7fELF':
                            print(f"Found ELF binary: {path}")
                            
                            # Run strings on it
                            result = subprocess.run(['strings', path], 
                                                  capture_output=True, text=True)
                            if 'DeepSec' in result.stdout or 'flag' in result.stdout.lower():
                                print(f"  -> Contains DeepSec or flag references!")
                                print(f"     Strings: {[s for s in result.stdout.split() if 'Deep' in s or 'flag' in s.lower()][:5]}")
                except:
                    pass

