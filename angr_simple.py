#!/usr/bin/env python3
"""
Simple Angr approach - just find the success path
"""

import angr
import claripy
import sys

BINARY = "./KeyForge_unpacked"

def main():
    print("[*] Loading binary...")
    p = angr.Project(BINARY, auto_load_libs=False)
    
    # Find addresses of the success and failure strings
    # "License valid!" and "License validation failed."
    
    print("[*] Finding string addresses...")
    
    # Create initial state
    state = p.factory.entry_state()
    
    # Find the address that prints "License valid!"
    # From our analysis, it's at 0x1137 (loads string at 0x2033)
    success_addr = 0x1137
    fail_addr = 0x111d  # "License validation failed"
    invalid_addr = 0x1147  # "Invalid format"
    
    print(f"[*] Success address: 0x{success_addr:x}")
    print(f"[*] Fail addresses: 0x{fail_addr:x}, 0x{invalid_addr:x}")
    
    # Create simulation manager
    simgr = p.factory.simulation_manager(state)
    
    print("[*] Exploring to find success path...")
    print("[*] This may take a while...")
    
    # Explore
    simgr.explore(
        find=success_addr,
        avoid=[fail_addr, invalid_addr]
    )
    
    if simgr.found:
        print("\n[+] Found path to success!")
        found_state = simgr.found[0]
        
        # Try to get the stdin
        stdin_content = found_state.posix.dumps(0)
        print(f"\n[+] Input that leads to success:")
        print(stdin_content)
        
        # Try to extract as string
        try:
            flag = stdin_content.decode('utf-8', errors='replace').strip()
            print(f"\n[+] FLAG: {flag}")
        except:
            print(f"\n[+] Raw bytes: {stdin_content.hex()}")
    else:
        print("\n[!] No path found to success")
        print(f"[*] Active paths: {len(simgr.active)}")
        print(f"[*] Deadended: {len(simgr.deadended)}")
        print(f"[*] Errored: {len(simgr.errored)}")

if __name__ == "__main__":
    main()
