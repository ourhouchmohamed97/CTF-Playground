#!/usr/bin/env python3
"""
Targeted Angr approach - Start execution at validation function
"""

import angr
import claripy

BINARY = "./KeyForge_unpacked"
FLAG_LEN = 36

def main():
    print("[*] Loading binary...")
    p = angr.Project(BINARY, auto_load_libs=False)
    
    # Create symbolic flag
    flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(FLAG_LEN)]
    
    # Add constraints immediately
    print("[*] Setting up constraints...")
    
    # Prefix: DeepSec{
    prefix = b"DeepSec{"
    constraints = []
    for i in range(len(prefix)):
        constraints.append(flag_chars[i] == prefix[i])
    
    # Suffix: }
    constraints.append(flag_chars[FLAG_LEN - 1] == ord('}'))
    
    # Middle: alphanumeric + _
    for i in range(len(prefix), FLAG_LEN - 1):
        constraints.append(
            claripy.Or(
                claripy.And(flag_chars[i] >= ord('a'), flag_chars[i] <= ord('z')),
                claripy.And(flag_chars[i] >= ord('A'), flag_chars[i] <= ord('Z')),
                claripy.And(flag_chars[i] >= ord('0'), flag_chars[i] <= ord('9')),
                flag_chars[i] == ord('_')
            )
        )
    
    # Try with blank state and simpler approach
    print("[*] Creating blank state at entry...")
    state = p.factory.blank_state(addr=p.entry)
    
    # Add all constraints
    for c in constraints:
        state.solver.add(c)
    
    # Allocate memory for flag and put it there
    flag_addr = 0x1000000  # Arbitrary address
    flag_bv = claripy.Concat(*flag_chars)
    state.memory.store(flag_addr, flag_bv)
    
    # Set up registers as if we're calling the validation function
    # We need to find the validation function address first
    cfg = p.analyses.CFGFast()
    
    validation_addr = None
    for func_addr, func in cfg.functions.items():
        if 'sub_4055da' in str(func) or func_addr == 0x4055da:
            validation_addr = func_addr
            break
    
    if not validation_addr:
        # Try to find by looking for the function that checks the flag
        print("[!] Could not find validation function, using heuristic...")
        validation_addr = 0x1280  # From the decompilation, adjust as needed
    
    print(f"[*] Validation function at: {hex(validation_addr)}")
    
    # Actually, let's try a completely different approach
    # Use angr's calling convention to call the validation function directly
    print("\n[*] Trying direct function call approach...")
    
    call_state = p.factory.call_state(
        validation_addr,
        flag_addr,
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY}
    )
    
    # Add constraints to call state
    flag_bv2 = claripy.Concat(*flag_chars)
    call_state.memory.store(flag_addr, flag_bv2)
    
    for c in constraints:
        call_state.solver.add(c)
    
    # Add constraint that function returns 1 (success)
    simgr = p.factory.simulation_manager(call_state)
    
    print("[*] Exploring from validation function...")
    
    def is_success(state):
        # Function should return 1 in rax
        return state.solver.is_true(state.regs.rax == 1)
    
    try:
        simgr.explore(find=is_success, num_find=1)
    except Exception as e:
        print(f"[!] Error: {e}")
    
    if simgr.found:
        print("\n[+] Found solution!")
        found_state = simgr.found[0]
        
        flag_bytes = []
        for i in range(FLAG_LEN):
            try:
                byte_val = found_state.solver.eval(flag_chars[i])
                flag_bytes.append(byte_val)
            except:
                flag_bytes.append(ord('?'))
        
        flag_str = bytes(flag_bytes).decode('ascii', errors='replace')
        
        print(f"\n{'='*70}")
        print(f"FLAG: {flag_str}")
        print(f"{'='*70}")
        
        # Verify with the binary
        import subprocess
        try:
            result = subprocess.run(
                ['./KeyForge_unpacked'],
                input=flag_str.encode() + b'\n',
                capture_output=True,
                timeout=2,
                cwd='/workspaces/CTF-Playground'
            )
            print(f"\nVerification: {result.stdout.decode()}")
        except:
            pass
        
        return flag_str
    else:
        print("\n[-] No solution found with direct call approach")
        print(f"Deadended: {len(simgr.deadended)}, Errored: {len(simgr.errored)}")
        
        # Fall back to brute force with hints
        print("\n[*] Angr failed. Falling back to intelligent brute force...")
        print("[*] Based on the validation algorithms, trying common patterns...")
        
        return None

if __name__ == "__main__":
    main()
