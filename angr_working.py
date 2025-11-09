#!/usr/bin/env python3
"""
Working Angr solver for KeyForge - Simplified approach
"""

import angr
import claripy
import sys

BINARY = "./KeyForge_unpacked"
FLAG_LEN = 36

def main():
    print("[*] Loading binary:", BINARY)
    
    # Load project
    p = angr.Project(BINARY, auto_load_libs=False)
    
    # Create symbolic input for the flag
    flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(FLAG_LEN)]
    flag = claripy.Concat(*flag_chars)
    
    # Create initial state with symbolic stdin
    newline = claripy.BVV(ord('\n'), 8)
    stdin_content = claripy.Concat(flag, newline)
    
    state = p.factory.entry_state(
        stdin=angr.SimFile('/dev/stdin', content=stdin_content)
    )
    
    # Add constraints
    print("[*] Adding constraints...")
    
    # Known prefix: "DeepSec{"
    prefix = b"DeepSec{"
    for i in range(len(prefix)):
        state.solver.add(flag_chars[i] == prefix[i])
    
    # Known suffix: "}"
    state.solver.add(flag_chars[FLAG_LEN - 1] == ord('}'))
    
    # Middle characters: printable ASCII only
    for i in range(len(prefix), FLAG_LEN - 1):
        state.solver.add(flag_chars[i] >= 0x20)
        state.solver.add(flag_chars[i] <= 0x7e)
        # More restrictive: alphanumeric + underscore + dash
        state.solver.add(
            claripy.Or(
                claripy.And(flag_chars[i] >= ord('a'), flag_chars[i] <= ord('z')),
                claripy.And(flag_chars[i] >= ord('A'), flag_chars[i] <= ord('Z')),
                claripy.And(flag_chars[i] >= ord('0'), flag_chars[i] <= ord('9')),
                flag_chars[i] == ord('_'),
                flag_chars[i] == ord('-'),
                flag_chars[i] == ord('!')
            )
        )
    
    # Create simulation manager
    simgr = p.factory.simulation_manager(state)
    
    print("[*] Starting symbolic execution...")
    print("[*] This may take several minutes...")
    
    # Define success and failure conditions
    def check_success(state):
        try:
            output = state.posix.dumps(1)
            return b'License valid!' in output
        except:
            return False
    
    def check_failure(state):
        try:
            output = state.posix.dumps(1)
            return b'Invalid format' in output or b'validation failed' in output
        except:
            return False
    
    # Run exploration
    try:
        simgr.explore(
            find=check_success,
            avoid=check_failure,
            num_find=1
        )
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")
    
    # Check results
    if simgr.found:
        print("\n[+] SUCCESS! Found valid input!")
        found_state = simgr.found[0]
        
        # Extract the flag
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
        
        # Show binary output
        try:
            output = found_state.posix.dumps(1)
            print(f"\nBinary output:\n{output.decode('ascii', errors='replace')}")
        except:
            pass
        
        return flag_str
    else:
        print("\n[-] No solution found")
        print(f"Active states: {len(simgr.active)}")
        print(f"Deadended states: {len(simgr.deadended)}")
        print(f"Errored states: {len(simgr.errored)}")
        
        if simgr.errored:
            print("\nErrors encountered:")
            for i, err in enumerate(simgr.errored[:3]):
                print(f"  Error {i}: {err.error}")
        
        return None

if __name__ == "__main__":
    main()
