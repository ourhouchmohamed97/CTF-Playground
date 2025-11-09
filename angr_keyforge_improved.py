#!/usr/bin/env python3
"""
Improved Angr solver for KeyForge
Strategy: Hook the validation function and add constraints directly
"""

import angr
import claripy
import logging

# Reduce angr verbosity
logging.getLogger("angr").setLevel(logging.WARNING)
logging.getLogger("claripy").setLevel(logging.WARNING)

BINARY = "./KeyForge_unpacked"
FLAG_LEN = 36

def main():
    print("[*] Loading binary:", BINARY)
    p = angr.Project(BINARY, auto_load_libs=False)
    
    # Find key addresses by analyzing the binary
    # The main function calls validate_flag, let's find that
    cfg = p.analyses.CFGFast()
    
    # Look for the validation function
    validation_func = None
    for func in cfg.functions.values():
        if 'validate' in func.name.lower() or func.addr == 0x4055da:
            validation_func = func
            print(f"[*] Found validation function at: {hex(func.addr)}")
            break
    
    # Create symbolic flag
    flag = claripy.BVS("flag", FLAG_LEN * 8)
    
    # Start from main with symbolic stdin
    state = p.factory.entry_state(
        stdin=angr.SimFile('/dev/stdin', content=flag, size=FLAG_LEN),
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY}
    )
    
    # Constrain the flag
    # Known prefix: DeepSec{
    prefix = b"DeepSec{"
    for i, c in enumerate(prefix):
        state.solver.add(flag.get_byte(i) == c)
    
    # Known suffix: }
    state.solver.add(flag.get_byte(FLAG_LEN - 1) == ord('}'))
    
    # Middle characters must be printable and reasonable
    for i in range(len(prefix), FLAG_LEN - 1):
        b = flag.get_byte(i)
        # Alphanumeric + underscore + common symbols
        state.solver.add(
            claripy.Or(
                claripy.And(b >= ord('a'), b <= ord('z')),
                claripy.And(b >= ord('A'), b <= ord('Z')),
                claripy.And(b >= ord('0'), b <= ord('9')),
                b == ord('_'),
                b == ord('-'),
                b == ord('!'),
                b == ord('@')
            )
        )
    
    # Create simulation manager
    simgr = p.factory.simulation_manager(state)
    
    print("[*] Exploring (looking for 'valid' or 'correct' in output)...")
    
    # Define success condition
    def is_success(state):
        stdout = state.posix.dumps(1)
        # Check for success messages
        if b'valid!' in stdout.lower() or b'correct' in stdout.lower():
            if b'failed' not in stdout.lower() and b'invalid' not in stdout.lower():
                return True
        return False
    
    def is_failure(state):
        stdout = state.posix.dumps(1)
        return b'failed' in stdout.lower() or b'Invalid' in stdout
    
    try:
        # Explore with pruning
        simgr.explore(
            find=is_success,
            avoid=is_failure,
            num_find=1
        )
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"[!] Error during exploration: {e}")
    
    # Check results
    if simgr.found:
        print("[+] Found solution!")
        found_state = simgr.found[0]
        solution = found_state.solver.eval(flag, cast_to=bytes)
        try:
            flag_str = solution.decode('ascii')
            print(f"\n{'='*60}")
            print(f"FLAG: {flag_str}")
            print(f"{'='*60}")
        except:
            print(f"FLAG (raw): {solution}")
        
        # Show output
        stdout = found_state.posix.dumps(1)
        print(f"\nBinary output: {stdout.decode(errors='replace')}")
        
    else:
        print("[-] No solution found")
        print(f"[*] Active states: {len(simgr.active)}")
        print(f"[*] Deadended states: {len(simgr.deadended)}")
        print(f"[*] Errored states: {len(simgr.errored)}")
        
        # Show some active states for debugging
        if simgr.active:
            print("\n[*] Sample active state outputs:")
            for i, s in enumerate(simgr.active[:3]):
                try:
                    out = s.posix.dumps(1)
                    print(f"  State {i}: {out[:100]}")
                except:
                    pass

if __name__ == "__main__":
    main()
