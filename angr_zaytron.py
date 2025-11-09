#!/usr/bin/env python3
"""
Zaytron Angr Solver - Symbolically execute to find the flag
"""

try:
    import angr
    import claripy
except ImportError:
    print("[!] Angr not installed. Install with: pip install angr")
    exit(1)

def solve_zaytron():
    print("="*70)
    print("Zaytron Angr Solver")
    print("="*70)
    
    binary = '/workspaces/CTF-Playground/Zaytron'
    
    print("\n[*] Loading binary...")
    p = angr.Project(binary, auto_load_libs=False)
    
    # The seed is 0xdeadbeef (3735928559)
    seed = 3735928559
    
    # Create symbolic flag
    flag_len = 50  # Maximum reasonable flag length
    flag = claripy.BVS('flag', flag_len * 8)
    
    # Start from entry point
    state = p.factory.entry_state(
        stdin=angr.SimPackets(name='stdin'),
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY}
    )
    
    # Prepare input: seed + newline + flag + newline
    seed_str = f"{seed}\n"
    
    # Write seed to stdin first
    for i, c in enumerate(seed_str):
        state.posix.files[0].write(i, claripy.BVV(ord(c), 8), len(seed_str))
    
    # Write symbolic flag after seed
    offset = len(seed_str)
    for i in range(flag_len):
        b = flag.get_byte(i)
        # Constrain to printable ASCII
        state.solver.add(b >= 0x20)
        state.solver.add(b <= 0x7e)
    
    # Add newline after flag
    state.posix.files[0].write(offset + flag_len, claripy.BVV(ord('\n'), 8), 1)
    
    # Common flag format constraints
    # Try DeepSec{ format
    prefix = b"DeepSec{"
    for i, c in enumerate(prefix):
        state.solver.add(flag.get_byte(i) == c)
    
    # Ending with }
    state.solver.add(flag.get_byte(flag_len - 1) == ord('}'))
    
    print("[*] Starting symbolic execution...")
    simgr = p.factory.simulation_manager(state)
    
    # Look for success message
    def is_success(s):
        try:
            out = s.posix.dumps(1)
            return b'Congratulations' in out
        except:
            return False
    
    def is_failure(s):
        try:
            out = s.posix.dumps(1)
            return b'Sorry' in out or b'Invalid' in out
        except:
            return False
    
    try:
        simgr.explore(
            find=is_success,
            avoid=is_failure,
            num_find=1
        )
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    except Exception as e:
        print(f"[!] Error: {e}")
    
    if simgr.found:
        print("\n[+] Solution found!")
        found_state = simgr.found[0]
        solution = found_state.solver.eval(flag, cast_to=bytes)
        
        # Find the actual flag (stop at first null or non-printable)
        flag_str = ""
        for b in solution:
            if 32 <= b <= 126:
                flag_str += chr(b)
            else:
                break
        
        print(f"\n{'='*70}")
        print(f"FLAG: {flag_str}")
        print(f"{'='*70}")
        
        # Verify
        stdout = found_state.posix.dumps(1)
        print(f"\nBinary output:\n{stdout.decode(errors='replace')}")
        
        return flag_str
    else:
        print("\n[-] No solution found")
        print(f"Active: {len(simgr.active)}, Deadended: {len(simgr.deadended)}, Errored: {len(simgr.errored)}")
        
        # Show some debug info
        if simgr.deadended:
            print("\nSample deadended state:")
            try:
                s = simgr.deadended[0]
                print(s.posix.dumps(1)[:200])
            except:
                pass
    
    return None

if __name__ == "__main__":
    solve_zaytron()
