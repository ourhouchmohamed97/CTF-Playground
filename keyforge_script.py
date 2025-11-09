#!/usr/bin/env python3
# run_angr_keyforge.py
# Usage: ./run_angr_keyforge.py  (requires angr in current venv)
# Expects the unpacked binary at ./KeyForge_unpacked

import angr
import claripy
import logging
import sys
import time

logging.getLogger("angr").setLevel(logging.INFO)

BINARY = "./KeyForge_unpacked"    # adjust path if needed
FLAG_LEN = 36

def main():
    start_time = time.time()
    print("[*] Loading binary:", BINARY)
    p = angr.Project(BINARY, auto_load_libs=False)

    # symbolic stdin of FLAG_LEN bytes
    flag = claripy.BVS("flag", FLAG_LEN * 8)

    # create initial state using the stdin (posix)
    state = p.factory.full_init_state(stdin=flag)

    # add printable constraints
    for i in range(FLAG_LEN):
        b = flag.get_byte(i)
        state.solver.add(b >= 0x20)  # ' '
        state.solver.add(b <= 0x7e)  # '~'

    # enforce known prefix and suffix:
    prefix = b"DeepSec{"
    for i, c in enumerate(prefix):
        state.solver.add(flag.get_byte(i) == c)
    state.solver.add(flag.get_byte(FLAG_LEN - 1) == ord('}'))

    # OPTIONAL: if you want to force alnum+some special set for middle:
    # allowed = [ord(x) for x in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-!"]
    # for i in range(len(prefix), FLAG_LEN-1):
    #     state.solver.add(claripy.Or(*[flag.get_byte(i) == v for v in allowed]))

    simgr = p.factory.simulation_manager(state)

    print("[*] Beginning exploration (this may take time)...")
    # Try to find state where stdout contains 'valid' (as your README suggested)
    def is_success(s):
        try:
            out = s.posix.dumps(1)
            if b"valid" in out:
                return True
        except Exception:
            pass
        return False

    # tune parameters:
    # - step: number of steps before trimming (smaller for quick trimming)
    # - find: success condition
    # - avoid: optional addresses to skip (not used here)
    try:
        simgr.explore(find=is_success, timeout=60*10)  # 10-minute timeout as a safety cap
    except Exception as e:
        print("[!] explore() raised:", e)

    if simgr.found:
        found = simgr.found[0]
        try:
            solution = found.solver.eval(flag, cast_to=bytes)
            print("[+] Solution (raw bytes):", solution)
            try:
                print("[+] FLAG:", solution.decode(errors="replace"))
            except Exception:
                print("[+] FLAG (repr):", repr(solution))
        except Exception as e:
            print("[!] Could not evaluate flag:", e)
    else:
        print("[-] No solution found in this run.")
        # useful debugging info:
        print("[*] Active states:", len(simgr.active))
        for i, s in enumerate(simgr.active[:5]):
            try:
                print(f"  - active[{i}] PC={hex(s.solver.eval(s.regs.pc))}, stdout snippet: {s.posix.dumps(1)[:200]!r}")
            except Exception:
                pass

    print("[*] Elapsed time: {:.1f}s".format(time.time() - start_time))

if __name__ == "__main__":
    main()
