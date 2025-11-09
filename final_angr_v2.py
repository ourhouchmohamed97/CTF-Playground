#!/usr/bin/env python3
import angr
import claripy

p = angr.Project('./KeyForge_unpacked', auto_load_libs=False)

# Create 37-byte symbolic input (36 chars + newline)
flag_chars = [claripy.BVS(f'c{i}', 8) for i in range(36)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(ord('\n'), 8)])

# Create state with symbolic stdin
state = p.factory.entry_state(stdin=angr.SimFile('/dev/stdin', content=flag, size=37))

# Add format constraints
for i, c in enumerate(b"DeepSec{"):
    state.solver.add(flag_chars[i] == c)

state.solver.add(flag_chars[35] == ord('}'))

# Middle chars printable
for i in range(8, 35):
    state.solver.add(flag_chars[i] >= 0x20)
    state.solver.add(flag_chars[i] <= 0x7e)

simgr = p.factory.simulation_manager(state)

print("[*] Exploring...")
simgr.explore(find=lambda s: b"License valid" in s.posix.dumps(1))

if simgr.found:
    s = simgr.found[0]
    print("[+] Found solution!")
    solution = b''.join(s.solver.eval(c, cast_to=bytes) for c in flag_chars)
    print(f"FLAG: {solution.decode('utf-8', errors='replace')}")
else:
    print("[-] No solution found")
    print(f"Active: {len(simgr.active)}, Deadended: {len(simgr.deadended)}, Errored: {len(simgr.errored)}")

