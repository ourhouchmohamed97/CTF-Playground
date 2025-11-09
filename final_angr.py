#!/usr/bin/env python3
import angr
import claripy

p = angr.Project('./KeyForge_unpacked', auto_load_libs=False)

# Create 36-byte symbolic input
flag = claripy.BVS('flag', 8 * 36)

# Create state with symbolic stdin
state = p.factory.entry_state(stdin=angr.SimPackets.from_one_packet(flag))

# Add format constraints
for i, c in enumerate(b"DeepSec{"):
    state.solver.add(flag.get_byte(i) == c)

state.solver.add(flag.get_byte(35) == ord('}'))

# Middle chars printable
for i in range(8, 35):
    b = flag.get_byte(i)
    state.solver.add(b >= 0x20)
    state.solver.add(b <= 0x7e)

simgr = p.factory.simulation_manager(state)

# Find "License valid!" address (from disassembly: 0x1137)
# But since it's PIE, we need the relative address
# The puts call is at 0x113e, so we target that
simgr.explore(find=lambda s: b"License valid" in s.posix.dumps(1))

if simgr.found:
    s = simgr.found[0]
    print("[+] Found solution!")
    solution = s.solver.eval(flag, cast_to=bytes)
    print(f"FLAG: {solution.decode('utf-8', errors='replace')}")
else:
    print("[-] No solution found")
    print(f"Active: {len(simgr.active)}, Deadended: {len(simgr.deadended)}")

