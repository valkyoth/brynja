"""Arm scalar/register/spill argument preservation on ordinary machine paths.

Assumes valid compiler/Vec allocation ABI, non-aliasing private spill storage
and reviewed ordinary callee memory effects. This does NOT prove preceding
input-plan arithmetic, all memory aliases, joining, or exception recovery.
"""
import re
from collections import deque

import batch_worker_arm_flow as flow
import batch_worker_arm_roots as roots
from batch_worker_handoff import machine, require, successors, stable_frame


def inspect(body, clear, drop, noreturn, arm, apple):
    require(arm, 'register-held Arm machine arguments')
    _, sites, _ = machine.inspect(body, clear, drop, noreturn, arm, apple)
    code, labels, raw = machine.machine.parse(body, arm)
    symbols = [machine.machine.call_symbol(op, args, arm, apple) for op, args in code]
    spawn = next(i for i, s in enumerate(symbols) if re.fullmatch(machine.inline.SPAWN, s or ''))
    edges = successors(code, labels, symbols, noreturn, arm)
    seeds, grow, result = roots.roots(code, labels, edges, symbols, spawn)
    stable_frame(code, edges, min(seeds), sites, True)
    require(all(symbols[pc] == clear for pc in sites), 'direct scalar machine cleanup calls')
    states, pending, updates = {(0, False): {}}, deque([(0, False)]), 0
    while pending:
        pc, active = key = pending.popleft()
        outgoing = flow.step(*code[pc], states[key])
        if pc in seeds:
            kind, register = seeds[pc]
            require(not active, 'machine owner initialization precedes spawning')
            outgoing[register] = (kind, 0)
        if pc == grow:
            # The allocator may overwrite its full 24-byte result temporary.
            outgoing = {k: v for k, v in outgoing.items() if not (
                isinstance(k, int) and k < result + 24 and result < k + 8)}
        active = active or pc == spawn
        for successor in edges[pc]:
            key = successor, active
            old = states.get(key)
            merged = outgoing if old is None else {k: v for k, v in old.items() if outgoing.get(k) == v}
            if old is None or old != merged:
                states[key] = dict(merged)
                pending.append(key)
                updates += 1
                require(updates <= 200000, 'bounded machine argument fixed point')
    require((grow, False) in states and states[grow, False].get('x3') == ('count', 0),
            'machine allocation receives original full slot count')
    for pc in sites:
        facts = states.get((pc, True), {})
        require(facts.get('x0') == ('base', 0) and facts.get('x1') == ('count', 0),
                'machine cleanup must receive original base and full count')
    return len(states), sites, seeds, raw


def check(row, panic):
    return inspect(*machine.context(row, panic))


def mutations(row, panic):
    args = machine.context(row, panic)
    states, sites, seeds, raw = inspect(*args)
    body, clear, drop, noreturn, arm, apple = args
    lines = body.splitlines(keepends=True)
    changes = []
    for pc in sorted(sites):
        index, _ = raw[pc]
        for injected in ('mov x0, xzr', 'mov x1, xzr', 'add x0, x0, #256', 'sub x1, x1, #1',
                         'mov w0, w0', 'mov w1, w1', 'blr x8'):
            changes.append(''.join(lines[:index] + [injected + '\n'] + lines[index:]))
    for pc, (kind, register) in seeds.items():
        index, _ = raw[pc]
        if kind == 'base' and 'mov' in raw[pc][1]:
            continue  # Empty initialization shape has separate structural tests.
        # Redefine each independently anchored value after its initialization.
        changes.append(''.join(lines[:index + 1] + [f'mov {register}, xzr\n'] + lines[index + 1:]))
    for changed in changes:
        try:
            inspect(changed, clear, drop, noreturn, arm, apple)
        except ValueError as error:
            require('machine cleanup must receive' in str(error) or
                    'allocation receives original' in str(error), 'actual argument-provenance mutation failure')
        else:
            raise AssertionError('Arm register/spill argument mutant survived')
    return states, len(sites), len(changes)
