"""Local exception-only Storage destructor argument handoff.

Assumes the unwinder restores this function's stack frame and ordinary callees
preserve it. This does not validate CFI, preceding header writes/aliases, buffer
provenance, indirect callees or runtime unwinding. The original empty header is
anchored independently of the destructor. A single-entry, call-free suffix must
construct its full-width address on every recorded incoming edge.
"""
import re

import batch_worker_arm_flow as flow
import batch_worker_handoff as handoff
import batch_worker_unwind as unwind
from batch_cleanup_flow import require


def combined_edges(code, labels, symbols, covered, clear, drop, noreturn, arm):
    edges = handoff.successors(code, labels, symbols, noreturn, arm)
    for pc, pad in covered.items():
        # Same separately reviewed non-unwinding cleanup contract as reachability.
        if pad is not None and symbols[pc] not in (clear, drop):
            edges[pc] = tuple(set((*edges[pc], pad)))
    return edges


def owner(code, edges, spawn, arm):
    if not arm:
        return handoff.owner(code, edges, spawn, False)
    candidates = []
    for pc, (op, args) in enumerate(code):
        if op != 'stp' or len(args) != 3 or args[0] != 'xzr' or not re.fullmatch(r'x\d+', args[1]):
            continue
        offset = handoff.stack_offset(args[2], True)
        if offset is None:
            continue
        for start in range(max(0, pc - 5), pc):
            if code[start] != ('mov', ['w' + args[1][1:], '#1']):
                continue
            # W-register assignment of literal one defines the full X value.
            facts = {args[1]: ('dangling', 1)}
            valid = True
            for i in range(start, pc):
                if edges[i] != (i + 1,) or any(i + 1 in targets for p, targets in edges.items() if p != i):
                    valid = False
                if i > start:
                    facts = flow.step(*code[i], facts)
            if valid and facts.get(args[1]) == ('dangling', 1):
                candidates.append((pc, offset))
    require(len(candidates) == 1, 'one independent exception Storage header')
    initial, root = candidates[0]
    require(handoff.reaches(edges, 0, initial) and not handoff.reaches(edges, 0, spawn, initial),
            'exception Storage header initialization dominates spawning')
    return initial, root


def inspect(body, clear, drop, noreturn, arm, apple):
    _, all_sites, _, _, _ = unwind.inspect(body, clear, drop, noreturn, arm, apple, from_entry=True)
    _, ordinary, _ = handoff.machine.inspect(body, clear, drop, noreturn, arm, apple)
    sites = all_sites - ordinary
    require(sites and drop is not None, 'non-vacuous exception-only Storage destructor')
    code, labels, raw, covered, _ = unwind.lsda.parse(body, arm, apple)
    symbols = [handoff.machine.machine.call_symbol(*instruction, arm, apple) for instruction in code]
    require(all(symbols[pc] == drop for pc in sites), 'retained destructor on exception-only paths')
    spawn = next(pc for pc, symbol in enumerate(symbols) if re.fullmatch(handoff.machine.inline.SPAWN, symbol or ''))
    edges = combined_edges(code, labels, symbols, covered, clear, drop, noreturn, arm)
    initial, root = owner(code, edges, spawn, arm)
    handoff.stable_frame(code, edges, initial, sites, arm)
    active = handoff.reachable(edges, spawn)
    setups = {}
    for pc in sites:
        for start in range(max(0, pc - 8), pc):
            if start not in active or any(edges[i] != (i + 1,) or any(
                    i + 1 in targets for p, targets in edges.items() if p != i and p in active)
                    for i in range(start, pc)):
                continue
            try:
                args = handoff.prefix(code, start, pc, root, arm)
            except ValueError:
                continue
            if args[0] == ('address', root):
                setups[pc] = start
                break
        require(pc in setups, 'exception destructor must receive original full-width owner address')
    return root, setups, raw


def mutations(row):
    args = handoff.machine.context(row, 'unwind')
    root, sites, raw = inspect(*args)
    body, clear, drop, noreturn, arm, apple = args
    lines = body.splitlines(keepends=True)
    count = 0
    for pc in sites:
        index, _ = raw[pc]
        injections = (('mov x0, xzr', 'add x0, x0, #8', 'mov w0, w0', 'blr x8') if arm else
                      ('xorl %edi, %edi', 'addq $8, %rdi', 'movl %edi, %edi', 'callq *%rax'))
        changes = [''.join(lines[:index] + [injected + '\n'] + lines[index:]) for injected in injections]
        # Current rows form the owner address immediately before the call.
        setup_index, setup = raw[pc - 1]
        old = f'#{root}' if arm else f'{root}(%rsp)'
        new = f'#{root + 8}' if arm else f'{root + 8}(%rsp)'
        require(old in setup, 'emitted exception owner address mutation site')
        changes.append(''.join(lines[:setup_index] + [setup.replace(old, new) + '\n'] + lines[setup_index + 1:]))
        # Landing directly on the call preserves cleanup reachability, but
        # bypasses the mandatory argument setup. Keep the call inventory intact.
        code, labels, _, _, records = unwind.lsda.parse(body, arm, apple)
        spawn = next(i for i, instruction in enumerate(code) if re.fullmatch(
            handoff.machine.inline.SPAWN, handoff.machine.machine.call_symbol(*instruction, arm, apple) or ''))
        ordinal = next(n for start, end, _, n in records if start <= spawn < end)
        base = next(name for name in labels if re.fullmatch(r'\.?Lfunc_begin\d+', name))
        label = 'Ltmp900000'
        require(label not in body, 'fresh exception mutation label')
        changed = ''.join(lines[:index] + [label + ':\n'] + lines[index:])
        changes.append(unwind.replace_field(changed, ordinal, 2, f'.uleb128 {label}-{base}'))
        for changed in changes:
            unwind.inspect(changed, clear, drop, noreturn, arm, apple, from_entry=True)
            try:
                inspect(changed, clear, drop, noreturn, arm, apple)
            except ValueError as error:
                require('exception destructor must receive' in str(error), 'specific exception argument rejection')
            else:
                raise AssertionError('exception-only destructor argument mutant survived')
            count += 1
    return root, len(sites), count
