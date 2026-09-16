"""Machine CFG cleanup-call reachability on ordinary returning paths only.

Native thread creation marks storage dirty. Every subsequent normal return
must pass the exact separately-qualified clear/drop symbol. Data effects, call
arguments, exception tables, CFI recovery, worker joining and runtime linking
are NOT proved. Traps, noreturn callees, abort and infinite execution do not
establish erasure. Valid code/ABI and reviewed callee contracts are assumptions.
"""
import re

import batch_worker_machine_cfg as machine
from batch_worker_machine_cfg import inline, require
from batch_cleanup_flow import assembly_function


def inspect(body, clear, drop, noreturn, arm, apple):
    code, labels, raw = machine.parse(body, arm)
    symbols = [machine.call_symbol(op, args, arm, apple) for op, args in code]
    spawn = [pc for pc, symbol in enumerate(symbols) if re.fullmatch(inline.SPAWN, symbol or '')]
    require(len(spawn) == 1, 'one native spawn instruction in machine coordinator')
    pending, seen, sites, returns = [(0, False, False)], set(), set(), set()
    while pending:
        pc, active, dirty = state = pending.pop()
        require(0 <= pc < len(code), 'no machine fallthrough out of function')
        if state in seen:
            continue
        seen.add(state)
        op, args = code[pc]
        symbol = symbols[pc]
        if pc == spawn[0]:
            active = dirty = True
        elif symbol == clear or (drop is not None and symbol == drop):
            if active:
                sites.add(pc)
            dirty = False
        if op == ('ret' if arm else 'retq'):
            require(not dirty, 'machine normal return bypasses worker cleanup')
            if active:
                returns.add(pc)
            continue
        if op in ('brk', 'ud2') or symbol in noreturn:
            continue
        if op == ('b' if arm else 'jmp'):
            pending.append((labels[args[0]], active, dirty))
            continue
        if op in (machine.ARM_BRANCH | {'cbz', 'cbnz', 'tbz', 'tbnz'} if arm else machine.X86_BRANCH):
            pending.append((labels[args[-1]], active, dirty))
        pending.append((pc + 1, active, dirty))
    require(returns and len(sites) >= 2 and any(pc == spawn[0] for pc, _, _ in seen),
            'non-vacuous spawned machine normal/error cleanup')
    return len(seen), sites, raw


def context(row, panic):
    _, clear, drop, _ = inline.check(row, panic)
    triple = re.search(r'^target triple = "([\w.-]+)"$', row['ll'], re.M)
    require(triple and triple[1] in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-musl',
                                     'arm64-apple-macosx11.0.0'), 'reviewed coordinator machine target')
    body = assembly_function(row['s'], ('9execution5batch', '8Executor7execute'))
    return body, clear, drop, inline.cfg.noreturn_symbols(row['ll']), not triple[1].startswith('x86'), 'apple' in triple[1]


def check(row, panic):
    return inspect(*context(row, panic))


def mutations(row, panic):
    body, clear, drop, noreturn, arm, apple = args = context(row, panic)
    states, sites, raw = inspect(*args)
    count = 0
    for pc in sorted(sites):
        source_line, line = raw[pc]
        lines = body.splitlines(keepends=True)
        require(lines[source_line].strip() == line, 'exact machine cleanup mutation line')
        symbol = clear if clear in line else drop
        require(symbol is not None and symbol in line, 'exact machine cleanup identity')
        for replacement in (line.replace(symbol, symbol + '_omitted'), 'ret' if arm else 'retq'):
            changed = ''.join(lines[:source_line] + [replacement + '\n'] + lines[source_line + 1:])
            try:
                inspect(changed, clear, drop, noreturn, arm, apple)
            except ValueError as error:
                require('machine normal return bypasses worker cleanup' in str(error),
                        'assembly mutation must fail on the actual cleanup obligation')
                count += 1
            else:
                raise AssertionError('machine normal cleanup bypass survived')
    return states, count
