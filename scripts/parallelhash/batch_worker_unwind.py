"""Cleanup reachability from the native-spawn LSDA landing pad.

Follow ordinary branches and recorded LSDA may-edges. This does not establish
coverage of every throwing call, action/personality decisions, unwind argument
registers, CFI recovery or linked offsets. Valid buffer arguments and the reviewed
non-unwinding clear/deallocator contracts are assumed. Traps/abort are never
erasure evidence.
"""
import re

import batch_worker_lsda as lsda
from batch_worker_handoff import machine, require, successors


def inspect(body, clear, drop, noreturn, arm, apple):
    machine.inspect(body, clear, drop, noreturn, arm, apple)
    code, labels, raw, exceptional, records = lsda.parse(body, arm, apple)
    symbols = [machine.machine.call_symbol(op, args, arm, apple) for op, args in code]
    spawn = next(i for i, s in enumerate(symbols) if re.fullmatch(machine.inline.SPAWN, s or ''))
    require(exceptional.get(spawn) is not None, 'native spawn has a recorded unwind landing pad')
    edges = successors(code, labels, symbols, noreturn, arm)
    pending, seen, cleans, resumed = [(exceptional[spawn], True)], set(), set(), set()
    while pending:
        pc, dirty = state = pending.pop()
        require(0 <= pc < len(code), 'bounded worker unwind control flow')
        if state in seen:
            continue
        seen.add(state)
        symbol = symbols[pc]
        if pc == spawn:
            dirty = True
        cleanup = symbol == clear or (drop is not None and symbol == drop)
        # The exact qualified Storage cleanup calls use the separately reviewed
        # non-unwinding clear/deallocator contracts. LLVM can retain conservative
        # LSDA entries even without a nounwind attribute across crate boundaries.
        # Every other recorded exception transfers before that call returns.
        if exceptional.get(pc) is not None and not cleanup:
            pending.append((exceptional[pc], dirty))
        if cleanup:
            dirty = False
            cleans.add(pc)
        if symbol == '_Unwind_Resume' or code[pc][0] in ('ret', 'retq'):
            require(not dirty, 'machine unwind path escapes before worker cleanup')
            if symbol == '_Unwind_Resume':
                resumed.add(pc)
            continue
        pending.extend((next_pc, dirty) for next_pc in edges[pc])
    require(cleans and resumed, 'non-vacuous spawn unwind cleanup and resume')
    return len(seen), cleans, exceptional[spawn], raw, records


def check(row, panic):
    require(panic == 'unwind', 'exception recovery is not an abort-profile guarantee')
    return inspect(*machine.context(row, panic))


def replace_field(body, ordinal, field, replacement):
    lines = body.splitlines(keepends=True)
    begin = next(i for i, line in enumerate(lines) if re.fullmatch(r'\.?Lcst_begin\d+:', line.strip()))
    end = next(i for i, line in enumerate(lines) if re.fullmatch(r'\.?Lcst_end\d+:', line.strip()))
    entries = [i for i in range(begin + 1, end) if lines[i].strip()]
    require(len(entries) % 4 == 0, 'exact LSDA mutation record extent')
    lines[entries[ordinal * 4 + field]] = '\t' + replacement + '\n'
    return ''.join(lines)


def mutations(row):
    args = machine.context(row, 'unwind')
    states, cleanups, pad, raw, records = inspect(*args)
    body, clear, drop, noreturn, arm, apple = args
    _, ordinary, _ = machine.inspect(*args)
    exceptional_only = cleanups - ordinary
    require(exceptional_only, 'distinct unwind-only Storage cleanup site')
    changes = []
    lines = body.splitlines(keepends=True)
    for pc in sorted(exceptional_only):
        index, line = raw[pc]
        symbol = clear if clear in line else drop
        for replacement in (line.replace(symbol, symbol + '_omitted'), 'ret' if arm else 'retq'):
            changes.append((''.join(lines[:index] + [replacement + '\n'] + lines[index + 1:]),
                            'machine unwind path escapes before worker cleanup'))
    code, labels, _, _, _ = lsda.parse(body, arm, apple)
    symbols = [machine.machine.call_symbol(op, operands, arm, apple) for op, operands in code]
    spawn = next(i for i, symbol in enumerate(symbols) if re.fullmatch(machine.inline.SPAWN, symbol or ''))
    record = next(ordinal for start, end, _, ordinal in records if start <= spawn < end)
    removed = replace_field(replace_field(body, record, 2, '.byte 0'), record, 3, '.byte 0')
    changes.append((removed, 'native spawn has a recorded unwind landing pad'))
    resume = next(i for i, symbol in enumerate(symbols) if symbol == '_Unwind_Resume' and i > max(exceptional_only))
    target = max(((pc, name) for name, pc in labels.items() if pc <= resume), key=lambda pair: pair[0])[1]
    base = next(name for name in labels if re.fullmatch(r'\.?Lfunc_begin\d+', name))
    changes.append((replace_field(body, record, 2, f'.uleb128 {target}-{base}'),
                    'machine unwind path escapes before worker cleanup'))
    for changed, expected in changes:
        # Normal-return inspection must still pass: rejection must come from
        # the newly checked exceptional scope, not existing ordinary coverage.
        machine.inspect(changed, clear, drop, noreturn, arm, apple)
        try:
            inspect(changed, clear, drop, noreturn, arm, apple)
        except ValueError as error:
            require(expected in str(error), 'specific exceptional cleanup mutation failure')
        else:
            raise AssertionError('machine exception cleanup mutation survived')
    return states, len(records), len(changes)
