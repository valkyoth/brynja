"""Cross-artifact invoke inventory and post-spawn exceptional cleanup.

The inventory compares multiplicities, not individual call-site identity or
indirect target provenance. LLVM invoke sites and assembly LSDA entries must
agree; omitted LLVM invokes, callee behavior, CFI and linked unwinding remain
outside this check. Clear/deallocator non-unwinding contracts are assumed.
"""
from collections import Counter
import re

import batch_worker_unwind as unwind
from batch_cleanup_flow import require


def inventory(llvm_body, body, arm, apple):
    cfg = unwind.machine.inline.cfg
    blocks, _, _ = cfg.parse(llvm_body)
    expected = Counter(cfg.callee(line) for lines in blocks.values() for line in lines
                       if cfg.operation(line).startswith('invoke '))
    code, _, _, covered, _ = unwind.lsda.parse(body, arm, apple)
    actual = Counter(unwind.machine.machine.call_symbol(*code[pc], arm, apple)
                     for pc, pad in covered.items() if pad is not None)
    require(expected and expected == actual, 'LLVM invoke / machine landing-pad inventory mismatch')
    return sum(expected.values())


def inspect(llvm_body, body, clear, drop, noreturn, arm, apple):
    count = inventory(llvm_body, body, arm, apple)
    states, cleanups, _, _, _ = unwind.inspect(body, clear, drop, noreturn, arm, apple, from_entry=True)
    return count, states, cleanups


def mutations(row):
    llvm_body, _, _, _ = unwind.machine.inline.check(row, 'unwind')
    args = unwind.machine.context(row, 'unwind')
    count, states, _ = inspect(llvm_body, *args)
    body, clear, drop, noreturn, arm, apple = args
    code, labels, _, covered, records = unwind.lsda.parse(body, arm, apple)
    symbols = [unwind.machine.machine.call_symbol(*instruction, arm, apple) for instruction in code]
    tested = 0
    # Remove each nonzero call-site entry independently, including entries for
    # indirect calls and noreturn invokes. Noreturn does not mean nounwind.
    for start, end, pad, ordinal in records:
        if pad is None or not any(start <= pc < end for pc in covered):
            continue
        changed = unwind.replace_field(unwind.replace_field(body, ordinal, 2, '.byte 0'), ordinal, 3, '.byte 0')
        try:
            inventory(llvm_body, changed, arm, apple)
        except ValueError as error:
            require('inventory mismatch' in str(error), 'specific missing invoke coverage rejection')
        else:
            raise AssertionError('missing invoke landing-pad coverage survived')
        tested += 1
    # Redirect a later throwing thread-join call to resume without cleanup.
    joins = [pc for pc, symbol in enumerate(symbols) if symbol and '6Thread4join' in symbol]
    require(len(joins) == 1 and covered.get(joins[0]) is not None, 'one recorded throwing thread join')
    ordinal = next(n for start, end, _, n in records if start <= joins[0] < end)
    resume = next(pc for pc, symbol in enumerate(symbols) if symbol == '_Unwind_Resume')
    target = max(((pc, name) for name, pc in labels.items() if pc <= resume))[1]
    base = next(name for name in labels if re.fullmatch(r'\.?Lfunc_begin\d+', name))
    changed = unwind.replace_field(body, ordinal, 2, f'.uleb128 {target}-{base}')
    inventory(llvm_body, changed, arm, apple)
    unwind.machine.inspect(changed, clear, drop, noreturn, arm, apple)
    try:
        unwind.inspect(changed, clear, drop, noreturn, arm, apple, from_entry=True)
    except ValueError as error:
        require('machine unwind path escapes' in str(error), 'specific later-call exceptional cleanup rejection')
    else:
        raise AssertionError('thread join exception bypass survived')
    return count, states, tested + 1
