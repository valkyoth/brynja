#!/usr/bin/env python3
"""Mutations of retained owner-region and core-clear bindings; no crypto run."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_sha3_owner_wipe as check
from test_kmac_verify_comparisons import rejects


def mutations(function):
    header = function.splitlines()[0]
    for old, new in (('dereferenceable(1040)', 'dereferenceable(1039)'), ('noalias ', ''), ('define void @', 'define i8 @')):
        yield 'wipe owner ABI', function.replace(header, header.replace(old, new), 1)
    graph, _, _ = check.reader.adapter.routes.transfer.finish.graph_info(function)
    for line in graph['start'][:-1]:
        if 'getelementptr ' in line:
            offset = int(line.rsplit(' ', 1)[1])
            yield 'shifted field address', function.replace(line, line.rsplit(' ', 1)[0] + ' ' + str(offset + 1), 1)
        else:
            name, args = check.reader.adapter.routes.guard.call(line)
            width = int(args[1].rsplit(' ', 1)[1])
            pointer = check.comparison.pointer(args[0])
            yield 'unbound clear callee', function.replace(line, line.replace(name, 'unreviewed_clear'), 1)
            yield 'wrong clearing owner', function.replace(line, line.replace(args[0], args[0].replace(pointer, '%foreign')), 1)
            yield 'shortened region', function.replace(line, line.replace(args[1], 'i64 noundef ' + str(width - 1)), 1)
            yield 'extended region', function.replace(line, line.replace(args[1], 'i64 noundef ' + str(width + 1)), 1)
            yield 'omitted region', function.replace(line, '', 1)
            yield 'duplicated region', function.replace(line, line + '\n  ' + line.replace(line.split(' = ')[0], '%duplicate', 1), 1)
    for injection in ('store i8 1, ptr %self, align 1', '%payload = load i8, ptr %self, align 1', 'call void @unreviewed(ptr %self)'):
        yield 'unreviewed payload access/call', function.replace('start:\n', 'start:\n  ' + injection + '\n', 1)
    yield 'early return', function.replace('start:\n', 'start:\n  ret void\n', 1)


def core_mutations(core, assembly, compiler, arm):
    def inspect(pair):
        return check.core_check(pair[0], pair[1], compiler, arm)
    # Existing helper checkers do the full semantic/instruction work. These
    # mutations check that this composed owner check actually invokes them.
    functions = check.comparison.definitions(core)
    clear_name, clear = check.bridge.one(functions, lambda name: '18clear_owned_region' in name, 'clear')
    zero = check.clearing.llvm.select(core)
    store = next(line for line in zero.splitlines() if 'store volatile i8 0,' in line)
    first = next(line for line in clear.splitlines() if 'tail call fastcc void @' in line)
    asm_body = check.clearing.select(assembly)
    asm_store = next(line for line in asm_body.splitlines() if ('strb\twzr' in line if arm else 'movb\t$0' in line))
    return rejects(inspect, (core, assembly), [
        ('missing core wrapper', (core.replace(clear, ''), assembly)),
        ('wrong wrapper identity', (core.replace(clear_name, 'other_clear'), assembly)),
        ('wrapper skips nonempty output', (core.replace(clear, clear.replace('icmp eq i64 %region.1, 0', 'icmp ne i64 %region.1, 0')), assembly)),
        ('wrapper drops volatile call', (core.replace(first, ''), assembly)),
        ('volatile store removed', (core.replace(zero, zero.replace(store, '', 1)), assembly)),
        ('ordinary instead of volatile store', (core.replace(zero, zero.replace(store, store.replace('volatile ', ''), 1)), assembly)),
        ('nonzero clearing', (core.replace(zero, zero.replace(store, store.replace('i8 0,', 'i8 1,'), 1)), assembly)),
        ('compiler fence removed', (core.replace(zero, zero.replace('fence syncscope("singlethread") seq_cst', '')), assembly)),
        ('machine clearing store removed', (core, assembly.replace(asm_body, asm_body.replace(asm_store, '', 1)))),
    ])


def main(record):
    count = bindings = controls = functions = 0
    for function, core, assembly, compiler, arm in check.cases(record):
        clear = check.core_check(core, assembly, compiler, arm)
        inspect = lambda value: check.inspect(value, clear)
        count += rejects(inspect, function, mutations(function))
        bindings += core_mutations(core, assembly, compiler, arm)
        graph, _, _ = check.reader.adapter.routes.transfer.finish.graph_info(function)
        locals_ = {match[1] for lines in graph.values() for line in lines
                   if (match := re.match('(' + check.SSA + ') = ', line))}
        for changed in (
                re.sub(check.SSA, lambda m: '%wipe_' + m[0][1:] if m[0] in locals_ else m[0], function),
                function.replace('start:\n', 'start:\n; harmless owner wipe comment\n', 1)):
            assert changed != function
            assert tuple(inspect(changed)) == check.REGIONS
            controls += 1
        functions += 1
    assert (functions, count, bindings, controls) == (16, 1552, 144, 32)
    print(f'SHA-3 owner wipe rejects {count} LLVM region regressions and {bindings} composed core/assembly regressions; {controls} naming/comment controls across {functions} bindings PASS')
    print('Retained-text tests only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
