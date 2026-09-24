#!/usr/bin/env python3
"""Reject stale or altered staging callees using only retained artifacts."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_sha3_fill_dependencies as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def bridge_mutants(function):
    graph, _, _ = check.progress.adapter.routes.transfer.finish.graph_info(function)
    for label, lines in graph.items():
        for index, line in enumerate(lines):
            yield 'missing bridge instruction', replace_block(function, label, lines[:index] + lines[index + 1:])
            changes = []
            if 'icmp eq' in line:
                changes += [('inverted length comparison', line.replace('icmp eq', 'icmp ne')),
                            ('self length comparison', line.replace('%input.1', '%destination.1'))]
            if 'tail call ' in line:
                name, args = check.progress.adapter.routes.guard.call(line)
                changes += [('missing copy dependency', line.replace(name, 'unreviewed_copy')),
                            ('wrong destination', line.replace('%destination.0', '%input.0')),
                            ('wrong source', line.replace('%input.0', '%destination.0')),
                            ('zero copy count', line.replace(args[2], 'i64 noundef 0')),
                            ('payload returned by value', line.replace('fastcc void', 'fastcc i8'))]
            if ' = phi i8 ' in line:
                changes += [('error becomes success', line.replace('[ 2, %start ]', '[ 0, %start ]')),
                            ('wrong copy success', re.sub(r'\[ (-?\d+),', '[ 1,', line, count=1))]
            for reason, changed in changes:
                yield reason, replace_block(function, label, lines[:index] + [changed] + lines[index + 1:])
    yield 'lost exclusive destination', function.replace('ptr noalias ', 'ptr ', 1)
    yield 'extra payload load', function.replace('start:\n', 'start:\n  %payload = load i8, ptr %input.0, align 1\n', 1)


def composed_mutants(case):
    function, sha3, core, compiler, sha3_asm, core_asm, arm, name, rate = case
    def changed(index, value):
        result = list(case)
        result[index] = value
        return tuple(result)
    definitions = check.comparison.definitions(core)
    copy = check.fill.shared.unique(definitions, '18copy_secret_region')
    primitive = check.fill.shared.unique(definitions, 'secret_memory_transfer10copy_bytes')
    clear = check.fill.shared.unique(definitions, '18clear_owned_region')
    wrapper = definitions[copy]
    copy_call = next(line for line in wrapper.splitlines() if 'tail call fastcc void @' in line)
    permute = check.fill.shared.unique(check.comparison.definitions(sha3), '11permutation6native6scalar')
    for reason, index, value in (
        ('missing copy wrapper', 2, core.replace(wrapper, '')),
        ('copy wrapper skips actual primitive', 2, core.replace(wrapper, wrapper.replace(copy_call, ''))),
        ('missing copy primitive definition', 2, core.replace(definitions[primitive], '')),
        ('missing clear wrapper', 2, core.replace(definitions[clear], '')),
        ('copy erasure boundary removed', 5, core_asm.replace('BRYNJA_COPY_ERASE', 'MISSING_COPY_ERASE')),
        ('scalar erasure boundary removed', 4, sha3_asm.replace('BRYNJA_SCALAR_ERASE', 'MISSING_SCALAR_ERASE')),
        ('scalar assembly identity mismatch', 4, sha3_asm.replace(permute + ':', 'other_scalar:')),
        ('copy assembly identity mismatch', 5, core_asm.replace(primitive + ':', 'other_copy:')),
        ('wrong bound fill definition', 7, 'unreviewed_fill'),
        ('wrong caller rate', 8, 136 if rate == 168 else 168),
        ('wrong assembly target', 6, not arm),
        ('missing scalar definition', 1, sha3.replace(check.comparison.definitions(sha3)[permute], '')),
    ):
        yield reason, changed(index, value)
    zero = check.progress.ownership.wiping.clearing.llvm.select(core)
    store = next(line for line in zero.splitlines() if 'store volatile i8 0,' in line)
    yield 'volatile cleanup dependency altered', changed(2, core.replace(zero, zero.replace(store, store.replace('volatile ', ''), 1)))


def main(record):
    bridges = bindings = controls = functions = 0
    for case in check.cases(record):
        _, _, core, compiler, *_ = case
        definitions = check.comparison.definitions(core)
        wrapper = definitions[check.fill.shared.unique(definitions, '18copy_secret_region')]
        primitive = check.fill.shared.unique(definitions, 'secret_memory_transfer10copy_bytes')
        inspect = lambda body: check.copy_bridge(body, primitive, compiler)
        bridges += rejects(inspect, wrapper, bridge_mutants(wrapper))
        bindings += rejects(lambda value: check.inspect(*value, thorough=False), case, composed_mutants(case))
        graph, _, _ = check.progress.adapter.routes.transfer.finish.graph_info(wrapper)
        locals_ = {match[1] for lines in graph.values() for line in lines
                   if (match := re.match('(' + check.SSA + ') = ', line))}
        for changed in (
                re.sub(check.SSA, lambda m: '%bridge_' + m[0][1:] if m[0] in locals_ else m[0], wrapper),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), wrapper),
                wrapper.replace('start:\n', 'start:\n; harmless bridge comment\n', 1)):
            assert changed != wrapper
            inspect(changed)
            controls += 1
        functions += 1
    assert (functions, bridges, bindings, controls) == (16, 272, 208, 48), (functions, bridges, bindings, controls)
    print(f'Reader-bound fill rejects {bridges} copy-wrapper and {bindings} composed dependency regressions; {controls} controls PASS')
    print('Retained-artifact checks only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
