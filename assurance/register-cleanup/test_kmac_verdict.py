#!/usr/bin/env python3
"""Negative controls for actual verdict LLVM; no compiler/runtime invocation."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_verdict as check
from test_kmac_verify_comparisons import rejects


def mutants(name, body):
    returned = next(line for line in body.splitlines() if line.strip().startswith('ret '))
    # All additions operate on retained actual functions, not a separate model.
    for label, instruction in (
        ('raw difference load', '  %raw = load i8, ptr %difference'),
        ('escaping scalar store', '  store i8 1, ptr %difference, align 1'),
        ('unreviewed call', '  %escaped = call i8 @unreviewed(i8 1)'),
        ('unreviewed branch', '  br label %escape'),
    ):
        yield label, body.replace(returned, instruction + '\n' + returned, 1)
    yield 'constant verdict', body.replace(returned, re.sub(check.SSA, '1', returned), 1)
    yield 'undefined verdict', body.replace(returned, re.sub(check.SSA, '%undefined', returned), 1)
    yield 'omitted return', body.replace(returned, '', 1)
    yield 'post-return work', body.replace(returned, returned + '\n  %later = load i8, ptr %difference', 1)
    role = check.role(name)
    if role == 'choice':
        yield 'wrong Choice mask', body.replace(', 1, !dbg', ', 0, !dbg')
        yield 'changed Choice operation', body.replace('and i8', 'or i8')
        return
    call = next(line for line in body.splitlines() if re.search(r' = (?:tail )?call ', line))
    yield 'missing predicate call', body.replace(call, '', 1)
    yield 'duplicate predicate call', body.replace(call, call + '\n' + call, 1)
    symbol = re.search(check.comparison.SYMBOL, call)
    arguments = check.comparison.arguments(call, symbol.end())
    old_pointer = check.comparison.pointer(arguments[0])
    yield 'wrong difference pointer', body.replace(call, call.replace(old_pointer, '%other'), 1)
    if role == 'root':
        yield 'partial-byte mask', body.replace(call, call.replace('-1', '0'), 1)
        yield 'changed predicate return ABI', body.replace(call, call[:symbol.start()].replace('i32', 'i64').replace('i1 ', 'i64 ') + call[symbol.start():], 1)
    else:
        yield 'wrong predicate normalization', body.replace(', 1, !dbg', ', 0, !dbg')
        yield 'inverted predicate normalization', body.replace('icmp eq', 'icmp ne')
        yield 'partial-byte mask', body.replace(call, call.replace('%mask', '0'), 1)


def main(record):
    mutations, absent = 0, 0
    for _, _, core, _ in check.comparison.cases(record):
        chain = check.inspect(core)
        for name, body in chain:
            mutations += rejects(check.inspect, core,
                                 ((label, core.replace(body, changed, 1)) for label, changed in mutants(name, body)))
            absent += rejects(check.inspect, core, [('missing wrapper', core.replace(body, '', 1))])
        leaf = [(name, body) for name, body in check.comparison.definitions(core).items() if check.LEAF in name]
        if len(leaf) != 1:
            raise AssertionError('ambiguous private predicate')
        absent += rejects(check.inspect, core, [('missing private boundary', core.replace(leaf[0][1], '', 1))])
    if mutations != 400 or absent != 48:
        raise AssertionError(f'incomplete verdict mutation inventory: {mutations}, {absent}')
    print('KMAC verdict wrappers reject 400 load/store/call/return/normalization mutations and 48 missing definitions')
    print('Retained LLVM-text mutants only; subprocess execution forbidden; no release-gate changes')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler or runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
