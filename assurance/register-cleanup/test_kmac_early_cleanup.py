#!/usr/bin/env python3
"""Pre-finish metadata ownership/cleanup mutations of retained LLVM text only."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_early_cleanup as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def early_blocks(function, names, defined):
    graph, edges, events, origin, finish = check.prelude(function, names, defined)
    pending, seen = ['start'], set()
    while pending:
        label = pending.pop()
        if label in seen or label == finish:
            continue
        seen.add(label)
        pending.extend(edges[label][0])
    return graph, edges, events, origin, finish, seen


def mutants(function, names, defined, state_callees):
    graph, edges, events, origin, finish, seen = early_blocks(function, names, defined)
    for label in sorted(seen):
        lines = graph[label]
        for index, role, args, invoked in events.get(label, []):
            assert role in ('CLEAR', 'GLUE')
            line = lines[index]
            yield 'unbound clearing callee', function.replace(line, line.replace('@' + names[role] + '(', '@unreviewed('), 1)
            pointer = check.comparison.pointer(args[0])
            yield 'wrong metadata owner', function.replace(line, line.replace(pointer, '%candidate'), 1)
            base, _ = origin(pointer)
            load = base + ' = load ptr, ptr %self, align 8'
            assert load in lines[:index]
            yield 'metadata loaded from wrong Core', function.replace(load, load.replace('%self', '%candidate'), 1)
            yield 'metadata loaded after request', replace_block(function, label,
                [value for value in lines[:index] if value != load] + [line, load] + lines[index + 1:])
            if role == 'CLEAR':
                for width in (0, 2, 63, 67):
                    yield 'incomplete or excessive metadata width', function.replace(line, line.replace(args[1], f'i64 noundef {width}'), 1)
                if pointer != base:
                    gep = next(value for value in lines if value.startswith(pointer + ' = '))
                    yield 'wrong metadata region offset', function.replace(gep, re.sub(r'i64 \d+$', 'i64 0', gep), 1)
            if invoked:
                normal, unwind = edges[label][0]
                yield 'skip cleanup invocation', replace_block(function, label, lines[:index] + ['br label %' + normal])
                yield 'exchange cleanup normal/unwind', replace_block(function, label,
                    lines[:-1] + ['to label %' + unwind + ' unwind label %' + normal])
            else:
                yield 'skip clearing request', replace_block(function, label, lines[:index] + lines[index + 1:])
            duplicate = line.replace('invoke ', 'call ')
            duplicate = re.sub('^' + check.SSA + ' = ', '%injected_duplicate = ', duplicate)
            yield 'duplicate cleanup', replace_block(function, label, lines[:index] + [duplicate] + lines[index:])
        if edges[label][1] is None:
            end = len(lines) - (2 if lines[-1].startswith('to label ') else 1)
            for replacement in ('ret { i1, i8 } undef', 'resume { ptr, i32 } undef', 'unreachable', 'br label %' + label):
                # Keep any preceding instructions and replace only the terminator.
                # A completed cleanup return is legitimate, not a negative case.
                if events.get(label) and not lines[-1].startswith('to label ') and replacement.startswith(('ret ', 'resume ')):
                    continue
                yield 'early exit/loop bypass', replace_block(function, label, lines[:end] + [replacement])
        for line in lines:
            if line.startswith('invoke void @'):
                name, args = check.guard.call(line)
                assert name in state_callees
                yield 'unbound state destructor', function.replace(line, line.replace('@' + name + '(', '@unreviewed('), 1)
                pointer = check.comparison.pointer(args[0])
                yield 'wrong state owner', function.replace(line, line.replace(pointer, '%candidate'), 1)
        yield 'overwrite original metadata descriptor', replace_block(function, label,
            ['store ptr %candidate, ptr %self, align 8'] + lines)
        yield 'opaque indirect side effect', replace_block(function, label,
            ['call void %injected(ptr %self)'] + lines)
    lines = graph[finish]
    copy = next(line for line in lines if '@llvm.memcpy.p0.p0.i64(' in line)
    _, args = check.guard.call(copy)
    for width in (0, 8, 16, 64):
        yield 'truncated/oversized ownership handoff', function.replace(copy, copy.replace(args[2], 'i64 ' + str(width)), 1)
    yield 'handoff of wrong Core', function.replace(copy, copy.replace('%self', '%candidate'), 1)
    destination = check.comparison.pointer(args[0])
    yield 'copy to wrong handoff slot', function.replace(copy, copy.replace(destination, '%candidate'), 1)
    yield 'missing ownership handoff', function.replace(copy, '', 1)
    yield 'duplicate ownership handoff', function.replace(copy, copy + '\n  ' + copy, 1)
    finish_line = next(line for line in lines if '6finish' in line and 'call ' in line)
    _, args = check.guard.call(finish_line)
    yield 'finish receives uncopied slot', function.replace(finish_line,
        finish_line.replace(args[1], args[1].replace(check.comparison.pointer(args[1]), '%candidate')), 1)
    yield 'handoff after premature metadata cleanup', replace_block(function, finish,
        ['call fastcc void @' + names['GLUE'] + '(ptr nonnull %candidate)'] + lines)


def aliases():
    wipe = 'HardenedFips202Owner4wipe'
    drop = 'hardened_accelerated_in_place_xof_core_Borrowed4drop'
    scope = 'hardened_accelerated_in_place_xof_core_Scope4drop'
    text = (f'define void @{wipe}(ptr %self) {{\nstart:\n  ret void\n}}\n'
            f'define void @{scope}(ptr %self) {{\nstart:\n  ret void\n}}\n'
            f'@{wipe}_alias = unnamed_addr alias void (ptr), ptr @{wipe}\n'
            f'@{drop} = unnamed_addr alias void (ptr), ptr @{scope}\n')
    expected = {wipe, wipe + '_alias', drop}
    def inspect(value):
        check.require(check.state_symbols(value) == expected, 'all aliases retain exact bound void-pointer definitions')
    changes = [
        ('unbound alias', text.replace('ptr @' + wipe + '\n', 'ptr @unbound\n')),
        ('cross-kind alias', text.replace('ptr @' + wipe + '\n', 'ptr @' + scope + '\n')),
        ('wrong alias ABI', text.replace('alias void (ptr)', 'alias void (i64)')),
        ('duplicate alias', text + text.splitlines()[-1] + '\n'),
        ('missing scope definition', text.replace('define void @' + scope, 'define void @unbound')),
        ('declaration not definition', text.replace('define void @' + wipe, 'declare void @' + wipe)),
    ]
    return rejects(inspect, text, changes)


def main(record):
    count = controls = functions = builds = 0
    alias_count = aliases()
    for _, names, defined, state_callees, verifiers in check.cases(record):
        for function in verifiers:
            inspect = lambda value: check.inspect(value, names, defined, state_callees)
            count += rejects(inspect, function, mutants(function, names, defined, state_callees))
            baseline = inspect(function)
            graph, _, _, _, _, seen = early_blocks(function, names, defined)
            owner = next(re.match('(' + check.SSA + r') = load ptr, ptr %self, align 8', line)[1]
                         for label in sorted(seen) for line in graph[label]
                         if re.fullmatch(check.SSA + r' = load ptr, ptr %self, align 8', line))
            for changed in (
                    re.sub(re.escape(owner) + r'(?![-.$\w])', '%original_metadata', function),
                    re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                    function.replace('start:\n', 'start:\n; harmless early-path comment\n', 1)):
                assert changed != function and inspect(changed) == baseline
                controls += 1
            functions += 1
        builds += 1
    assert (builds, functions, count, controls, alias_count) == (8, 24, 2040, 72, 6)
    print(f'Early KMAC cleanup rejects {count} ownership/region/handoff/CFG mutations and {alias_count} alias regressions; {controls} scoped controls across {functions} verifiers PASS')
    print('Retained LLVM-text mutations only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
