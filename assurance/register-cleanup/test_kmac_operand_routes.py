#!/usr/bin/env python3
"""Mutation-test retained KMAC operand routing without executing crypto."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_operand_routes as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, trace, accumulate):
    for value in sorted(trace.used):
        _, rhs = trace.definitions[value]
        line = value + ' = ' + rhs
        yield 'unrelated selected SSA value', function.replace(line, value + ' = freeze i64 0', 1)
        if rhs.startswith('getelementptr ') and re.search(r'i64 -?\d+$', rhs):
            wrong = re.sub(r'i64 (-?\d+)$', lambda m: 'i64 ' + str(int(m[1]) + 1), line)
            yield 'wrong selected field offset', function.replace(line, wrong, 1)
        if rhs.startswith('phi '):
            wrong = re.sub(r'\[ [^,]+,', '[ %foreign,', line)
            yield 'wrong recurrence values', function.replace(line, wrong, 1)
        if rhs.startswith('load '):
            yield 'wrong selected load owner', function.replace(line,
                re.sub(r', ptr ' + check.SSA + ',', ', ptr %foreign,', line), 1)
        if rhs.startswith(('add ', 'icmp ', 'call noundef i64 @llvm.umin')):
            wrong = re.sub(r'(, (?:i64 )?)(\d+)(\)?$)', lambda m: m[1] + str(int(m[2]) + 1) + m[3], line)
            if wrong != line:
                yield 'wrong loop step/limit/chunk width', function.replace(line, wrong, 1)
    for label, lines in trace.graph.items():
        for index, line in enumerate(lines):
            if line.startswith('store i8 ') and re.search(r'store i8 (' + check.SSA + ')', line)[1] in trace.used:
                yield 'wrong first pointer byte', function.replace(line, re.sub(r'store i8 ' + check.SSA + ',', 'store i8 0,', line), 1)
                yield 'missing first pointer byte', replace_block(function, label, lines[:index] + lines[index + 1:])
            if line in trace.copies:
                _, args = check.guard.call(line)
                if args[2] != 'i64 15':
                    continue
                yield 'partial descriptor copy', function.replace(line, line.replace('i64 15', 'i64 7'), 1)
                yield 'wrong descriptor source', function.replace(line,
                    line.replace(args[1], args[1].replace(check.comparison.pointer(args[1]), '%foreign')), 1)
                yield 'duplicate descriptor copy', replace_block(function, label, lines[:index] + [line] + lines[index:])
            if not line.startswith('invoke void @'):
                continue
            name, args = check.guard.call(line)
            if name == accumulate:
                actual = check.comparison.pointer(args[1])
                expected = check.comparison.pointer(args[2])
                wrong = line.replace(args[2], args[2].replace(expected, actual))
                yield 'compare actual bytes with themselves', function.replace(line, wrong, 1)
                swapped = line.replace(args[1], args[1].replace(actual, '%temporary_operand'))
                swapped = swapped.replace(args[2], args[2].replace(expected, actual)).replace('%temporary_operand', expected)
                yield 'swap candidate and secret operands', function.replace(line, swapped, 1)
            if not any(token in name for token in ('14squeeze_secret', '12final_secret', '25squeeze_final_bits_secret')):
                continue
            output = len(args) - (2 if '14squeeze_secret' in name else 3)
            yield 'unbound reader call', function.replace(line, line.replace('@' + name + '(', '@foreign_reader('), 1)
            yield 'wrong reader output buffer', function.replace(line,
                line.replace(args[output], args[output].replace(check.comparison.pointer(args[output]), '%candidate')), 1)
            yield 'wrong reader output length', function.replace(line,
                line.replace(args[output + 1], 'i64 noundef 2'), 1)


def alias_tests():
    total = 0
    for accelerated in (False, True):
        methods = ('14squeeze_secret', '25squeeze_final_bits_secret') if accelerated else ('14squeeze_secret',)
        for method in methods:
            prefix = '_ZN16brynja_hash_sha38hardened' + ('11accelerated' if accelerated else '') + '8in_place3xof'
            name = prefix + '15Cshake256Reader' + method
            target = prefix + ('14Shake128Reader' if accelerated else '14Shake256Reader') + method
            tail = method == '25squeeze_final_bits_secret'
            abi = 'ptr, ptr, ptr, i64' + (', i8' if tail else '')
            alias = f'@{name} = unnamed_addr alias void ({abi}), ptr @{target}'
            definition = f'define void @{target}(ptr sret([24 x i8]) %out, ptr %reader, ptr %buffer, i64 %length' + (', i8 %valid' if tail else '') + ') {\nstart:\n  ret void\n}'
            text = alias + '\n' + definition
            wrong_target = target.replace('8in_place3xof', '8in_place5other')
            mutants = [
                ('missing target', alias),
                ('duplicate alias', text + '\n' + alias),
                ('wrong alias ABI', text.replace('alias void (ptr,', 'alias void (i64,', 1)),
                ('wrong target ABI', text.replace('sret([24 x i8])', 'sret([16 x i8])')),
                ('wrong target family', text.replace(target, wrong_target)),
                ('wrong target rate', text.replace(target, target.replace('128Reader' if accelerated else '256Reader', '256Reader' if accelerated else '128Reader'))),
            ]
            total += rejects(check.reader_symbols, text, mutants)
    return total


def main(record):
    count = controls = functions = 0
    for _, function, names, defined, callees in check.cases(record):
        inspect = lambda text: check.inspect(text, names, defined, callees)
        trace = inspect(function)
        count += rejects(inspect, function, mutations(function, trace, names['ACCUMULATE']))
        for changed in (
                re.sub(re.escape(trace.owner) + r'(?![-.$\w])', '%verification_metadata', function),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless operand-routing comment\n', 1)):
            assert changed != function
            assert len(inspect(changed).used) == len(trace.used)
            controls += 1
        functions += 1
    aliases = alias_tests()
    assert (functions, count, controls, aliases) == (24, 1752, 72, 18)
    print(f'KMAC operand routing rejects {count} LLVM mutations and {aliases} alias regressions; {controls} owner/label/comment controls across {functions} verifiers PASS')
    print('Retained-text tests only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
