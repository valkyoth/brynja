#!/usr/bin/env python3
"""Retained final-adapter mutations; never rebuild or execute cryptography."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_final_adapter as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, trace):
    header = function.splitlines()[0]
    for changed in (header.replace('sret([24 x i8])', 'sret([32 x i8])'),
                    header.replace('define void @', 'define i64 @'), header.replace(' %_0,', ' %foreign,')):
        yield 'wrong adapter result ABI', function.replace(header, changed, 1)
    label, index, error, success, returning, result = trace.adapter_details
    lines = trace.graph[label]
    call = lines[index]
    name, args = check.routes.guard.call(call)
    for old, new in ((name, 'unreviewed_reader'), ('%self.0', '%foreign'), ('%self.1', '%foreign'),
                     (args[0], args[0].replace(result, '%foreign'))):
        yield 'wrong reader identity/forwarding', function.replace(call, call.replace(old, new), 1)
    load, compare = lines[index + 1:index + 3]
    yield 'discriminator from wrong result', function.replace(load, load.replace('ptr ' + result, 'ptr %foreign'), 1)
    yield 'inverted result discriminator', function.replace(compare, compare.replace('icmp eq', 'icmp ne'), 1)
    yield 'wrong error discriminator', function.replace(compare, compare.replace(', 2', ', 3'), 1)
    condition, yes, no = check.shape.branch(trace, label)
    for terminal in (f'br i1 {condition}, label %{no}, label %{yes}', f'br label %{yes}', f'br label %{no}'):
        yield 'wrong result decision edge', replace_block(function, label, lines[:-1] + [terminal])
    for injection in ('store i64 0, ptr ' + result + ', align 8', 'call void @unreviewed(ptr ' + result + ')'):
        yield 'intervening result clobber', replace_block(function, label, lines[:index + 1] + [injection] + lines[index + 1:])
    copying = trace.graph[success][0]
    _, copy_args = check.routes.guard.call(copying)
    for parameter in (0, 1):
        pointer = check.comparison.pointer(copy_args[parameter])
        yield 'wrong descriptor copy endpoint', function.replace(copying,
            copying.replace(copy_args[parameter], copy_args[parameter].replace(pointer, '%foreign')), 1)
    for length in (0, 8, 23, 25):
        yield 'partial/oversized descriptor copy', function.replace(copying, copying.replace('i64 24', 'i64 ' + str(length)), 1)
    yield 'missing success copy', replace_block(function, success, trace.graph[success][1:])
    yield 'duplicate success copy', replace_block(function, success, [copying] + trace.graph[success])
    yield 'reader error reaches success copy', replace_block(function, error, ['br label %' + success])
    for injection in ('store i64 0, ptr %_0, align 8', 'call void @unreviewed(ptr %_0)'):
        yield 'post-copy output modification', replace_block(function, returning, [injection] + trace.graph[returning])
    lifetime = trace.graph[returning][-2]
    yield 'end caller output rather than local result', function.replace(lifetime, lifetime.replace(result, '%_0'), 1)


def aliases():
    prefix = '_ZN16brynja_hash_sha38hardened8in_place3xof'
    source = prefix + '15Cshake128Reader25squeeze_final_bits_secret'
    target = prefix + '14Shake128Reader25squeeze_final_bits_secret'
    alias = f'@{source} = unnamed_addr alias void (ptr, ptr, i1, ptr), ptr @{target}'
    definition = f'define void @{target}(ptr sret([24 x i8]) %out, ptr %state, i1 %flag, ptr %buffer) {{\nstart:\n  ret void\n}}'
    text = alias + '\n' + definition
    def inspect(value):
        check.require(source in check.final_symbols(value), 'selected adapter alias remains bound')
    return rejects(inspect, text, [
        ('missing definition', alias), ('missing alias', definition),
        ('duplicate alias', text + '\n' + alias),
        ('wrong alias ABI', text.replace('alias void (ptr, ptr, i1, ptr)', 'alias void (ptr, ptr, i64, ptr)')),
        ('wrong target ABI', text.replace('sret([24 x i8])', 'sret([32 x i8])')),
        ('wrong reader strength', text.replace(target, target.replace('128Reader', '256Reader'))),
    ])


def main(record):
    count = controls = functions = 0
    for _, function, callees in check.cases(record):
        inspect = lambda value: check.inspect(value, callees)
        trace = inspect(function)
        count += rejects(inspect, function, mutations(function, trace))
        local_names = {match[1] for lines in trace.graph.values() for line in lines
                       if (match := re.match('(' + check.SSA + ') = ', line))}
        for changed in (
                re.sub(check.SSA, lambda match: '%adapter_' + match[0][1:] if match[0] in local_names else match[0], function),
                re.sub(r'\bbb(\d+)\b', lambda match: 'bb' + str(int(match[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless adapter comment\n', 1)):
            assert changed != function
            assert len(inspect(changed).adapter_blocks) == len(trace.adapter_blocks)
            controls += 1
        functions += 1
    alias_count = aliases()
    assert (functions, count, controls, alias_count) == (16, 432, 48, 6)
    print(f'KMAC final adapter rejects {count} LLVM mutations and {alias_count} alias regressions; {controls} SSA/label/comment controls across {functions} adapters PASS')
    print('Retained-text tests only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
