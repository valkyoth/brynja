#!/usr/bin/env python3
"""Mutate retained comparison artifacts; never rebuild or change runtime code."""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_verify_comparisons as check


def rejects(inspect, original, mutants):
    count = 0
    inspect(original)
    for label, mutant in mutants:
        if mutant == original:
            raise AssertionError('missing mutation: ' + label)
        try:
            inspect(mutant)
        except ValueError:
            count += 1
            continue
        raise AssertionError('accepted mutation: ' + label)
    return count


def call_mutants(function):
    calls = check.comparison_calls(function)
    first, second, verdict = calls
    for label, old, new in (
        ('missing first accumulation', first, ''),
        ('missing second accumulation', second, ''),
        ('duplicate accumulation', first, first + '\n' + first),
        ('missing verdict', verdict, ''),
        ('different callee', first, first.replace(check.ACCUMULATE, 'unreviewed')),
        ('scalar operand', first, first.replace('ptr ', 'i8 ', 1)),
        ('by-value operand', first, first.replace('ptr ', 'ptr byval(i8) ', 1)),
        ('secret return', first, re.sub(r'\bvoid\b', 'i8', first, count=1)),
        ('scalar verdict operand', verdict, verdict.replace('ptr ', 'i8 ', 1)),
        ('changed verdict return', verdict, re.sub(r'\bi8\b', 'i64', verdict, count=1)),
    ):
        yield label, function.replace(old, new, 1)


def forwarding_mutants(function):
    lines = function.splitlines()
    call = next(line for line in lines[1:] if check.PRIVATE in line)
    for label, old, new in (
        ('omitted forwarding', call, ''),
        ('duplicate forwarding', call, call + '\n' + call),
        ('wrong callee', call, call.replace(check.PRIVATE, 'unreviewed')),
        ('wrong forwarded pointer', call, call.replace('%left', '%right')),
        ('by-value forwarding', call, call.replace('ptr ', 'ptr byval(i8) ', 1)),
        ('scalar forwarding', call, call.replace('ptr ', 'i8 ', 1)),
        ('secret-returning forwarding', call, re.sub(r'\bvoid\b', 'i8', call, count=1)),
        ('secret byte load', call, '  %secret = load i8, ptr %left\n' + call),
        ('escaping pointer store', call, '  store ptr %left, ptr %right, align 8\n' + call),
        ('early return', call, '  ret void\n' + call),
        ('unreviewed control flow', call, '  br label %escape\n' + call),
    ):
        yield label, function.replace(old, new, 1)


def assembly_mutants(text, marker, arm):
    end = r'(?m)^(.*BRYNJA_' + marker + r'_END.*)$'
    yield 'missing wipe boundary', text.replace('BRYNJA_' + marker + '_ERASE', 'MISSING_ERASE')
    yield 'missing wipe instruction', re.sub(
        r'(?m)^(.*BRYNJA_' + marker + r'_ERASE[^\n]*\n)[^\n]+\n', r'\1', text)
    load = 'ldr x4, [x0]' if arm else 'movq (%rdi), %rax'
    yield 'cleanup load', re.sub(end, load + r'\n\1', text)
    yield 'post-cleanup load', re.sub(end, r'\1\n' + load, text)
    yield 'secret spill', re.sub(r'(?m)^(.*BRYNJA_' + marker + r'_BEGIN.*)$',
                               r'\1\n' + ('str x4, [sp]' if arm else 'pushq %rax'), text)


def record_mutants(document):
    def change(label, update):
        mutated = deepcopy(document)
        update(mutated)
        return label, mutated
    yield change('overclaim', lambda d: d.update(qualifies_register_cleanup=True))
    yield change('schema', lambda d: d.update(schema=2))
    yield change('stale source', lambda d: d['sources'].update({'unexpected': '0' * 64}))
    yield change('missing configuration', lambda d: d['records'].pop())
    yield change('duplicate configuration', lambda d: d['records'].append(d['records'][0]))
    yield change('wrong execution', lambda d: d['records'][0].update(execution='unqualified'))
    yield change('unknown mode', lambda d: d['records'][0].update(mode='unknown'))
    yield change('changed log', lambda d: d['records'][0].update(log_sha256='0' * 64))
    yield change('missing observations', lambda d: d['records'][0].update(observations=[]))
    yield change('missing artifact', lambda d: d['records'][0]['artifacts'].popitem())
    def artifact(d, escape):
        artifacts = d['records'][0]['artifacts']
        key = next(iter(artifacts))
        if escape:
            artifacts['../outside.mir'] = artifacts.pop(key)
        else:
            artifacts[key] = '0' * 64
    yield change('artifact hash', lambda d: artifact(d, False))
    yield change('artifact escape', lambda d: artifact(d, True))


def main(record):
    totals = [0, 0, 0]
    for row, kmac, core, assembly in check.cases(record):
        accelerated = row['mode'] == 'accelerated'
        functions = check.verifiers(kmac, accelerated)
        rejects(lambda text: check.verifiers(text, accelerated), kmac,
                [('missing verifier', kmac.replace(functions[0], '', 1))])
        for function in functions:
            totals[0] += rejects(check.comparison_calls, function, call_mutants(function))
        for _, function in check.forwarding_chain(core):
            totals[1] += rejects(check.forwarder, function, forwarding_mutants(function))
        for inspector, marker in ((check.difference, 'DIFFERENCE'), (check.predicate, 'PREDICATE')):
            arm = row['target'].startswith('aarch64')
            totals[2] += rejects(lambda text: inspector.inspect(text, arm), assembly,
                                 assembly_mutants(assembly, marker, arm))
    expected = [48 * 10, 24 * 11, 32 * 5]
    if totals != expected:
        raise AssertionError('incomplete artifact mutation campaign: ' + repr(totals))
    document = json.loads(record.read_text())
    records = rejects(lambda d: check.validate_record(d, record.parent), document, record_mutants(document))
    if records != 12:
        raise AssertionError('incomplete record mutation campaign')
    print(f'KMAC comparison artifacts reject {totals[0]} call-ABI, {totals[1]} pointer-forwarding and {totals[2]} assembly regressions')
    print('Sixteen missing-verifier inventories and twelve record/source/hash/log regressions rejected')
    print('LLVM/assembly-text mutations, not compiled/runtime mutants; subprocess execution forbidden')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('must not rerun compiler or runtime')):
        main(parser.parse_args().record.resolve())
