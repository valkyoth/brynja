#!/usr/bin/env python3
"""Retained clear assembly text mutants; no native or emulated execution."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_volatile_clear_assembly as check
from test_kmac_verify_comparisons import rejects


def mutants(body, arm):
    for index, line in enumerate(body.splitlines()):
        stripped = line.strip()
        if not stripped or stripped.startswith(('.', '_')) or 'MEMBARRIER' in stripped:
            continue
        lines = body.splitlines()
        yield 'missing instruction', '\n'.join(lines[:index] + lines[index + 1:])
        yield 'duplicated instruction', '\n'.join(lines[:index] + [line, line] + lines[index + 1:])
    store = next(line for line in body.splitlines() if ('strb ' in line.replace('\t', ' ') if arm else 'movb' in line))
    if arm:
        changes = [(store, store.replace('wzr', 'w2')),
                   ('[x0], #1', '[x0], #2'), ('subs\tx1', 'sub\tx1'),
                   ('cbz\tx1', 'cbnz\tx1'), ('b.ne\t', 'b.eq\t')]
        extras = ('ldr x2, [x0]', 'str x2, [sp]', 'bl unreviewed', 'movi v0.16b, #0')
    else:
        changes = [(store, store.replace('$0', '%dl')),
                   ('andq\t$7', 'andq\t$3'), ('cmpq\t$8', 'cmpq\t$9'),
                   ('movq\t%rdi, %rax', 'movq\t%rsi, %rax'),
                   ('addq\t$8, %rax', 'addq\t$7, %rax')]
        extras = ('movq (%rdi), %rdx', 'pushq %rax', 'callq unreviewed', 'vpxor %ymm0, %ymm0, %ymm0')
    for old, new in changes:
        yield 'wrong zero/address/flag/loop computation', body.replace(old, new)
    for extra in extras:
        yield 'payload/stack/call/vector injection', body.replace(store, '\t' + extra + '\n' + store, 1)
    barrier = next(line for line in body.splitlines() if 'MEMBARRIER' in line)
    yield 'missing compiler annotation', body.replace(barrier, '')
    yield 'premature compiler annotation', body.replace(barrier + '\n', '').replace(store, barrier + '\n' + store, 1)
    labels = re.findall(r'(?m)^(\.LBB\d+_\d+):', body)
    yield 'wrong branch destination', body.replace(labels[-1], labels[0], 1)


def main(record):
    count = controls = builds = 0
    for _, body, arm in check.cases(record):
        count += rejects(lambda text: check.inspect(text, arm), body, mutants(body, arm))
        renamed = re.sub(r'\.LBB(\d+)_', lambda match: '.LBB' + str(int(match[1]) + 1000) + '_', body)
        spaced = '\n'.join('   ' + line.strip().replace('\t', '  ') if line.startswith('\t') else line
                           for line in body.splitlines())
        for changed in (renamed, spaced):
            assert changed != body
            assert check.inspect(changed, arm) == check.inspect(body, arm)
            controls += 1
        builds += 1
    if (count, builds, controls) != (344, 8, 16):
        raise AssertionError(f'incomplete clearing assembly campaign: {count}/{builds}/{controls}')
    print(f'Volatile-clear assembly rejects {count} mutations across {builds} bodies; {controls} label/spacing controls PASS')
    print('Retained text mutations only; subprocess execution forbidden; no release-gate changes')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
