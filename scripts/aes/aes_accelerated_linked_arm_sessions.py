"""Inspected ARM session admission/direction bodies, not native qualification.

Exact whole-body policies; only independently bound call relocations normalize.
The per-operation review requires these bodies before checking its callers.
"""
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('arm_session_constructors',
        Path(__file__).with_name('aes_accelerated_linked_arm_constructors.py'))
constructors = importlib.util.module_from_spec(spec)
spec.loader.exec_module(constructors)
kernels, require, TARGET = constructors.kernels, constructors.require, constructors.TARGET
POLICY = json.loads(Path(__file__).with_name('accelerated-arm-session-review.json').read_text())


def policy(direction, compiler, panic, admission):
    require(direction in ('encrypt', 'decrypt') and compiler in ('1.90.0', '1.99.1')
            and panic in ('abort', 'unwind') and admission in ('static', 'hosted'),
            'unreviewed ARM session configuration')
    return POLICY['/'.join((compiler, admission, panic, direction))]


def candidates(table):
    selected = {}
    operation = r'7Session10(encrypt|decrypt)(128|192|256)'
    legacy = r'_ZN17brynja_crypto_cpu3aes' + operation + r'17h[0-9a-f]{16}E'
    current = r'_RNvM(?:s[0-9a-z]*_)?NtC\w+_17brynja_crypto_cpu3aesNtB[0-9a-z]+_' + operation
    for line in table.splitlines():
        if '17brynja_crypto_cpu3aes' not in line or '7Session' not in line or not any(s in line for s in ('encrypt', 'decrypt')):
            continue
        row = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(row is not None, 'unrecognized ARM session symbol row')
        match = re.fullmatch(legacy, row[3]) or re.fullmatch(current, row[3])
        require(match is not None, 'unrecognized ARM session symbol')
        role = match[1], int(match[2])
        require(role not in selected, 'duplicate ARM session symbol')
        selected[role] = row[3], int(row[1], 16), int(row[2], 16)
    require(set(selected) == {(d, b) for d in ('encrypt', 'decrypt') for b in (128, 192, 256)},
            'ARM session symbol population changed')
    constructors.cleanup.disjoint(selected.values())
    return selected


def check(lines, raw, row, image, targets, direction, compiler, panic, admission):
    expected = policy(direction, compiler, panic, admission)
    edges = {'kernel', 'resume'} if (compiler, panic) == ('1.90.0', 'unwind') else {'kernel'}
    require(set(targets) == edges, 'ARM session call population changed')
    constructors.cleanup.disjoint([row, *targets.values()])
    actual, _, _ = constructors.portable.observe(lines, raw, row, image, targets)
    require(actual == expected, 'ARM session stream changed; explicit re-review required')
    return {'direction': direction, **actual}


def inspect(table, assembly, image, compiler, panic, admission):
    policy('encrypt', compiler, panic, admission)
    selected = candidates(table)
    bound = {}
    for row in kernels.select(table, TARGET):
        result = kernels.check(*kernels.decode(assembly, row, TARGET), row, image, TARGET)
        require(result['bits'] not in bound, 'duplicate ARM session kernel width')
        bound[result['bits']] = row
    require(set(bound) == {128, 192, 256}, 'ARM session kernel population changed')
    runtime = {}
    if (compiler, panic) == ('1.90.0', 'unwind'):
        runtime['resume'] = constructors.resume_target(table, image, admission)
    constructors.cleanup.disjoint([*selected.values(), *bound.values(), *runtime.values()])
    reports, rejected = [], 0
    for (direction, bits), row in sorted(selected.items()):
        args = (*constructors.decode(assembly, row), row, image, {'kernel': bound[bits], **runtime},
                direction, compiler, panic, admission)
        reports.append({'bits': bits, **check(*args)})
        rejected += constructors.mutations(check, *args)
    require(rejected == 15 * sum(policy(d, compiler, panic, admission)['instructions']
                                for d in ('encrypt', 'decrypt')), 'ARM session mutation population changed')
    return {'sessions': reports, 'rejected_mutations': rejected,
            'scope': 'six ARM session admission/direction bodies and matched-width kernels; '
                     'not startup, native qualification, exception-table dispatch or spill erasure'}
