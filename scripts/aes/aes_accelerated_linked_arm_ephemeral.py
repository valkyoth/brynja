"""Bounded final-linked ARM per-operation callers; not native qualification.

Policies pin inspected whole bodies, including temporary expansion, repeated
admission, output staging, clearing and retained exceptional cleanup paths.
"""
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('arm_ephemeral_cached',
        Path(__file__).with_name('aes_accelerated_linked_arm_cached.py'))
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
constructors = prior.prior
kernels, require, TARGET = prior.kernels, prior.require, prior.TARGET
POLICY = json.loads(Path(__file__).with_name('accelerated-arm-ephemeral-review.json').read_text())
spec = importlib.util.spec_from_file_location('arm_ephemeral_sessions',
        Path(__file__).with_name('aes_accelerated_linked_arm_sessions.py'))
sessions = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sessions)


def policy(kind, bits, compiler, panic, admission):
    require(kind in ('public', 'secret') and bits in (128, 192, 256)
            and compiler in ('1.90.0', '1.99.1') and panic in ('abort', 'unwind')
            and admission in ('static', 'hosted'), 'unreviewed ARM ephemeral configuration')
    return POLICY['/'.join((compiler, admission, panic, kind, str(bits)))]


def candidates(table):
    selected = {}
    patterns = {
        'public': (r'_ZN30brynja_aes_accelerated_fixture9public(128|192|256)17h[0-9a-f]{16}E',
                   r'_RNvC\w+_30brynja_aes_accelerated_fixture9public(128|192|256)'),
        'secret': (r'_ZN13brynja_crypto3aes9execution9Aes(128|192|256)Key6secret17h[0-9a-f]{16}E',
                   r'_RNvM(?:s[0-9a-z]*_)?NtNtC\w+_13brynja_crypto3aes9executionNtB[0-9a-z]+_9Aes(128|192|256)Key6secret'),
    }
    for line in table.splitlines():
        if 'brynja_aes_accelerated_fixture9public' in line:
            kind = 'public'
        elif '3aes9execution' in line and 'Key6secret' in line and 'ExpandedKey' not in line:
            kind = 'secret'
        else:
            continue
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(match is not None, 'unrecognized ARM ephemeral symbol row')
        address, size, name = match.groups()
        match = re.fullmatch(patterns[kind][0], name) or re.fullmatch(patterns[kind][1], name)
        require(match is not None, 'unrecognized ARM ephemeral symbol')
        role = kind, int(match[1])
        require(role not in selected, 'duplicate ARM ephemeral symbol')
        selected[role] = name, int(address, 16), int(size, 16)
    require(set(selected) == {(k, b) for k in ('public', 'secret') for b in (128, 192, 256)},
            'ARM ephemeral symbol population changed')
    constructors.cleanup.disjoint(selected.values())
    return selected


def check(lines, raw, row, image, targets, kind, bits, compiler, panic, admission):
    expected = policy(kind, bits, compiler, panic, admission)
    edges = {'zeroize', 'expand'} | ({'copy', 'encrypt', 'decrypt'} if kind == 'secret' else {'kernel'})
    if (compiler, panic) == ('1.90.0', 'unwind'):
        edges.add('resume')
    require(set(targets) == edges, 'ARM ephemeral call population changed')
    constructors.cleanup.disjoint([row, *targets.values()])
    actual, _, _ = constructors.portable.observe(lines, raw, row, image, targets)
    require(actual == expected, 'ARM ephemeral stream changed; explicit re-review required')
    return {'kind': kind, 'bits': bits, **actual}


def inspect(table, assembly, image, compiler, panic, admission):
    policy('public', 128, compiler, panic, admission)
    dependency = prior.inspect(table, assembly, image, compiler, panic, admission)
    session_review = sessions.inspect(table, assembly, image, compiler, panic, admission)
    session_rows = sessions.candidates(table)
    selected = candidates(table)
    cached = prior.candidates(table)
    owners = constructors.candidates(table, assembly, image)
    clearing = constructors.cleanup.candidates(table)
    bound = {}
    for row in kernels.select(table, TARGET):
        result = kernels.check(*kernels.decode(assembly, row, TARGET), row, image, TARGET)
        require(result['bits'] not in bound, 'duplicate ARM ephemeral kernel width')
        bound[result['bits']] = row
    require(set(bound) == {128, 192, 256}, 'ARM ephemeral kernel population changed')
    runtime = {}
    if (compiler, panic) == ('1.90.0', 'unwind'):
        runtime['resume'] = prior.resume_target(table, image, admission)
    constructors.cleanup.disjoint([*selected.values(), *cached.values(), *owners.values(),
                                  *clearing.values(), *bound.values(), *runtime.values(), *session_rows.values()])
    reports, rejected = [], 0
    for (kind, bits), row in sorted(selected.items()):
        targets = {'zeroize': clearing['zeroize'],
                   'expand': owners[f'expand{bits}'], **runtime}
        if kind == 'secret':
            targets.update(copy=owners['copy'], encrypt=session_rows['encrypt', bits],
                           decrypt=session_rows['decrypt', bits])
        else:
            targets['kernel'] = bound[bits]
        args = (*constructors.decode(assembly, row), row, image, targets,
                kind, bits, compiler, panic, admission)
        reports.append(check(*args))
        rejected += constructors.mutations(check, *args)
    require(rejected == sum(policy(k, b, compiler, panic, admission)['instructions'] * 5
                            for k, b in selected), 'ARM ephemeral mutation population changed')
    return {'callers': reports, 'rejected_caller_mutations': rejected,
            'cached_review': dependency, 'session_review': session_review,
            'scope': 'six ARM per-operation public/secret callers, matched-width expansion and kernels; '
                     'session/cached/constructor/expansion/cleanup replay; not native qualification, arbitrary '
                     'inlining, every call site, exception-table dispatch, unwinder qualification or spill erasure'}
