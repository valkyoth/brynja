"""Bounded final-linked ARM cached callers, not ephemeral or native qualification.

Complete streams were inspected before pinning the policy. The static unwind
runtime is an explicitly trusted boundary, not a reviewed exception dispatcher.
"""
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('arm_cached_constructors',
        Path(__file__).with_name('aes_accelerated_linked_arm_constructors.py'))
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
kernels, require, TARGET = prior.kernels, prior.require, prior.TARGET
POLICY = json.loads(Path(__file__).with_name('accelerated-arm-cached-review.json').read_text())
# Shared with constructors; neither review qualifies the unwinder itself.
RESUME = prior.RESUME


def policy(kind, bits, compiler, panic, admission):
    require(kind in ('public', 'secret') and bits in (128, 192, 256)
            and compiler in ('1.90.0', '1.99.1') and panic in ('abort', 'unwind')
            and admission in ('static', 'hosted'), 'unreviewed ARM cached configuration')
    return POLICY['/'.join((compiler, admission, panic, kind, str(bits)))]


def candidates(table):
    selected = {}
    owner = r'17Aes(128|192|256)ExpandedKey(20encrypt_block_public|6secret)'
    legacy = r'_ZN13brynja_crypto3aes9execution' + owner + r'17h[0-9a-f]{16}E'
    current = r'_RNvM(?:s[0-9a-z]*_)?NtNtC\w+_13brynja_crypto3aes9executionNtB[0-9a-z]+_' + owner
    for line in table.splitlines():
        if not ('3aes9execution' in line and 'ExpandedKey' in line
                and ('encrypt_block_public' in line or 'secret' in line)):
            continue
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(match is not None, 'unrecognized ARM cached symbol row')
        address, size, name = match.groups()
        match = re.fullmatch(legacy, name) or re.fullmatch(current, name)
        require(match is not None, 'unrecognized ARM cached symbol')
        role = ('public' if match[2] == '20encrypt_block_public' else 'secret', int(match[1]))
        require(role not in selected, 'duplicate ARM cached symbol')
        selected[role] = name, int(address, 16), int(size, 16)
    require(set(selected) == {(k, b) for k in ('public', 'secret') for b in (128, 192, 256)},
            'ARM cached symbol population changed')
    prior.cleanup.disjoint(selected.values())
    return selected


resume_target = prior.resume_target
resume_mutations = prior.resume_mutations


def check(lines, raw, row, image, targets, kind, bits, compiler, panic, admission):
    expected = policy(kind, bits, compiler, panic, admission)
    edges = {'kernel', 'zeroize'}
    if kind == 'secret':
        edges.add('copy')
    if (compiler, panic) == ('1.90.0', 'unwind'):
        edges.add('resume')
    require(set(targets) == edges, 'ARM cached call population changed')
    prior.cleanup.disjoint([row, *targets.values()])
    actual, _, _ = prior.portable.observe(lines, raw, row, image, targets, tail_calls=('zeroize',))
    require(actual == expected, 'ARM cached stream changed; explicit re-review required')
    return {'kind': kind, 'bits': bits, **actual}


def inspect(table, assembly, image, compiler, panic, admission):
    policy('public', 128, compiler, panic, admission)
    # No caller can pass if its previously reviewed dependency closure fails.
    dependency = prior.inspect(table, assembly, image, compiler, panic, admission)
    selected = candidates(table)
    constructors = prior.candidates(table, assembly, image)
    clearing = prior.cleanup.candidates(table)
    bound = {}
    for row in kernels.select(table, TARGET):
        result = kernels.check(*kernels.decode(assembly, row, TARGET), row, image, TARGET)
        require(result['bits'] not in bound, 'duplicate ARM cached kernel width')
        bound[result['bits']] = row
    require(set(bound) == {128, 192, 256}, 'ARM cached kernel population changed')
    runtime, runtime_controls = {}, 0
    if (compiler, panic) == ('1.90.0', 'unwind'):
        runtime['resume'] = resume_target(table, image, admission)
        runtime_controls = resume_mutations(table, image, admission)
    prior.cleanup.disjoint([*selected.values(), *constructors.values(), *clearing.values(),
                            *bound.values(), *runtime.values()])
    reports, rejected = [], 0
    for (kind, bits), row in sorted(selected.items()):
        targets = {'kernel': bound[bits], 'zeroize': clearing['zeroize'], **runtime}
        if kind == 'secret':
            targets['copy'] = constructors['copy']
        args = (*prior.decode(assembly, row), row, image, targets, kind, bits, compiler, panic, admission)
        reports.append(check(*args))
        rejected += prior.mutations(check, *args)
    require(rejected == sum(policy(k, b, compiler, panic, admission)['instructions'] * 5
                            for k, b in selected), 'ARM cached mutation population changed')
    return {'callers': reports, 'rejected_caller_mutations': rejected,
            'runtime_boundary': runtime, 'rejected_runtime_mutations': runtime_controls,
            'constructor_review': dependency,
            'scope': 'six ARM cached public/secret callers, matched-width kernels, copy and clear; '
                     'constructor/expansion/cleanup replay; not ephemeral callers, native qualification, '
                     'arbitrary inlining, every call site, exception-table dispatch, unwinder qualification or spill erasure'}
