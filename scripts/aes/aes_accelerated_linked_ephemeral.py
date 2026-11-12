"""Complete x86 per-operation secret-output streams and their expansion closure.

The cached secret-output review is replayed as well. This does not approve
constructors, public per-operation callers, destructor entry points or ARM.
"""
import re
import importlib.util
from pathlib import Path


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


cached = module('aes_accelerated_linked_secret')
sessions = module('aes_accelerated_linked_sessions')
expansion = module('aes_accelerated_linked_expansion')
portable = module('check-aes-linked')
kernels, image_review = cached.kernels, cached.image_review
require, TARGET = kernels.require, cached.TARGET


def policies(rows):
    return {bits: portable.rounds.policy(count, size, 0, calls, text, encoding)
            for bits, count, size, calls, text, encoding in rows}


# Full normal/error paths inspected, including post-expansion authority checks
# and the 1.90 unwind cleanup pad. Explicit review required for every change.
POLICY = {
    ('1.90.0', 'abort'): policies([
        (128, 137, 494, 11, 'e89cfd7c3085c39481a1b1d78ba76d1c39a650ae20de8aef43b5c6e75f255b97', '22b40636ba5ce44e28d5c3882344f39fe3897573bc96754d876f6df66cee5496'),
        (192, 139, 510, 11, 'c121fdbfd57465b0dc5236f5f52552f86a0772b9cd322d6d7620e134e4e2a029', '60ba824d76d6ae0f8b53ec465469a2679babb1a2a68413d0f6ff0947f5f24ab3'),
        (256, 141, 526, 11, 'd513d38f9660303258d5c5e5e20b3d9c9802d2a641ca7b55e716505edc16a5ec', '0bd7ba53a928775ebc1eb9a43c255706f77fbe0e25a7efa7475695d0e973278e'),
    ]),
    ('1.90.0', 'unwind'): policies([
        (128, 172, 671, 17, '05ab621c0ac3f59e2a59ef8d0c49df3c9a9be5d41fb5c53ae2bff8742b539921', '18fb6d3f98207c2ffe7d0fced88d13d769e1082a8d6055f5f9469cb7586ae836'),
        (192, 174, 687, 17, 'ca9ff279cef1575863548cc4818268c65cdac8c51256dc3f8df2e048b03767dc', '4f4d180a72700dfeb94afdc524664c6d72cb10530dc5a97703378e79cf5d3634'),
        (256, 174, 693, 17, 'f12234d610c172b4222e3d2d2d70ec6910da0e8bb86976923a0adfd0b791ce0c', 'c1667570428f0869cdb737e5f02522a701ae20d8ffa10cac3ba63c024fcb176e'),
    ]),
    ('1.99.1', 'abort'): policies([
        (128, 136, 528, 12, 'efbb2c4bb4fe869458c7552348af2f0c5d3cbf42476337cd20c614a3d2749f33', '2c2ec4cf307ccc40923ad52c97d957269b41682b763eb47c53b6b8ab97c0c94e'),
        (192, 138, 544, 12, '3ad872df4f3b7f85a88ade185897365c5ce580bb4674c16b5edeed35b727aa76', 'fb1735df22462ef71d123d50e271b66d5667fb3eb7a8a38c9c515da1d15bf969'),
        (256, 140, 560, 12, 'dd98bd7be1ec4475d312c6cc17ccb0af5993bf7080f530e3a423831aea3ba0a7', '1928e4ff56a942e4dc5a5f8da268b4800d56c00b8d82a794793ce86a5d9d790c'),
    ]),
    ('1.99.1', 'unwind'): policies([
        (128, 132, 496, 11, 'a961db75c5b4f9cd48d84761f5a9a8007bd8826cfadc2c57aa61c7a76782f838', '499add6e706906843d3aa7593dd9e613302f1671779bdb1bde25e277a5d204f8'),
        (192, 134, 512, 11, '95ad86fcd66930d9a208aed6b7b35f62d532534669e3c218183b4b2019a8b9a6', 'c9d2821456bfdcbee867f7e4a40818759486fc28593a18bb73f62c3833982765'),
        (256, 136, 528, 11, '3ce2482f0b53b0a2ab800cfc5f95387544d35b55f66abc52c90b33d8e43e9a68', '9bea348d9d71c2ed581e5a112efba27406a3492e4a070613151cb84ecadc3623'),
    ]),
}


def candidates(table):
    selected = {}
    owner = r'9Aes(128|192|256)Key6secret'
    legacy = r'_ZN13brynja_crypto3aes9execution' + owner + r'17h[0-9a-f]{16}E'
    current = r'_RNvM(?:s[0-9a-z]*_)?NtNtC\w+_13brynja_crypto3aes9executionNtB[0-9a-z]+_' + owner
    for line in table.splitlines():
        if '3aes9execution' not in line or 'Key6secret' not in line or 'ExpandedKey' in line:
            continue
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(match is not None, 'unrecognized ephemeral-secret symbol row')
        address, size, name = match.groups()
        match = re.fullmatch(legacy, name) or re.fullmatch(current, name)
        require(match is not None, 'unrecognized ephemeral-secret symbol')
        bits = int(match[1])
        require(bits not in selected and int(size, 16) > 0, 'duplicate/empty ephemeral-secret symbol')
        selected[bits] = (name, int(address, 16), int(size, 16))
    require(set(selected) == {128, 192, 256}, 'ephemeral-secret symbol population changed')
    ordered = sorted(selected.values(), key=lambda r: r[1])
    require(all(a + n <= b for (_, a, n), (_, b, _) in zip(ordered, ordered[1:])), 'overlapping ephemeral-secret symbols')
    return selected


def expansion_candidates(table, assembly, image):
    selected = {}
    for row in expansion.select(table, TARGET):
        result = expansion.check(*kernels.decode(assembly, row, TARGET), row, image, TARGET)
        role = 'expand' + str(result['bits'])
        require(role not in selected, 'duplicate expansion width')
        selected[role] = row
    require(set(selected) == {'expand128', 'expand192', 'expand256'}, 'expansion population changed')
    return selected


def check(lines, raw, sizes, row, image, targets, bits, compiler, panic):
    require((compiler, panic) in POLICY and bits in POLICY[compiler, panic], 'unreviewed ephemeral-secret configuration')
    edges = {'encrypt', 'decrypt', 'zeroize', 'copy', 'expand'}
    if (compiler, panic) == ('1.90.0', 'unwind'):
        edges.add('resume')
    require(set(targets) == edges, 'ephemeral-secret call target population changed')
    require(len(raw) == row[2], 'ephemeral-secret symbol extent changed')
    actual, _ = image_review.observe(lines, raw, sizes, row[0], row[1], image, targets)
    require(actual == POLICY[compiler, panic][bits], 'ephemeral-secret stream changed; explicit re-review required')
    return {'bits': bits, **actual}


def mutations(lines, raw, sizes, row, image, targets, bits, compiler, panic):
    check(lines, raw, sizes, row, image, targets, bits, compiler, panic)
    rejected = 0
    for index in range(len(lines)):
        changed = list(lines)
        changed[index] = 'unreviewed-instruction'
        try:
            check(changed, raw, sizes, row, image, targets, bits, compiler, panic)
        except ValueError as error:
            require('stream changed' in str(error), 'text mutation rejected for unrelated reason')
            rejected += 1
        else:
            raise ValueError('ephemeral-secret textual mutation accepted')
    pos = kernels.mapped(image, TARGET, row[1], row[2])
    for index in range(len(raw)):
        altered = raw[:index] + bytes([raw[index] ^ 1]) + raw[index + 1:]
        replaced = image[:pos] + altered + image[pos + len(raw):]
        try:
            check(lines, altered, sizes, row, replaced, targets, bits, compiler, panic)
        except ValueError as error:
            require(any(s in str(error) for s in ('stream changed', 'branch destination mismatch',
                    'call destination mismatch', 'unsupported call encoding')), 'byte mutation rejected for unrelated reason')
            rejected += 1
        else:
            raise ValueError('ephemeral-secret encoded mutation accepted')
    return rejected


def inspect(table, assembly, image, compiler, panic, relocations=''):
    require((compiler, panic) in POLICY, 'unreviewed ephemeral-secret configuration')
    cached_result = cached.inspect(table, assembly, image, compiler, panic, relocations)
    helpers = cached.candidates(table)
    expansion_result = expansion.inspect(table, assembly, image, TARGET)
    expansions = expansion_candidates(table, assembly, image)
    session_result = sessions.inspect(table, assembly, image, compiler, panic, relocations)
    bound = sessions.candidates(table)
    targets = {role: helpers[role] for role in ('zeroize', 'copy')}
    if (compiler, panic) == ('1.90.0', 'unwind'):
        targets['resume'] = cached.public.cleanup.resume_target(assembly, relocations, image)
    results, rejected = [], 0
    for bits, row in sorted(candidates(table).items()):
        args = (*kernels.decode(assembly, row, TARGET), row, image,
                {**targets, 'encrypt': bound['encrypt', bits], 'decrypt': bound['decrypt', bits],
                 'expand': expansions['expand' + str(bits)]}, bits, compiler, panic)
        results.append(check(*args))
        rejected += mutations(*args)
    require(rejected == sum(p['instructions'] + p['symbol_bytes'] for p in POLICY[compiler, panic].values()),
            'ephemeral-secret mutation population changed')
    return {'wrappers': results, 'cached_secret_review': cached_result,
            'expansion_review': expansion_result, 'session_review': session_result,
            'rejected_wrapper_mutations': rejected,
            'scope': 'x86 cached and ephemeral secret encrypt/decrypt wrappers, hardware expansion and session closure, kernels, copy and clear; not constructors, ephemeral public callers, destructor entry points, ARM callers, or exception-table proof'}
