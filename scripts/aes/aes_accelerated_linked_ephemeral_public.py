"""Bounded x86 public-output review through package-external operation wrappers.

The library operation is inlined into these fixture wrappers. No constructor,
destructor, ARM caller or arbitrary downstream inlining claim is made.
"""
import importlib.util
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('ephemeral_dependency_review',
        Path(__file__).with_name('aes_accelerated_linked_ephemeral.py'))
secret = importlib.util.module_from_spec(spec)
spec.loader.exec_module(secret)
kernels, image_review = secret.kernels, secret.image_review
require, TARGET = secret.require, secret.TARGET

# Entire normal/error streams inspected, not generated from an accepting run.
# Width variants differ in frame sizes, zero stores, cleanup sizes and branches.
POLICY = {
    ('1.90.0', 'abort'): secret.policies([
        (128, 96, 350, 5, 'be92166a72e97bd1fc60a9f7c8a001c312c525e5796ce36041ea40dde1fe83f4', '07ae132564498b7df7148b89bdccd61aaa36be44e5bb6fd6aa391682cdd67e3d'),
        (192, 98, 366, 5, '9b977b448743caf5f7c6cda9594ca75cc4e30879eab7e85778f7095e79ceade2', '6e3510308c31ce37bdcaaab793f5f52cef0a4a9623d608f35edb294cf709d9f6'),
        (256, 100, 382, 5, '5dce17aafdaa8ad6b1f88e8309d6178921ea5f2557175d53cb05510e8949653c', '344bef3d3f50b2187739c6c133dd92644941eabf77971dfe537c62381b44d274'),
    ]),
    ('1.90.0', 'unwind'): secret.policies([
        (128, 117, 450, 8, '483054230556f159584f6c0f042f6165cfd9e728deb128e38eb346a8fc644572', '9b1ab8fd55095f1b3e4a3f227a7184c8faf747c2a3c639bafe99c6f95acf23cf'),
        (192, 119, 466, 8, '77502ba655a0286481b066ff5712968dba9ea911e4cdbf1c7e7c54dea47317ac', 'ae40cf9fda84879342556e099fe21955a80c1797a17b211e8d7575d032201ad4'),
        (256, 121, 482, 8, '41e7f84b34b105b2e86597d26292657012303293bce1b7a4cd51296fc72d3b18', '9e31e6848b036302badf59e79b36e901a416fa7a77dc4d38cb2374b3a7c28087'),
    ]),
    ('1.99.1', 'abort'): secret.policies([
        (128, 98, 353, 5, 'c4de9e39cdca2a0ae57b9e39166c35cbb6e568cd63c832c81f786b7c60f9b61a', '7947b104500dfd5868dd77857cc3de17fceae3cb9ef72c031bbd69c722b2b1f2'),
        (192, 100, 369, 5, 'cb3830b0d27a3257d45eb9fd620d21edd1142477b55d0366cad1c4eb375085f0', 'f23c99ff2e9b311bbd9c074b3cffd832e60fd5b0ff26ea5d46d033b279b034b3'),
        (256, 102, 385, 5, '0fd1f6b5a22ea4c6e1b36c59f2122e7fefbbab523052c17cc67d829179c1d7ec', '74c3adad5dec18af67e74c56d63fc7bf431618592b481b8e4189eb7cdd2e769a'),
    ]),
    ('1.99.1', 'unwind'): secret.policies([
        (128, 96, 349, 5, '607174caa870210c63b93105664b0274e338a6cc9ff452b23b9fd2069428a48f', '326d0df805dd9acbb85e1e05aee1b3402a2a27c70a73c817dc3a48b1fb47d391'),
        (192, 98, 365, 5, 'e1e01f64847f1fbe478bc81394742ca3dbdffe6c778f4f012d4f48100c0db48c', '075894bc3dae35b21dc94dfb1efb5889f639930ecd732d00a68cf46c757134ae'),
        (256, 100, 381, 5, 'b6ee6cb8a082e932a4168226bc91f9e86a7383bb3c1eb7f840a6d8219d4c0c64', 'f221e6d65ef9a2edc244de672e15ca88d26ff93561a37d77da4ad868e8339ff2'),
    ]),
}


def candidates(table):
    selected = {}
    legacy = r'_ZN30brynja_aes_accelerated_fixture9public(128|192|256)17h[0-9a-f]{16}E'
    current = r'_RNvC\w+_30brynja_aes_accelerated_fixture9public(128|192|256)'
    for line in table.splitlines():
        if '30brynja_aes_accelerated_fixture9public' not in line:
            continue
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(match is not None, 'unrecognized ephemeral-public symbol row')
        address, size, name = match.groups()
        match = re.fullmatch(legacy, name) or re.fullmatch(current, name)
        require(match is not None, 'unrecognized ephemeral-public symbol')
        bits = int(match[1])
        require(bits not in selected and int(size, 16) > 0, 'duplicate/empty ephemeral-public symbol')
        selected[bits] = (name, int(address, 16), int(size, 16))
    require(set(selected) == {128, 192, 256}, 'ephemeral-public symbol population changed')
    ordered = sorted(selected.values(), key=lambda row: row[1])
    require(all(a + n <= b for (_, a, n), (_, b, _) in zip(ordered, ordered[1:])), 'overlapping ephemeral-public symbols')
    return selected


def check(lines, raw, sizes, row, image, targets, bits, compiler, panic):
    require((compiler, panic) in POLICY and bits in POLICY[compiler, panic], 'unreviewed ephemeral-public configuration')
    edges = {'kernel', 'zeroize', 'expand'}
    if (compiler, panic) == ('1.90.0', 'unwind'):
        edges.add('resume')
    require(set(targets) == edges, 'ephemeral-public call target population changed')
    require(len(raw) == row[2], 'ephemeral-public symbol extent changed')
    actual, _ = image_review.observe(lines, raw, sizes, row[0], row[1], image, targets)
    require(actual == POLICY[compiler, panic][bits], 'ephemeral-public stream changed; explicit re-review required')
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
            raise ValueError('ephemeral-public textual mutation accepted')
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
            raise ValueError('ephemeral-public encoded mutation accepted')
    return rejected


def inspect(table, assembly, image, compiler, panic, relocations=''):
    require((compiler, panic) in POLICY, 'unreviewed ephemeral-public configuration')
    # Replay the pinned hardware expansion, sessions, secret wrappers and
    # dependencies, plus cached public callers. No unreviewed callee shortcut.
    dependencies = secret.inspect(table, assembly, image, compiler, panic, relocations)
    cached_public = secret.cached.public.inspect(table, assembly, image, compiler, panic, relocations)
    expansions = secret.expansion_candidates(table, assembly, image)
    helpers = secret.cached.candidates(table)
    bound = {}
    for row in kernels.select(table, TARGET):
        result = kernels.check(*kernels.decode(assembly, row, TARGET), row, image, TARGET)
        require(result['bits'] not in bound, 'duplicate kernel width')
        bound[result['bits']] = row
    require(set(bound) == {128, 192, 256}, 'kernel width population changed')
    targets = {'zeroize': helpers['zeroize']}
    if (compiler, panic) == ('1.90.0', 'unwind'):
        targets['resume'] = secret.cached.public.cleanup.resume_target(assembly, relocations, image)
    results, rejected = [], 0
    for bits, row in sorted(candidates(table).items()):
        args = (*kernels.decode(assembly, row, TARGET), row, image,
                {**targets, 'kernel': bound[bits], 'expand': expansions['expand' + str(bits)]}, bits, compiler, panic)
        results.append(check(*args))
        rejected += mutations(*args)
    require(rejected == sum(p['instructions'] + p['symbol_bytes'] for p in POLICY[compiler, panic].values()),
            'ephemeral-public mutation population changed')
    return {'wrappers': results, 'secret_and_expansion_review': dependencies,
            'cached_public_review': cached_public, 'rejected_wrapper_mutations': rejected,
            'scope': 'x86 per-operation public encryption in package-external wrappers plus replayed cached public and secret operation closure; not constructors, destructors, ARM callers, arbitrary downstream inlining or exception-table proof'}
