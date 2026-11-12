"""Bounded x86 cached secret-output caller review; see the assurance note.

Whole streams are pinned after inspection, not learned from a candidate build.
Only validated direct-call displacements may vary, including the explicitly
admitted tail edge to volatile clearing. No exception-table proof is claimed.
"""
import importlib.util
from pathlib import Path
import re


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


public = module('aes_accelerated_linked_public')
copy_review = module('aes_linked_wrappers')
kernels, image_review = public.kernels, public.image_review
require, TARGET = kernels.require, public.TARGET


def policies(count, size, calls, tails, rows):
    return {bits: {**policy, 'tail_calls': tails}
            for bits, policy in public.policies(count, size, calls, rows).items()}


OLD_ABORT = policies(69, 232, 5, 0, [
    (128, 'a6fbd15496a40852968c515059c97173c40e009033bf91bd1a761380b9639cc4', '990b55f504db71cf5205c7295ac8585480858d52421146530dfa7e4b1e64a780'),
    (192, '3716d0588dc0707aa2b0b557780baa49888b8ee09aeae1d4aa2036b4bfdb224b', 'd2e65812ad2b988e715af870fd83d0ce3c311a00bdd69eeae0d4b1d6af8f5a6c'),
    (256, 'e697dd704ed7e1603c7150603125256e021536211bb0e515aeb665f821a0b69b', '5d7c956f23797ac87d405b71034e01cee8300d16ae8a669e3e5acf0e97cdbea3'),
])
OLD_UNWIND = policies(95, 338, 9, 0, [
    (128, '978686cbb4f67764cbab1c5e7473c1faf5d1d45ca9183f300de771670e9c1635', '62d3810064005e6daaf7c04d9eabfd175eb3cf54147ff51f4a20fd464dd0c906'),
    (192, '228b977119fbebe10d7d55193380dce1bc2a9e292f89119336ff5a8e35cf574f', '5669197af0411f1237e4b5db5981792d986549ce63e56ceb7d090e7004bc5929'),
    (256, 'a6e455889b1feec094b39162c65e43943b1ddcce284586f7adebfcb884038e71', 'e3bc4979bc1137ef7a16ba050fd86deb163f1c6d6e1774f19e9634d2db8d3c48'),
])
CURRENT = policies(73, 250, 4, 1, [
    (128, 'f798376be2d1499b2546761ec984be346ea971ae57c03eae341148d5ad527886', 'a7cc43c352269ba9b584d2aea4704a40af31d67597e2edd22a71fedadbc169e0'),
    (192, 'fc3695c63e8969a86e9bc7f679fa117931b3b4f83f45ee4fc5b542c2a077563f', '03d0dfa813a88693a7e0dafb9ed1e2d0ce1d30816d5e3b7894b7dbde9ea8ffcb'),
    (256, '3dd92c876af93d73a3e97b8cf6ff5545a5744038238f24cb2dc89c33865d99e0', '6651be27316db8ea2e2c6971e98eff0a753c09f600551fa0ca26a05bf70fc8ac'),
])
POLICY = {('1.90.0', 'abort'): OLD_ABORT, ('1.90.0', 'unwind'): OLD_UNWIND,
          ('1.99.1', 'abort'): CURRENT, ('1.99.1', 'unwind'): CURRENT}


def candidates(table):
    selected = {}
    owner = r'17Aes(128|192|256)ExpandedKey6secret'
    legacy = r'_ZN13brynja_crypto3aes9execution' + owner + r'17h[0-9a-f]{16}E'
    current = r'_RNvM(?:s[0-9a-z]*_)?NtNtC\w+_13brynja_crypto3aes9executionNtB[0-9a-z]+_' + owner
    helpers = {'zeroize': '22secret_memory_volatile23zeroize_region_volatile',
               'copy': '22secret_memory_transfer10copy_bytes'}
    for line in table.splitlines():
        if not (('3aes9execution' in line and 'ExpandedKey6secret' in line)
                or any(name in line for name in helpers.values())):
            continue
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(match is not None, 'unrecognized cached-secret symbol row')
        address, size, name = match.groups()
        match = re.fullmatch(legacy, name) or re.fullmatch(current, name)
        if match:
            role = int(match[1])
        else:
            roles = [role for role, suffix in helpers.items() if re.fullmatch(
                r'(?:_ZN11brynja_core' + suffix + r'17h[0-9a-f]{16}E|_RNvNtC\w+_11brynja_core' + suffix + ')', name)]
            require(len(roles) == 1, 'unrecognized cached-secret/helper symbol')
            role = roles[0]
        require(role not in selected and int(size, 16) > 0, 'duplicate/empty cached-secret symbol')
        selected[role] = (name, int(address, 16), int(size, 16))
    require(set(selected) == {128, 192, 256, 'zeroize', 'copy'}, 'cached-secret symbol population changed')
    ordered = sorted(selected.values(), key=lambda r: r[1])
    require(all(a + n <= b for (_, a, n), (_, b, _) in zip(ordered, ordered[1:])), 'overlapping cached-secret symbols')
    return selected


def check(lines, raw, sizes, row, image, targets, bits, compiler, panic):
    require((compiler, panic) in POLICY and bits in POLICY[compiler, panic], 'unreviewed cached-secret configuration')
    edges = {'kernel', 'zeroize', 'copy'}
    if (compiler, panic) == ('1.90.0', 'unwind'):
        edges.add('resume')
    require(set(targets) == edges, 'cached-secret call target population changed')
    require(len(raw) == row[2], 'cached-secret symbol extent changed')
    actual, _ = image_review.observe(lines, raw, sizes, row[0], row[1], image, targets, tail_calls=('zeroize',))
    require(actual == POLICY[compiler, panic][bits], 'cached-secret stream changed; explicit re-review required')
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
            raise ValueError('cached-secret textual mutation accepted')
    pos = kernels.mapped(image, TARGET, row[1], row[2])
    for index in range(len(raw)):
        altered = raw[:index] + bytes([raw[index] ^ 1]) + raw[index + 1:]
        replaced = image[:pos] + altered + image[pos + len(raw):]
        try:
            check(lines, altered, sizes, row, replaced, targets, bits, compiler, panic)
        except ValueError as error:
            require(any(s in str(error) for s in ('stream changed', 'branch destination mismatch',
                    'call destination mismatch', 'unsupported call encoding', 'unsupported tail-call encoding')),
                    'byte mutation rejected for unrelated reason')
            rejected += 1
        else:
            raise ValueError('cached-secret encoded mutation accepted')
    return rejected


def inspect(table, assembly, image, compiler, panic, relocations=''):
    require((compiler, panic) in POLICY, 'unreviewed cached-secret configuration')
    selected = candidates(table)
    bound = {}
    for row in kernels.select(table, TARGET):
        result = kernels.check(*kernels.decode(assembly, row, TARGET), row, image, TARGET)
        require(result['bits'] not in bound, 'duplicate kernel width')
        bound[result['bits']] = row
    require(set(bound) == {128, 192, 256}, 'kernel width population changed')
    clear = selected['zeroize']
    lines, raw, _ = kernels.decode(assembly, clear, TARGET)
    pos = kernels.mapped(image, TARGET, clear[1], clear[2])
    require(image[pos:pos + len(raw)] == raw, 'zeroize decoded bytes differ from executable')
    clear_result = public.helpers.check(lines, raw, clear[0], clear[1], 'zeroize', compiler)
    clear_mutations = public.helpers.mutations(lines, raw, clear[0], clear[1], 'zeroize', compiler)
    copy = selected['copy']
    args = (*kernels.decode(assembly, copy, TARGET), copy[0], copy[1], image, {}, 'copy', compiler, panic)
    copy_result = copy_review.check(*args)
    copy_mutations = copy_review.mutations(*args)
    targets = {'zeroize': clear, 'copy': copy}
    if (compiler, panic) == ('1.90.0', 'unwind'):
        targets['resume'] = public.cleanup.resume_target(assembly, relocations, image)
    results, rejected = [], 0
    for bits in (128, 192, 256):
        row = selected[bits]
        args = (*kernels.decode(assembly, row, TARGET), row, image,
                {**targets, 'kernel': bound[bits]}, bits, compiler, panic)
        results.append(check(*args))
        rejected += mutations(*args)
    require(rejected == sum(p['instructions'] + p['symbol_bytes'] for p in POLICY[compiler, panic].values()),
            'cached-secret mutation population changed')
    return {'wrappers': results, 'zeroize': clear_result, 'copy': copy_result,
            'rejected_wrapper_mutations': rejected, 'rejected_zeroize_mutations': clear_mutations,
            'rejected_copy_mutations': copy_mutations,
            'scope': 'x86 cached secret encrypt/decrypt wrappers, matching kernels, copy and volatile clear; not constructors, ephemeral operations, returned-owner destruction, ARM callers, or exception-table proof'}
