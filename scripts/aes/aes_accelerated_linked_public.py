"""Exact x86 cached public-encryption wrappers, not all accelerated owners.

The reviewed streams include authority admission, output staging and cleanup.
Compiler-specific landing pads are bound to the imported unwinder, not claimed
as a proof of exception-table dispatch. See the permanent assurance note.
"""
import importlib.util
from pathlib import Path
import re


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


kernels = module('aes_accelerated_linked_kernels')
image_review = module('aes_linked_mix')
helpers = module('aes_linked_helpers')
cleanup = module('aes_linked_cleanup')
require = kernels.require
TARGET = 'x86_64-unknown-linux-gnu'


def policies(count, size, calls, rows):
    return {bits: dict(instructions=count, symbol_bytes=size, calls=calls,
                      constant_loads=0, text_sha256=text, encoding_sha256=encoding)
            for bits, text, encoding in rows}


# Complete streams inspected, including both normal and error returns, and the
# 1.90 unwind landing pad. Width changes only the public schedule bound. No
# automatic refresh path: changes require reviewing the entire affected stream.
OLD_ABORT = policies(48, 139, 2, [
    (128, '911ed2831e0800ebaa710d5468e10381884f2dd7e38ac0fa5f7286308c8f323d', '8b4c35690bc26ec46317b1143b6c280dcc778717c743ab7772ec8960c8b2923a'),
    (192, '382f25a42c7156449509cfdffd867f3cf762cab5f00c36bb98080648a2ee1a6d', '739fff0b0fd8b26cf4251ec78435649bec9bb983396b9f5982b4eb14e5325a6a'),
    (256, '7cd5aa5edf98ff92ed586625450e7b04e0061c036b1f0f356f06435868eacc36', '2c894fac4fb1b6c44d3b40d1354c6d709e3f04214d51b7d3878ce72e53e5ee70'),
])
OLD_UNWIND = policies(73, 228, 4, [
    (128, '6a3f092dbec059f0ad0bc4fb251af3a10648d8221f45e6f94e2664e814627c64', '4ff041c29e6373ceeba6f631d44a556e8fea8862301c76310f61ae59fe10b502'),
    (192, '5cd0bdd7589873e72a1a2703cc1e5a02c74c2889e56fc008db2403c6874b6bcc', '6a21d3aed8d2afb29bcc9aa38007befe42c9c3714075ad84119793013cfdcc5e'),
    (256, '48a5f8a21406ab58f77142f71f755d9de4c3d305135b8f2eb603e0ae1f322931', '7262199b5d363f946d9a579caef332d19412d9ac1a6cbce3c11bcba883b62a97'),
])
CURRENT = policies(47, 138, 2, [
    (128, '966b2894839308aa52d02604cfc75c54b7fe3a4876eec3fe73eed29e06e32ee6', '7734dd7e48678ceafc42ac9a7f3b18f8a58679aca0866100f927105cbb66168f'),
    (192, 'a7596307a3018d0c513b9fb0e5f38ad5906dc505c9edf9cf92cd05e6dcbbe7f5', '43184abed4153da0204b12401b55d0b3c1a17e2b26bc02de016c1a88c100962f'),
    (256, 'bfc088f37b43dc8fbfeec9291928d864eab798ea98b89a96f5dc0bd44f89016d', '1d355ae1d3f20caf5feb5843ed4d2c9c9a8b5a51b77afc325107c369fe0eb71e'),
])
POLICY = {('1.90.0', 'abort'): OLD_ABORT, ('1.90.0', 'unwind'): OLD_UNWIND,
          ('1.99.1', 'abort'): CURRENT, ('1.99.1', 'unwind'): CURRENT}


def candidates(table):
    selected = {}
    owner = r'17Aes(128|192|256)ExpandedKey20encrypt_block_public'
    legacy = r'_ZN13brynja_crypto3aes9execution' + owner + r'17h[0-9a-f]{16}E'
    current = r'_RNvM(?:s[0-9a-z]*_)?NtNtC\w+_13brynja_crypto3aes9executionNtB[0-9a-z]+_' + owner
    clear = (r'(?:_ZN11brynja_core22secret_memory_volatile23zeroize_region_volatile17h[0-9a-f]{16}E|'
             r'_RNvNtC\w+_11brynja_core22secret_memory_volatile23zeroize_region_volatile)')
    for line in table.splitlines():
        relevant = ('3aes9execution' in line and 'encrypt_block_public' in line) or '23zeroize_region_volatile' in line
        if not relevant:
            continue
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(match is not None, 'unrecognized cached-public symbol row')
        address, size, name = match.groups()
        match = re.fullmatch(legacy, name) or re.fullmatch(current, name)
        if match:
            role = int(match[1])
        else:
            require(re.fullmatch(clear, name) is not None, 'unrecognized cached-public/clear symbol')
            role = 'zeroize'
        require(role not in selected and int(size, 16) > 0, 'duplicate/empty cached-public symbol')
        selected[role] = (name, int(address, 16), int(size, 16))
    require(set(selected) == {128, 192, 256, 'zeroize'}, 'cached-public symbol population changed')
    ordered = sorted(selected.values(), key=lambda r: r[1])
    require(all(a + n <= b for (_, a, n), (_, b, _) in zip(ordered, ordered[1:])), 'overlapping cached-public symbols')
    return selected


def check(lines, raw, sizes, row, image, targets, bits, compiler, panic):
    require((compiler, panic) in POLICY and bits in POLICY[compiler, panic], 'unreviewed cached-public configuration')
    edges = {'kernel', 'zeroize', 'resume'} if (compiler, panic) == ('1.90.0', 'unwind') else {'kernel', 'zeroize'}
    require(set(targets) == edges, 'cached-public call target population changed')
    require(len(raw) == row[2], 'cached-public symbol extent changed')
    actual, _ = image_review.observe(lines, raw, sizes, row[0], row[1], image, targets)
    require(actual == POLICY[compiler, panic][bits], 'cached-public stream changed; explicit re-review required')
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
            raise ValueError('cached-public textual mutation accepted')
    pos = kernels.mapped(image, TARGET, row[1], row[2])
    # Change matching file bytes as well: do not only test the file/decoder bind.
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
            raise ValueError('cached-public encoded mutation accepted')
    return rejected


def inspect(table, assembly, image, compiler, panic, relocations=''):
    require((compiler, panic) in POLICY, 'unreviewed cached-public configuration')
    selected = candidates(table)
    bound = {}
    for row in kernels.select(table, TARGET):
        result = kernels.check(*kernels.decode(assembly, row, TARGET), row, image, TARGET)
        require(result['bits'] not in bound, 'duplicate kernel width')
        bound[result['bits']] = row
    require(set(bound) == {128, 192, 256}, 'kernel width population changed')
    clear = selected['zeroize']
    lines, raw, sizes = kernels.decode(assembly, clear, TARGET)
    pos = kernels.mapped(image, TARGET, clear[1], clear[2])
    require(image[pos:pos + len(raw)] == raw, 'zeroize decoded bytes differ from executable')
    clear_result = helpers.check(lines, raw, clear[0], clear[1], 'zeroize', compiler)
    clear_mutations = helpers.mutations(lines, raw, clear[0], clear[1], 'zeroize', compiler)
    targets = {'zeroize': clear}
    if (compiler, panic) == ('1.90.0', 'unwind'):
        targets['resume'] = cleanup.resume_target(assembly, relocations, image)
    results, rejected = [], 0
    for bits in (128, 192, 256):
        row = selected[bits]
        args = (*kernels.decode(assembly, row, TARGET), row, image,
                {**targets, 'kernel': bound[bits]}, bits, compiler, panic)
        results.append(check(*args))
        rejected += mutations(*args)
    require(rejected == sum(p['instructions'] + p['symbol_bytes'] for p in POLICY[compiler, panic].values()),
            'cached-public mutation population changed')
    return {'wrappers': results, 'zeroize': clear_result, 'rejected_wrapper_mutations': rejected,
            'rejected_zeroize_mutations': clear_mutations,
            'scope': 'x86 cached public encrypt wrappers, matching kernels and volatile clear; not constructors, secret-output or ephemeral operations, ARM callers, or exception-table proof'}
