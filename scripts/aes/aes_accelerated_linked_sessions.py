"""Complete x86 session round-call bodies, bound to reviewed width/direction.

These exact streams were inspected with the per-operation caller review. Only
validated direct-call displacements are normalized. No automatic policy refresh.
"""
import importlib.util
from pathlib import Path
import re

SPEC = importlib.util.spec_from_file_location('session_cached_helpers',
    Path(__file__).with_name('aes_accelerated_linked_secret.py'))
cached = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cached)
kernels, image_review = cached.kernels, cached.image_review
require, TARGET = kernels.require, cached.TARGET


def policy(count, size, calls, text, encoding):
    return dict(instructions=count, symbol_bytes=size, calls=calls, constant_loads=0,
                text_sha256=text, encoding_sha256=encoding)


OLD_ABORT = {
    'encrypt': policy(24, 56, 1, '21a87d1ffd8c510eef95244dda32a09e0e27e7fe289340b9faaa0d6b009a3608', 'b2e3a74d3f728aa3afdd8ddc19dc23fc894239e43629b50a19a1a2040676ec83'),
    'decrypt': policy(24, 59, 1, 'e004c9b86ad027add798c0e6014c365a5c46847d35203887252071e9f2df6a2f', 'c83ddd8de54347632d5992a4086d681a4574753b72135b063e5bd77169878ba4'),
}
OLD_UNWIND = {
    'encrypt': policy(36, 98, 2, '7b474faf26e8fedc5540142bc52f1269190e8bec6e3bf334436b2bf439195384', 'aa4e6ed2b4f4957622ce7cf9430885421c0da8e04cfd386a418af72ea89e2e31'),
    'decrypt': policy(36, 101, 2, 'e762368e87aa1af80feaa84f7788132905a22772a16c6f4cfa05f0698cadd18b', 'dd70511b23f5fe9e3713179ea382e3adc5029284346c8a91a949ef67fa5ff310'),
}
CURRENT = {
    'encrypt': policy(24, 56, 1, '1d98c088fda1e5d9396eeb578e54f8a85a95dea2a775c37b42e7226f62e59d61', '0366f1cc568a0fd574cca4cd7ac8e70aae8cfbd9a6bea68015c2a88ae005feee'),
    'decrypt': policy(24, 59, 1, 'bd917b2a5e0eff12890dc0ffe571401eda8d6fa38de9a7619f7a3489328eb884', '7a3f182ab9951b540f5fc7c325cc4fad11091fa5579ae6c10270d7a2dae375f8'),
}
POLICY = {('1.90.0', 'abort'): OLD_ABORT, ('1.90.0', 'unwind'): OLD_UNWIND,
          ('1.99.1', 'abort'): CURRENT, ('1.99.1', 'unwind'): CURRENT}


def candidates(table):
    selected = {}
    operation = r'7Session10(encrypt|decrypt)(128|192|256)'
    legacy = r'_ZN17brynja_crypto_cpu3aes' + operation + r'17h[0-9a-f]{16}E'
    current = r'_RNvM(?:s[0-9a-z]*_)?NtC\w+_17brynja_crypto_cpu3aesNtB[0-9a-z]+_' + operation
    for line in table.splitlines():
        if '17brynja_crypto_cpu3aes' not in line or '7Session' not in line or not any(s in line for s in ('encrypt', 'decrypt')):
            continue
        row = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(row is not None, 'unrecognized session symbol row')
        match = re.fullmatch(legacy, row[3]) or re.fullmatch(current, row[3])
        require(match is not None, 'unrecognized session symbol')
        role = match[1], int(match[2])
        require(role not in selected and int(row[2], 16) > 0, 'duplicate/empty session symbol')
        selected[role] = row[3], int(row[1], 16), int(row[2], 16)
    require(set(selected) == {(d, b) for d in ('encrypt', 'decrypt') for b in (128, 192, 256)},
            'session symbol population changed')
    ordered = sorted(selected.values(), key=lambda r: r[1])
    require(all(a + n <= b for (_, a, n), (_, b, _) in zip(ordered, ordered[1:])), 'overlapping session symbols')
    return selected


def check(lines, raw, sizes, row, image, targets, direction, compiler, panic):
    require((compiler, panic) in POLICY and direction in POLICY[compiler, panic], 'unreviewed session configuration')
    require(set(targets) == ({'kernel', 'resume'} if (compiler, panic) == ('1.90.0', 'unwind') else {'kernel'}),
            'session call target population changed')
    require(len(raw) == row[2], 'session extent changed')
    actual, _ = image_review.observe(lines, raw, sizes, row[0], row[1], image, targets)
    require(actual == POLICY[compiler, panic][direction], 'session stream changed; explicit re-review required')
    return {'direction': direction, **actual}


def mutations(lines, raw, sizes, row, image, targets, direction, compiler, panic):
    check(lines, raw, sizes, row, image, targets, direction, compiler, panic)
    pos = kernels.mapped(image, TARGET, row[1], row[2])
    rejected = 0
    for index in range(len(lines) + len(raw)):
        text, code, executable = list(lines), raw, image
        if index < len(lines):
            text[index] = 'unreviewed-instruction'
        else:
            offset = index - len(lines)
            code = raw[:offset] + bytes([raw[offset] ^ 1]) + raw[offset + 1:]
            executable = image[:pos] + code + image[pos + len(code):]
        try:
            check(text, code, sizes, row, executable, targets, direction, compiler, panic)
        except ValueError as error:
            require(any(s in str(error) for s in ('stream changed', 'branch destination mismatch',
                    'call destination mismatch', 'unsupported call encoding')), 'session mutation rejected for unrelated reason')
            rejected += 1
        else:
            raise ValueError('session mutation accepted')
    return rejected


def inspect(table, assembly, image, compiler, panic, relocations=''):
    require((compiler, panic) in POLICY, 'unreviewed session configuration')
    selected = candidates(table)
    bound = {}
    for row in kernels.select(table, TARGET):
        result = kernels.check(*kernels.decode(assembly, row, TARGET), row, image, TARGET)
        require(result['bits'] not in bound, 'duplicate session kernel width')
        bound[result['bits']] = row
    require(set(bound) == {128, 192, 256}, 'session kernel population changed')
    extra = {}
    if (compiler, panic) == ('1.90.0', 'unwind'):
        extra['resume'] = cached.public.cleanup.resume_target(assembly, relocations, image)
    results, rejected = [], 0
    for (direction, bits), row in sorted(selected.items()):
        args = (*kernels.decode(assembly, row, TARGET), row, image,
                {'kernel': bound[bits], **extra}, direction, compiler, panic)
        results.append({'bits': bits, **check(*args)})
        rejected += mutations(*args)
    require(rejected == 3 * sum(p['instructions'] + p['symbol_bytes'] for p in POLICY[compiler, panic].values()),
            'session mutation population changed')
    return {'sessions': results, 'rejected_mutations': rejected,
            'scope': 'six static x86 session round-call bodies and matched kernels; not startup, hosted admission or exception-table proof'}
