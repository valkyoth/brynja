#!/usr/bin/env python3
"""Replay the bounded Linux ARM hosted DIT session review; not timing qualification."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


constructors = module('dit_constructors', 'aes_accelerated_linked_arm_constructors.py')
expansion = module('dit_expansion', 'aes_accelerated_linked_expansion.py')
arm, kernels, require = constructors.portable, constructors.kernels, constructors.require
TARGET = 'aarch64-unknown-linux-musl'
# Manually inspected whole-body streams; no command regenerates this policy.
# See docs/assurance/aes-dit.md for scope and control-flow reasoning.
POLICY = {
    '1.90.0': {
        'expand': (113, 21, 3, '0d79b0a4ab59a3ba07d044e9aa144a0329abcb0e927c81af69e1841acbedda0a', '31262e7e10723e3f21dd79c52efcd92d36b9c2e929d160cedcddc29ac02ac5c5'),
        'encrypt': (88, 11, 2, '4bc8b5adb3f532e19bd84f72a7357e54b59bb16d900a96e4d806c33eec1386fb', '7974af67ce56559cd5962c06fe106e965d5f393d98605498fe6cb38be07b231f'),
        'decrypt': (88, 11, 2, '14ab4c0712ce0d4cd42a0df1865ffa8d945ac8f57028522915dfe163b86a8868', '14aac14ed76964774687146d3a5b65a0525e2223a69799bf82c9efe55f303e6d'),
    },
    '1.99.1': {
        'expand': (97, 18, 2, '6de4678b5a7172d2e746d611e266b0f9df96a5384b82fa00a57c49e634d669e6', 'aa11716bd1e1b8bf61efab7230251a94d780edefa55e0525c8788fe816277808'),
        'encrypt': (74, 8, 2, 'f349dcdc3cf048088b0b97c34c086acef2aaa131b0ad8875af90aa353c59895b', 'fcb90b113565e71ea7c850dcfb698c25e5099d4a32e518065437642310c9a526'),
        'decrypt': (74, 8, 2, '9b3e51bd08946185e1d61293e92eb9c100f0fed2943266b7ace7e42330373400', '838dae248f1b04d5a209e17c93fe1b121b89feccd7eab37c247f806fe3a34896'),
    },
}
RESUME_SHA256 = '693ddef69a3b9400022564ef40a1049c37d9cbbb20430f7190de28e9b3a680c5'


def candidates(table):
    selected = {}
    operation = r'7Session(?:9(expand)|10(encrypt|decrypt))(128|192|256)'
    legacy = r'_ZN17brynja_crypto_cpu3aes' + operation + r'17h[0-9a-f]{16}E'
    current = r'_RNvM(?:s[0-9a-z]*_)?NtC\w+_17brynja_crypto_cpu3aesNtB[0-9a-z]+_' + operation
    for line in table.splitlines():
        if '17brynja_crypto_cpu3aes' not in line or '7Session' not in line or not any(k in line for k in ('expand', 'encrypt', 'decrypt')):
            continue
        row = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(row is not None, 'invalid DIT session symbol row')
        match = re.fullmatch(legacy, row[3]) or re.fullmatch(current, row[3])
        require(match is not None, 'invalid DIT session symbol')
        role = match[1] or match[2], int(match[3])
        require(role not in selected, 'duplicate DIT session')
        selected[role] = row[3], int(row[1], 16), int(row[2], 16)
    require(set(selected) == {(k, b) for k in ('expand', 'encrypt', 'decrypt') for b in (128, 192, 256)},
            'DIT session population changed')
    constructors.cleanup.disjoint(selected.values())
    return selected


def check(lines, raw, row, image, targets, compiler, kind):
    require(compiler in POLICY and kind in POLICY[compiler], 'unreviewed DIT configuration')
    require(set(targets) == ({'kernel', 'resume'} if compiler == '1.90.0' else {'kernel'}),
            'DIT call population changed')
    count, branches, calls, text, encoded = POLICY[compiler][kind]
    expected = dict(instructions=count, branches=branches, calls=calls, constants=0,
                    text_sha256=text, encoding_sha256=encoded)
    actual, _, _ = arm.observe(lines, raw, row, image, targets)
    require(actual == expected, 'DIT session stream changed; explicit re-review required')
    return actual


def inspect(table, assembly, image, compiler):
    require(compiler in POLICY, 'unreviewed DIT compiler')
    selected, bound = candidates(table), {}
    rejected = 0
    for kind, reviewer in (('round', kernels), ('expand', expansion)):
        for row in reviewer.select(table, TARGET):
            args = (*kernels.decode(assembly, row, TARGET), row, image, TARGET)
            result = reviewer.check(*args)
            key = kind, result['bits']
            require(key not in bound, 'duplicate DIT kernel width')
            bound[key] = row
            rejected += kernels.mutations(*args, checker=reviewer.check)
    require(len(bound) == 6, 'DIT kernel population changed')
    runtime = {}
    if compiler == '1.90.0':
        matches = [line for line in table.splitlines() if '_Unwind_Resume' in line]
        require(len(matches) == 1, 'ambiguous DIT unwind boundary')
        match = re.fullmatch(r'([0-9a-f]+) 00000000000000b8 T _Unwind_Resume', matches[0])
        require(match is not None, 'DIT unwind boundary extent changed')
        row = '_Unwind_Resume', int(match[1], 16), 184
        pos = arm.mapped(arm.segments(image), row[1], row[2], 5)
        require(hashlib.sha256(image[pos:pos + row[2]]).hexdigest() == RESUME_SHA256,
                'DIT unwind runtime changed; explicit re-review required')
        runtime['resume'] = row
    constructors.cleanup.disjoint([*selected.values(), *bound.values(), *runtime.values()])
    reports = []
    for (kind, bits), row in sorted(selected.items()):
        targets = {'kernel': bound['expand' if kind == 'expand' else 'round', bits], **runtime}
        args = (*constructors.decode(assembly, row), row, image, targets, compiler, kind)
        reports.append({'operation': kind, 'bits': bits, **check(*args)})
        rejected += constructors.mutations(check, *args)
    return {'binary_sha256': hashlib.sha256(image).hexdigest(), 'compiler': compiler,
            'sessions': reports, 'rejected_mutations': rejected,
            'scope': 'nine hosted Linux ARM DIT sessions and six raw kernels only; '
                     'not startup, caller cleanup, exception-table dispatch, Apple, timing or spill erasure'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=tuple(POLICY), required=True)
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    image = args.binary.read_bytes()
    def output(command):
        result = subprocess.run(command, text=True, capture_output=True, check=True)
        require(not result.stderr, 'DIT inspection tool diagnostic')
        return result.stdout
    table = output(['llvm-nm', '-S', '--defined-only', str(args.binary)])
    assembly = output(['llvm-objdump', '-d', '--no-print-imm-hex', str(args.binary)])
    result = inspect(table, assembly, image, args.toolchain)
    require(args.binary.read_bytes() == image, 'DIT binary changed during inspection')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f'AES DIT linked FAIL: {error}') from error
