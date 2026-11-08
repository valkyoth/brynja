"""Bounded AArch64 inverse instruction review, not a latency or whole-code proof.

Never refresh policy fingerprints automatically. Review changed instructions
first. Other AES helpers are constrained by the separate LLVM model, not by
this inverse-only machine grammar.
"""
import hashlib
import json
from pathlib import Path
import re

POLICY = Path(__file__).with_name('aarch64-inverse-review.json')
REVIEW = 'docs/assurance/aes-aarch64-review.md'
REGISTER = r'w(?:[0-9]|[12][0-9]|30)'
SAVE = {'str x27, [sp, #-80]!', 'stp x26, x25, [sp, #16]', 'stp x24, x23, [sp, #32]',
        'stp x22, x21, [sp, #48]', 'stp x20, x19, [sp, #64]'}
RESTORE = {'ldr x27, [sp], #80', 'ldp x26, x25, [sp, #16]', 'ldp x24, x23, [sp, #32]',
           'ldp x22, x21, [sp, #48]', 'ldp x20, x19, [sp, #64]'}


def require(condition, message):
    if not condition:
        raise ValueError('AES AArch64 inverse: ' + message)


def body(assembly, symbol):
    found = re.findall(r'^' + re.escape(symbol) + r':\n(.*?)^\s*\.size\s+'
                       + re.escape(symbol) + r',', assembly, re.M | re.S)
    require(len(found) == 1, 'missing/ambiguous inverse assembly')
    lines = []
    for line in found[0].splitlines():
        # AArch64 immediates start with #; unlike x86 this is NOT a comment.
        line = line.split('//', 1)[0].strip()
        if not line or line.startswith('.cfi_'):
            continue
        if re.fullmatch(r'\.Lfunc_end\d+:', line):
            continue  # Non-executable function-end label, no branches admitted.
        lines.append(' '.join(line.split()))
    require(lines, 'empty inverse assembly')
    return lines


def instructions(lines):
    require(len(lines) > 100 and lines[-1] == 'ret' and lines.count('ret') == 1,
            'truncated/changed inverse return')
    require(lines[0] == 'str x27, [sp, #-80]!' and lines[-2] == 'ldr x27, [sp], #80',
            'inverse stack frame changed')
    for line in SAVE | RESTORE:
        require(lines.count(line) == 1, 'fixed frame save/restore population changed')
    for line in lines:
        if line in SAVE | RESTORE or line == 'ret':
            continue
        if re.fullmatch(r'(?:and|eor) ' + REGISTER + ', ' + REGISTER + ', ' + REGISTER
                        + r'(?:, (?:lsl|lsr|asr) #(?:[0-9]|[12][0-9]|3[01]))?', line):
            continue
        if re.fullmatch(r'lsl ' + REGISTER + ', ' + REGISTER + r', #(?:[0-9]|[12][0-9]|3[01])', line):
            continue
        if re.fullmatch(r'sxtb ' + REGISTER + ', ' + REGISTER, line):
            continue
        extract = re.fullmatch(r'sbfx ' + REGISTER + ', ' + REGISTER + r', #(\d+), #(\d+)', line)
        if extract:
            low, width = map(int, extract.groups())
            require(0 <= low < 32 and 1 <= width <= 32 - low, 'invalid bitfield extent')
            continue
        if re.fullmatch(r'mov ' + REGISTER + ', #27', line):
            continue
        if re.fullmatch(r'cmn ' + REGISTER + ', #1', line):
            continue
        if re.fullmatch(r'csel ' + REGISTER + ', wzr, ' + REGISTER + ', gt', line):
            continue
        raise ValueError('AES AArch64 inverse: unreviewed instruction or operands: ' + line)
    return len(lines)


def fingerprint(assembly, symbol):
    lines = body(assembly, symbol)
    instructions(lines)
    return hashlib.sha256(('\n'.join(lines) + '\n').encode()).hexdigest(), len(lines)


def check(assembly, symbol, compiler, panic, policy=None):
    policy = json.loads(POLICY.read_text()) if policy is None else policy
    require(set(policy) == {'schema', 'review', 'target', 'panics', 'compilers'}
            and policy['schema'] == 1 and policy['review'] == REVIEW
            and policy['target'] == 'aarch64-unknown-linux-gnu'
            and policy['panics'] == ['abort', 'unwind']
            and set(policy['compilers']) == {'1.90.0', '1.99.1'}, 'review scope changed')
    require(compiler in policy['compilers'] and panic in policy['panics'], 'unreviewed configuration')
    require(all(isinstance(profiles, dict) and set(profiles) == {'abort', 'unwind'}
                and all(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value)
                        for value in profiles.values())
                for profiles in policy['compilers'].values()), 'invalid fingerprint')
    digest, count = fingerprint(assembly, symbol)
    require(digest == policy['compilers'][compiler][panic], 'instruction stream changed; explicit re-review required: ' + digest)
    return count
