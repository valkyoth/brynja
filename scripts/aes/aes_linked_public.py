"""Pinned public-consumer boundaries and their six production constructors.

Normal/error return paths only; not arbitrary inlining or exception dispatch.
"""
import importlib.util
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('aes_public_image', Path(__file__).with_name('aes_linked_mix.py'))
image_review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image_review)
require = image_review.require
EDGES = {}
for width in (128, 192, 256):
    EDGES[f'new{width}'] = ('zeroize', 'copy')
    EDGES[f'cached_new{width}'] = ('zeroize', 'copy', f'expand{width}')
    EDGES[f'public{width}'] = ('zeroize', f'new{width}', f'expand{width}', f'transform{width}')
    EDGES[f'cached_public{width}'] = ('zeroize', f'cached_new{width}', f'transform{width}')


def candidates(table):
    selected = {}
    consumer = (r'(?:_ZN6linked(9public|16cached_public)(128|192|256)17h[0-9a-f]{16}E|'
                r'_RNvC\w+_6linked(9public|16cached_public)(128|192|256))')
    owner = r'(9Aes(?:128|192|256)Key|17Aes(?:128|192|256)ExpandedKey)3new'
    legacy = r'_ZN13brynja_crypto3aes(?:4wide)?' + owner + r'17h[0-9a-f]{16}E'
    current = r'_RNvM(?:s[0-9a-z]*_)?Nt(?:Nt)?C\w+_13brynja_crypto3aes(?:4wide)?NtB[0-9a-z]+_' + owner
    for line in table.splitlines():
        relevant = ('6linked' in line and 'public' in line) or (
            '13brynja_crypto3aes' in line and 'Key3new' in line)
        if not relevant:
            continue
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(match is not None, 'unrecognized public/constructor symbol row')
        address, size, name = match.groups()
        row = (name, int(address, 16), int(size, 16))
        require(row[2] > 0, 'empty public/constructor symbol')
        match = re.fullmatch(consumer, name)
        if match:
            kind, bits = match.groups()[:2] if match[1] else match.groups()[2:]
            role = ('public' if kind == '9public' else 'cached_public') + bits
        else:
            match = re.fullmatch(legacy, name) or re.fullmatch(current, name)
            require(match is not None, 'unrecognized public/constructor symbol')
            bits = re.search(r'Aes(128|192|256)', match[1])[1]
            require(('4wide' in name) == (bits != '128'), 'constructor namespace mismatch')
            role = ('cached_new' if match[1].startswith('17') else 'new') + bits
        require(role not in selected, 'duplicate public/constructor role')
        selected[role] = row
    require(set(selected) == set(EDGES), 'public/constructor population changed')
    ordered = sorted(selected.values(), key=lambda row: row[1])
    require(all(a[1] + a[2] <= b[1] for a, b in zip(ordered, ordered[1:])),
            'overlapping public/constructor symbols')
    return selected


def policy(count, size, calls, text, encoding):
    return dict(instructions=count, symbol_bytes=size, calls=calls, constant_loads=0,
                text_sha256=text, encoding_sha256=encoding)


# Complete streams explicitly reviewed, identical after validated call/branch
# binding on both compiler endpoints and panic profiles. No auto-refresh path.
POLICY = {
    'new128': policy(20, 68, 2,
        'bab2f72ff0ed97ca46592d591c2f284695a1465685ff0c5f183908ca22efd70f',
        'b829650b9cd8db9df7fd89c3b783d113a45e575348de136c157f4995765a8daf'),
    'new192': policy(20, 68, 2,
        'edc93b10832462a46923f646081224cc4cc4bd4c3dfb9fa6dad9745ceea3d524',
        '63bb3febd3fda38601aec66b8d3403047076716ec6b07a1141d64f5387e1aad9'),
    'new256': policy(20, 68, 2,
        '99e37aa7da65326a30a93e9425b14d6e61803105e664476cfcf87d4e87503d7d',
        '43677e897115d64e4c018c6770017007da8fd899826f4f1d38b957cdc74083fe'),
    'cached_new128': policy(51, 214, 5,
        'fa66e39c494daea23883dd025ae52c65d2b1496529b81cca55b29cd6eab2ce05',
        '4e83161302dda7d2977eba67c782462b9bc965d778d779cd5d5c295ca33b1e84'),
    'cached_new192': policy(53, 230, 5,
        '43bc6cb4bdfa4de5522913878a2d3962d6aaa884d19fd12d6438e39e6272510c',
        '2431fc15a01eb4757e61d1fc526bf1049110057f91263506bd9e25b05512300b'),
    'cached_new256': policy(55, 246, 5,
        'e041e1cf64d3048fd809c0f5f91767c6493917d4d8263ee76b58310bd9daa1ec',
        'ec8cd78fc98b66d7b1ad318a4cfcd56212b4a1fa5ed0c03a8d23fa23f7cf42e4'),
    'public128': policy(70, 268, 6,
        '57dd8e011c2c847b2e1d753d35a1b42414c451640a75e20bda1db8b2016acd1e',
        'a48ab01a751aa3476ff62d4c2f95f355b4b5b47da7804b69d3e408c87288538c'),
    'public192': policy(72, 284, 6,
        '4ce93bc0bd4a57b1c549cecdb30b12c72cc64eb277d39431f45be13169de1abb',
        'e78d71773bbd34a69cfafedf246721b0f8fe3aede762b3bb8732b5149f4e9e28'),
    'public256': policy(74, 300, 6,
        '2f5aaf4480504f177fa8d6cb15756e43c9b0fce7df127edde85123d820f26bec',
        'bb6e7cb5c447f5c798a90d25300e89fdfa0e34e75d0e186d4ca6860940ad00df'),
    'cached_public128': policy(54, 161, 4,
        '42a0106d37b69d1ea0223dc1f6f611d3f3e4ff81ad8f04c60d68863fb0c98b4e',
        '411bf825d7831a1440f91cbdc64f569820f02f14b710fb1b0453e3ec7bee7cd4'),
    'cached_public192': policy(54, 161, 4,
        '04f0d5bc4c71013334a475a242b32e98070e176e9664a2d4bcae1aecdcdc21fe',
        '1cfa1362a8b63ed1ad9d965c05f693f651bba2084b4bb191572c9846c0e6d634'),
    'cached_public256': policy(54, 161, 4,
        '3ed4f81ef9d834f160e81e81a5cc46754e41bacd2eb06d61b82a346f1b068fc7',
        '1da8672a07c6ebee5ee869bd687a1462fe26c550961c9fbca7239c08f79e9d5b'),
}


def check(lines, raw, sizes, symbol, start, image, targets, role, compiler, panic):
    require(compiler in ('1.90.0', '1.99.1') and panic in ('abort', 'unwind')
            and role in POLICY, 'unreviewed public configuration')
    require(set(targets) == set(EDGES[role]), 'public call target population changed')
    actual, _ = image_review.observe(lines, raw, sizes, symbol, start, image, targets)
    require(actual == POLICY[role], 'reviewed public/constructor changed; explicit re-review required')
    return {'role': role, **actual}


def mutations(lines, raw, sizes, symbol, start, image, targets, role, compiler, panic):
    check(lines, raw, sizes, symbol, start, image, targets, role, compiler, panic)
    changed_reason = 'reviewed public/constructor changed'
    call = next(i for i, line in enumerate(lines) if line.startswith('callq '))
    clears = [i for i, line in enumerate(lines) if line.endswith('<' + targets['zeroize'][0] + '>')]
    size = next(i for i in range(clears[0] - 1, -1, -1) if re.fullmatch(r'movl \$\d+, %esi', lines[i]))
    replacements = [(0, 'movb (%rdi,%rax), %al', changed_reason),
                    (call, re.sub(r'0x[0-9a-f]+', '0x0', lines[call], count=1), 'call destination mismatch'),
                    (call, re.sub(r'<[^>]+>', '<unreviewed>', lines[call]), 'call destination mismatch'),
                    (clears[0], 'nop', changed_reason), (size, 'movl $0, %esi', changed_reason)]
    if role.startswith('new'):
        width = int(role[-3:]) // 8
        replacements += [
            (lines.index(f'movl ${width}, %edx'), 'movl $0, %edx', changed_reason),
            (lines.index('movq %r14, %rsi'), 'movq %rbx, %rsi', changed_reason),
            (lines.index(f'movq ${width}, 16(%r15)'), 'movq $0, 16(%r15)', changed_reason),
            (lines.index('movq $0, (%r15)'), 'movq $1, (%r15)', changed_reason),
        ]
    else:
        branch = next(i for i, line in enumerate(lines) if re.match(r'j\w+ ', line))
        replacements += [(branch, re.sub(r'0x[0-9a-f]+', '0x0', lines[branch], count=1), 'branch destination mismatch'),
                         (clears[-1], 'nop', changed_reason)]
        if role.startswith('cached_new'):
            copy_size = next(i for i, line in enumerate(lines) if re.fullmatch(r'movl \$\d+, %edx', line))
            replacements += [(copy_size, 'movl $0, %edx', changed_reason),
                             (lines.index('movq $1, (%r14)'), 'movq $0, (%r14)', changed_reason)]
        else:
            transform = next(i for i, line in enumerate(lines) if line.endswith('<' + targets['transform' + role[-3:]][0] + '>'))
            guard = transform + 3
            require(lines[guard].startswith('jne '), 'missing public success guard')
            replacements += [(lines.index('movaps (%rsp), %xmm0'), 'movups (%r12), %xmm0', changed_reason),
                             (guard, lines[guard].replace('jne ', 'je ', 1), 'branch destination mismatch')]
    cases = []
    for index, replacement, reason in replacements:
        changed = list(lines)
        changed[index] = replacement
        cases.append((changed, raw, image, reason))
    changed_raw, changed_image = bytearray(raw), bytearray(image)
    offset = image_review.file_offset(image_review.segments(image), start, len(raw), 5)
    changed_raw[0] ^= 1
    changed_image[offset] ^= 1
    cases.append((lines, bytes(changed_raw), bytes(changed_image), changed_reason))
    for text, code, executable, reason in cases:
        try:
            check(text, code, sizes, symbol, start, executable, targets, role, compiler, panic)
        except ValueError as error:
            require(reason in str(error), 'public mutation rejected for unrelated reason: ' + str(error))
        else:
            raise ValueError('AES linked public mutation accepted')
    return len(cases)
