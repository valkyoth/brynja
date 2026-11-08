"""Exact surviving secret-output wrapper review; not inlined/unwind qualification."""
import importlib.util
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('aes_wrapper_image', Path(__file__).with_name('aes_linked_mix.py'))
image_review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image_review)
require = image_review.require
EDGES = {
    'key128': ('zeroize', 'expand128', 'transform128', 'copy'),
    'cached128': ('zeroize', 'transform128', 'copy'),
    'key192': ('zeroize', 'expand192', 'secret192'),
    'key256': ('zeroize', 'expand256', 'secret256'),
    'secret192': ('zeroize', 'transform192', 'copy'),
    'secret256': ('zeroize', 'transform256', 'copy'),
    'copy': (),
}


def candidates(table):
    """Resolve exact owner names; leave opaque wide-secret widths for call binding."""
    selected, secrets = {}, []
    owner = r'(17Aes128ExpandedKey|9Aes128Key|9Aes192Key|9Aes256Key)9transform'
    legacy = r'_ZN13brynja_crypto3aes(?:4wide)?' + owner + r'17h[0-9a-f]{16}E'
    current = r'_RNvM(?:s[0-9a-z]+_)?Nt(?:Nt)?C\w+_13brynja_crypto3aes(?:4wide)?NtB[0-9a-z]+_' + owner
    secret = (r'(?:_ZN13brynja_crypto3aes4wide6secret17h[0-9a-f]{16}E|'
              r'_RINvNtNtC\w+_13brynja_crypto3aes4wide6secret(?:Kj18_Kjd0_Kjc_|Kj20_Kjf0_Kje_)EB6_)')
    copy = (r'(?:_ZN11brynja_core22secret_memory_transfer10copy_bytes17h[0-9a-f]{16}E|'
            r'_RNvNtC\w+_11brynja_core22secret_memory_transfer10copy_bytes)')
    for line in table.splitlines():
        relevant = ('13brynja_crypto3aes' in line and '8portable' not in line
                    and ('9transform' in line or '6secret' in line)) or '22secret_memory_transfer10copy_bytes' in line
        if not relevant:
            continue
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(match is not None, 'unrecognized wrapper symbol row')
        address, size, name = match.groups()
        row = (name, int(address, 16), int(size, 16))
        require(row[2] > 0, 'empty wrapper symbol')
        match = re.fullmatch(legacy, name) or re.fullmatch(current, name)
        if match:
            role = {'17Aes128ExpandedKey': 'cached128', '9Aes128Key': 'key128',
                    '9Aes192Key': 'key192', '9Aes256Key': 'key256'}[match[1]]
            require(('4wide' in name) == (role in ('key192', 'key256')), 'wrapper owner namespace mismatch')
        elif re.fullmatch(copy, name):
            role = 'copy'
        else:
            require(re.fullmatch(secret, name) is not None, 'unrecognized wrapper symbol')
            secrets.append(row)
            continue
        require(role not in selected, 'duplicate wrapper role')
        selected[role] = row
    require(set(selected) == {'key128', 'key192', 'key256', 'cached128', 'copy'}
            and len(secrets) == 2 and secrets[0][0] != secrets[1][0], 'wrapper population changed')
    ordered = sorted([*selected.values(), *secrets], key=lambda row: row[1])
    require(all(a[1] + a[2] <= b[1] for a, b in zip(ordered, ordered[1:])), 'overlapping wrapper symbols')
    return selected, secrets


def secret_role(lines, symbol, transforms):
    matches = [bits for bits in (192, 256) if sum(
        line == f'callq 0x{transforms[f"transform{bits}"][1]:x} <{transforms[f"transform{bits}"][0]}>'
        for line in lines) == 1]
    require(len(matches) == 1, 'ambiguous wide secret transform binding')
    bits = matches[0]
    if symbol.startswith('_RI'):
        require(('Kj18_Kjd0_Kjc_' if bits == 192 else 'Kj20_Kjf0_Kje_') in symbol,
                'wide secret generic width mismatch')
    return f'secret{bits}'


def policy(count, size, calls, text, encoding):
    return dict(instructions=count, symbol_bytes=size, calls=calls, constant_loads=0,
                text_sha256=text, encoding_sha256=encoding)


# Complete streams and compiler/profile differences inspected explicitly; see
# docs/assurance/aes-linked-review.md. There is no policy generation/refresh path.
COMMON = {
    'key128': policy(79, 318, 8,
        '45bac2a71ef8ef84671f3baa6c959b7bb05a0bc5725a4c051b67a5a3648bd5b8',
        '2bcb7d3492c1463e9942ea8b0be861b63adac9ecc6d3619fdc1ed5d478d28514'),
    'copy': policy(22, 63, 0,
        '79f00be6753030f6f7a12887cd6afb0afc8f4f9665b0510257c86c9b84fe41ed',
        '8130908772eb1534686a9a1dfeb7e1863bdc13141c8024582a58dfee7b0c15d1'),
}
PROFILE = {
    'abort': {
        'cached128': policy(59, 200, 5,
            '736346b5e1db4c9494c9f91ef9f92457b9518a6aeb0af9e517a111f4bb5990c7',
            '2048ac04fdd111524ad9f4685c315a57b7332fdb246c69476658f64d1e9dfc53'),
        'key192': policy(66, 281, 5,
            '98a993e90f06e8a3c4164f71a5c54ad75c7afff2df560f4f6e46ae8ac060dd40',
            '8463c75bfe957a808b57b6ad675732d583c9cc1f9bd155db4a88bc67d50ca6ac'),
        'key256': policy(68, 297, 5,
            '5c76b1f8e00adbbd094aaad0ca9f6969446d1c838eff139e2400d667aa7e70e4',
            'aaaf38d16c6cb141dcde2ac690e83afec04b09eeab29e40779b9a57a3b723b82'),
    },
    'unwind': {
        'cached128': policy(58, 197, 5,
            '36440a27fab5b1bbefa1b80a04db4b8a085c17707c939e125b6ba81418acfec5',
            '7d8dc9cafcebc286a831fae84b417bb61ea85596bd9c981b0bffa59781cadc75'),
        'key192': policy(66, 281, 5,
            'fe440f02bd56bd204dd42ce69e7d15e16a31c7d37f567e53487a8e1c227a92fc',
            '9f54efa3a825eea85c24f4ed5b31c2ad744fea98c153dd4774cfa36e9af4123c'),
        'key256': policy(68, 297, 5,
            '5acb0aec60bc5fb6250cb0a955c69fddd23e98d55402a93ffecd9f7960488dd9',
            '067cefa2b289f5c102623b71cd3af15bfce8417111f84bb91b4abc64aea71189'),
    },
}
WIDE = {
    '1.90.0': {
        'secret192': policy(64, 218, 6,
            '46c4d41b456333818a91de6033048731c1ea7dc1eb9b54ec71cd06630aed2aa0',
            '04d542669ae77743303ba422ec7d11c2a3bf93a2d2e2d20bf006d1d2aedf2d60'),
        'secret256': policy(64, 218, 6,
            'b0296f5a7bc22466238f3e9608c824ef082e6bd80b1f007a3a676d177e846978',
            '04d542669ae77743303ba422ec7d11c2a3bf93a2d2e2d20bf006d1d2aedf2d60'),
    },
    '1.99.1': {
        'secret192': policy(63, 211, 6,
            'f6b2bf2fdd0fe0385c209a28b4c30044f025ac363aa8ad67a5e0d187444ee65e',
            'b6d3136e4d65fdcacfd8af26eeeb6b5af09f38aa662eb96dbba93fd364e60cf7'),
        'secret256': policy(63, 211, 6,
            'e56d4f7ed5481bb1f10852909f5617efcb82b31cfb5959528eedfe68746ad4ef',
            'b6d3136e4d65fdcacfd8af26eeeb6b5af09f38aa662eb96dbba93fd364e60cf7'),
    },
}
POLICY = {(compiler, panic): {**COMMON, **PROFILE[panic], **WIDE[compiler]}
          for compiler in WIDE for panic in PROFILE}


def check(lines, raw, sizes, symbol, start, image, targets, role, compiler, panic):
    require((compiler, panic) in POLICY and role in EDGES, 'unreviewed wrapper configuration')
    require(set(targets) == set(EDGES[role]), 'wrapper call target population changed')
    actual, _ = image_review.observe(lines, raw, sizes, symbol, start, image, targets)
    require(actual == POLICY[compiler, panic][role], 'reviewed wrapper changed; explicit re-review required')
    return {'role': role, **actual}


def mutations(lines, raw, sizes, symbol, start, image, targets, role, compiler, panic):
    check(lines, raw, sizes, symbol, start, image, targets, role, compiler, panic)
    changed_reason = 'reviewed wrapper changed'
    branch = next(i for i, line in enumerate(lines) if re.match(r'j\w+ ', line))
    replacements = [(0, 'movb (%rdi,%rax), %al', changed_reason),
                    (branch, re.sub(r'0x[0-9a-f]+', '0x0', lines[branch], count=1), 'branch destination mismatch')]
    if role == 'copy':
        for original, replacement in (
            ('cmpq $8, %rdx', 'cmpq $16, %rdx'),
            ('movq %rax, (%rdi,%rcx)', 'movb %al, (%rdi,%rcx)'),
            ('incq %rcx', 'addq $2, %rcx'),
            ('xorl %eax, %eax', 'nop'),
            ('movq (%rsi,%rcx), %rax', 'movq (%rdi,%rcx), %rax'),
        ):
            replacements.append((lines.index(original), replacement, changed_reason))
    else:
        call = next(i for i, line in enumerate(lines) if line.startswith('callq '))
        clear = next(i for i, line in enumerate(lines) if line.endswith('<' + targets['zeroize'][0] + '>'))
        size = next(i for i in range(clear - 1, -1, -1) if re.fullmatch(r'movl \$\d+, %esi', lines[i]))
        status = next(i for i, line in enumerate(lines) if line.startswith('movq $1, ('))
        replacements += [
            (call, re.sub(r'0x[0-9a-f]+', '0x0', lines[call], count=1), 'call destination mismatch'),
            (call, re.sub(r'<[^>]+>', '<unreviewed>', lines[call]), 'call destination mismatch'),
            (clear, 'nop', changed_reason), (size, 'movl $0, %esi', changed_reason),
            (status, lines[status].replace('$1,', '$0,'), changed_reason),
        ]
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
            require(reason in str(error), 'wrapper mutation rejected for unrelated reason: ' + str(error))
        else:
            raise ValueError('linked wrapper mutation accepted')
    return len(cases)
