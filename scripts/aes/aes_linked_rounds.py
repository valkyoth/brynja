"""Pinned linked expansion/round bodies; no automatic review-policy refresh."""
import importlib.util
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('aes_round_image', Path(__file__).with_name('aes_linked_mix.py'))
image_review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image_review)
require = image_review.require
ROLES = tuple(f'{kind}{bits}' for kind in ('expand', 'transform') for bits in (128, 192, 256))


def policy(instructions, size, constants, calls, text, encoding):
    return dict(instructions=instructions, symbol_bytes=size, constant_loads=constants,
                calls=calls, text_sha256=text, encoding_sha256=encoding)


# Reviewed public loop/phase counters, exact calls, scratch cleanup and masks:
# docs/assurance/aes-linked-review.md. Relocations alone are normalized.
POLICY = {
    '1.90.0': {
        'expand128': policy(130, 451, 0, 5,
            'e4be12023574fea63cfaf306a6c0b6aa56d272d84ea995732a091a4f07b4c93d',
            'c67527b7b9c09cf23be4788a85014c1d9e5e19b64b7b2dbfc9d32a65b0b9857d'),
        'expand192': policy(144, 514, 0, 5,
            '4f2d92dfc0b2c170792eede2677bdd787750cd502c13d1efc8105b676ea8b3b2',
            'eed5c5490a70a597573d2d0f0237c5427d5a3aca7b75d48be0e74ced3c7494dd'),
        'expand256': policy(201, 677, 0, 9,
            'd7fb60516903e10147a6a8dfbb65fc7f4c144d4476927a332169876e8d8cbc7a',
            'f8a0cdbded36e06a561a8f3a3306f53dca0f3748a384be85eb785ff431df02a9'),
        'transform128': policy(204, 854, 4, 12,
            '16e18535d1cbedc3ed3cbeeecabbeed90b947dd39818cb613c01ad7236996d2e',
            'ea9c19d0988ef0afa8e2add690c0d40505bb7f38a5c27eb2f828d88a3afd28c1'),
        'transform192': policy(206, 875, 4, 12,
            '04073e89171bb5ecb96d4f0bae9280f7776a9837cd71a08762c01efb90c81570',
            '5d040d1f66a4ff695c2b6c036bc44b7e655bb9973dba0aacc1285fb156142d71'),
        'transform256': policy(206, 875, 4, 12,
            'c8b74f385740601ca206d4bf6a26d9c0d89cbf0a151bfb7e296da790b83be1bd',
            'a79c6fd719e538e8fca9d9bf97c3bcfdff84fdd87e79d3da1be7ed219a29c3be'),
    },
    '1.99.1': {
        'expand128': policy(129, 451, 0, 5,
            '553aad3677b82c07b1a7ece151e643afdcf03ddeee7e47acd46b91040245c1b0',
            'c3b9e7447c6439e38bca5559fd88993fdffe8e3314d0318691d7775d3a27bb89'),
        'expand192': policy(145, 522, 0, 5,
            '8989a8b2d578c8afa1c8e7ca5f45429b5165aa1876b7acef5ba66b9152ee943b',
            'f41d05ccf22f16dbf22ff519650159db0a91328900ed8f23fc8bfc152c2fff36'),
        'expand256': policy(220, 807, 0, 9,
            'ec5ad540222259ac97cce984e098131d7bd0b3a8895b06012b86c3b41ba0d293',
            'eddf462b3baed44f079d666f74685082ccd1f9d0e28ec3dc6872db0e1ebee079'),
        'transform128': policy(199, 840, 4, 12,
            '1cbcd355971a14372a07326404fe862811a45f19f4b56a339d2cc07c1c14eabf',
            'de3e9f68831882ad648349378a5703f831504367e22ab366b58d035b0a3c1dab'),
        'transform192': policy(201, 861, 4, 12,
            '2074ece66f7107078a8a6ab7a701f1980d56532256d19762a2e759313bdfa983',
            '422f722cb79e9480ca8b055cdee4c69e929d86a452cb3277247fbdc707f1fecd'),
        'transform256': policy(201, 861, 4, 12,
            '1fb4d0d0b470a5fc715455d758d0a48b743e81244ee73fdc84a79272086301a5',
            '4fd5ad113af93075f6d318c999482b91683bbb541533c9bf6a034a3f15cbaf60'),
    },
}


def role_for(lines, symbol):
    if '6expand' in symbol:
        match = re.fullmatch(r'cmpq \$(16|24|32), %rsi', lines[0]) if lines else None
        require(match is not None, 'missing expansion width admission')
        bits, kind = int(match[1]) * 8, 'expand'
    else:
        require('9transform' in symbol, 'unrecognized round helper')
        offsets = [int(m[1]) for line in lines
                   if (m := re.fullmatch(r'movdqu (160|192|224)\(%r14\), %xmm0', line))]
        require(len(offsets) == 2 and len(set(offsets)) == 1, 'ambiguous transform width')
        bits, kind = {160: 128, 192: 192, 224: 256}[offsets[0]], 'transform'
    require(('4wide' in symbol) == (bits != 128), 'round helper width/symbol mismatch')
    if symbol.startswith('_RI'):
        require(('Kj18_Kjd0_Kjc_' if bits == 192 else 'Kj20_Kjf0_Kje_') in symbol,
                'round helper generic width mismatch')
    return f'{kind}{bits}'


def population(roles):
    require(len(roles) == len(ROLES) and set(roles) == set(ROLES),
            'missing/duplicate reviewed round helper')


def check(lines, raw, sizes, symbol, start, image, targets, role, compiler):
    require(compiler in POLICY and role in POLICY[compiler], 'unreviewed round compiler/role')
    require(role_for(lines, symbol) == role, 'round role mismatch')
    expected = {'inverse', 'zeroize'} if role.startswith('expand') else {
        'substitute', 'mix', 'zeroize', 'add_key' if role == 'transform128' else 'wide_add_key'}
    require(set(targets) == expected, 'round call target population changed')
    actual, _ = image_review.observe(lines, raw, sizes, symbol, start, image, targets)
    require(actual == POLICY[compiler][role], 'reviewed round body changed; explicit re-review required')
    return {'role': role, **actual}


def mutations(lines, raw, sizes, symbol, start, image, targets, role, compiler):
    check(lines, raw, sizes, symbol, start, image, targets, role, compiler)
    branch = next(i for i, line in enumerate(lines) if line.startswith(('je ', 'jne ', 'ja ', 'jmp ')))
    call = next(i for i, line in enumerate(lines) if line.startswith('callq '))
    clearing = next(i for i, line in enumerate(lines) if line.endswith('<' + targets['zeroize'][0] + '>'))
    cleanup_size = next(i for i in range(clearing - 1, -1, -1)
                        if lines[i] == ('movl $4, %esi' if role.startswith('expand') else 'movl $16, %esi'))
    loop = next(i for i, line in enumerate(lines) if line.startswith('cmpq $') and '%rsi' not in line)
    cases = []
    for index, replacement, reason in (
        (1, 'movb (%rdi,%rax), %al', 'reviewed round body changed'),
        (branch, re.sub(r'0x[0-9a-f]+', '0x0', lines[branch], count=1), 'branch destination mismatch'),
        (call, re.sub(r'0x[0-9a-f]+', '0x0', lines[call], count=1), 'call destination mismatch'),
        (call, re.sub(r'<[^>]+>', '<unreviewed>', lines[call]), 'call destination mismatch'),
        (loop, re.sub(r'\$\d+', '$0', lines[loop]), 'reviewed round body changed'),
        (cleanup_size, 'movl $0, %esi', 'reviewed round body changed'),
        (clearing, 'nop', 'reviewed round body changed'),
    ):
        changed = list(lines)
        changed[index] = replacement
        cases.append((changed, raw, image, reason))
    changed_raw, changed_image = bytearray(raw), bytearray(image)
    offset = image_review.file_offset(image_review.segments(image), start, len(raw), 5)
    changed_raw[0] ^= 1
    changed_image[offset] ^= 1
    cases.append((lines, bytes(changed_raw), bytes(changed_image), 'reviewed round body changed'))
    for text, code, executable, reason in cases:
        try:
            check(text, code, sizes, symbol, start, executable, targets, role, compiler)
        except ValueError as error:
            require(reason in str(error), 'round mutation rejected for unrelated reason: ' + str(error))
        else:
            raise ValueError('linked round mutation accepted')
    return len(cases)
