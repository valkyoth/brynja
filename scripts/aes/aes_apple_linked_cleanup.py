"""Exact Apple volatile-clear and retained destruction-body review.

Only an external tail-branch displacement varies, and it must resolve to the
independently reviewed zeroizer in the same Mach-O executable. This does not
qualify operation/constructor callers or the platform unwind dispatcher.
"""
import hashlib
import importlib.util
from pathlib import Path
import re

SPEC = importlib.util.spec_from_file_location('apple_cleanup_mapping',
    Path(__file__).with_name('aes_apple_linked_kernels.py'))
kernels = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kernels)
require = kernels.require
ROLES = ('zeroize', 'destroy_key', 'destroy_block')


def configuration(compiler, panic, admission):
    require(compiler in ('1.90.0', '1.99.1') and panic in ('abort', 'unwind')
            and admission in ('static', 'hosted'), 'unsupported Apple cleanup configuration')


def relevant(symbol):
    return b'zeroize_region_volatile' in symbol or (
        b'30brynja_aes_accelerated_fixture9lifecycle' in symbol and b'destroy' in symbol)


def select(image):
    code, starts, symbols = kernels.parse(image, symbol_filter=relevant)
    ends = dict(zip(starts, starts[1:]))
    patterns = {
        'zeroize': r'__(?:ZN11brynja_core22secret_memory_volatile23zeroize_region_volatile17h[0-9a-f]{16}E|'
                   r'RNvNtC\w+_11brynja_core22secret_memory_volatile23zeroize_region_volatile)',
        'destroy_key': r'__(?:ZN30brynja_aes_accelerated_fixture9lifecycle6aes12811destroy_key17h[0-9a-f]{16}E|'
                       r'RNvNtNtC\w+_30brynja_aes_accelerated_fixture9lifecycle6aes12811destroy_key)',
        'destroy_block': r'__(?:ZN30brynja_aes_accelerated_fixture9lifecycle13destroy_block17h[0-9a-f]{16}E|'
                         r'RNvNtC\w+_30brynja_aes_accelerated_fixture9lifecycle13destroy_block)',
    }
    selected = {}
    for symbol, start in symbols:
        roles = [role for role, pattern in patterns.items() if re.fullmatch(pattern, symbol)]
        require(len(roles) == 1 and roles[0] not in selected, 'unknown/duplicate Apple cleanup symbol')
        require(start in ends, 'cleanup body lacks complete function boundaries')
        selected[roles[0]] = (symbol, start, ends[start] - start,
                              code['offset'] + start - code['address'])
    require(set(selected) == set(ROLES) and len({r[1] for r in selected.values()}) == 3,
            'Apple cleanup population/alias mismatch')
    return selected


def template(role, compiler, panic, start, clear=None):
    require(role in ROLES and compiler in ('1.90.0', '1.99.1') and panic in ('abort', 'unwind'),
            'unsupported Apple cleanup template')
    if role == 'zeroize':
        # Apple schedules the volatile store before decrement, unlike the
        # reviewed Linux sequence. All local branch words remain exact.
        words = ([0xb4000081, 0x3800141f, 0xf1000421, 0x54ffffc1, 0xd65f03c0]
                 if compiler == '1.90.0' else
                 [0xb40000a1, 0x3900001f, 0x91000400, 0xf1000421, 0x54ffffa1, 0xd65f03c0])
    elif (compiler, panic) == ('1.99.1', 'unwind'):
        words = [0x36000062, 0xb4000080, None, 0xb4000040, None, 0xd65f03c0]
    else:
        words = [0xb4000040, None, 0xd65f03c0]
    raw = bytearray()
    for word in words:
        if word is None:
            require(type(clear) is int and type(start) is int, 'missing clear target')
            delta = clear - (start + len(raw))
            require(delta % 4 == 0 and -(2**27) <= delta < 2**27, 'clear target outside B range')
            word = 0x14000000 | ((delta // 4) & 0x03ffffff)
        raw.extend(word.to_bytes(4, 'little'))
    return bytes(raw)


def check_body(image, row, role, compiler, panic, clear):
    _, start, size, pos = row
    raw = image[pos:pos + size]
    require(len(raw) == size and raw == template(role, compiler, panic, start, clear),
            'Apple cleanup encoding/extent changed; explicit review required')
    return {'role': role, 'symbol': row[0], 'address': hex(start), 'file_offset': pos,
            'size': size, 'instructions': size // 4, 'sha256': hashlib.sha256(raw).hexdigest()}


def inspect(image, compiler, panic, admission):
    configuration(compiler, panic, admission)
    dependency = kernels.inspect(image)
    selected = select(image)
    # Check the zeroizer before callers; a branch to a name alone proves nothing.
    reports = [check_body(image, selected[role], role, compiler, panic, selected['zeroize'][1])
               for role in ROLES]
    return {'binary_sha256': dependency['binary_sha256'], 'compiler': compiler, 'panic': panic,
            'admission': admission, 'cleanup_bodies': reports, 'kernel_review': dependency,
            'scope': 'Three complete Apple clear/destruction bodies and exact tail-call target, plus six AES bodies; '
                     'not constructor/operation callers, every call site, exception dispatch or spill erasure.'}
