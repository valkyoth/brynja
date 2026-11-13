"""Reviewed RV64 public-encryption callers; never learn templates from a build.

Full bodies bind staging, authority checks, publication and clearing. Calls bind
separately checked kernels/cleanup or live ELF import identities, not nm labels.
"""
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re

def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


sessions = module('public_sessions', 'aes_riscv_sessions.py')
cleanup = module('public_cleanup', 'aes_riscv_cleanup.py')
machine, require = sessions.machine, sessions.require
POLICY = json.loads(Path(__file__).with_name('riscv-public-review.json').read_text())


def policy(compiler, panic, kind, bits):
    require(compiler in ('1.90.0', '1.99.1') and panic in ('abort', 'unwind')
            and kind in ('ephemeral', 'cached') and bits in (128, 192, 256), 'unreviewed public profile')
    result = POLICY['bodies']['/'.join((compiler, panic, kind, str(bits)))]
    raw = bytes.fromhex(result['bytes'])
    require(0 < len(raw) <= 628, 'invalid public template extent')
    offsets = [c['offset'] for c in result['calls']]
    require(offsets == sorted(set(offsets)) and all(o % 2 == 0 and 0 <= o <= len(raw) - 8 for o in offsets)
            and all(a + 8 <= b for a, b in zip(offsets, offsets[1:])), 'invalid public call offsets')
    clear = 2 if kind == 'cached' else 4
    if (compiler, panic) == ('1.90.0', 'unwind'):
        clear *= 2
    elif (compiler, panic, kind) == ('1.99.1', 'abort', 'ephemeral'):
        clear = 5
    expected = Counter({'transform': 1, 'memcpy': 1, 'clear': clear})
    if kind == 'ephemeral':
        expected.update({'expand': 1, 'memset': 1})
    if (compiler, panic) == ('1.90.0', 'unwind'):
        expected['_Unwind_Resume'] = 2
    require(Counter(c['role'] for c in result['calls']) == expected, 'wrong public call population')
    require(all(raw[o:o + 8] == bytes(8) for o in offsets), 'invalid public call placeholder')
    return result


def select(nm):
    ephemeral = r'30brynja_aes_accelerated_fixture9public(128|192|256)'
    cached = r'13brynja_crypto3aes9execution17Aes(128|192|256)ExpandedKey20encrypt_block_public'
    patterns = (
        ('ephemeral', r'_ZN' + ephemeral + r'17h[0-9a-f]{16}E'),
        ('ephemeral', r'_RNvC\w+_' + ephemeral),
        ('cached', r'_ZN' + cached + r'17h[0-9a-f]{16}E'),
        ('cached', r'_RNvM\w+_NtNtC\w+_13brynja_crypto3aes9executionNtB\w+_17Aes(128|192|256)ExpandedKey20encrypt_block_public'),
    )
    rows = {}
    for line in nm.splitlines():
        if not (('brynja_aes_accelerated_fixture9public' in line)
                or ('brynja_crypto' in line and 'ExpandedKey20encrypt_block_public' in line)):
            continue
        row = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(row is not None, 'malformed public symbol row')
        matches = [(kind, re.fullmatch(pattern, row[3])) for kind, pattern in patterns]
        matches = [(kind, match) for kind, match in matches if match is not None]
        require(len(matches) == 1, 'unexpected public symbol')
        kind, match = matches[0]
        role = kind, int(match[1])
        require(role not in rows, 'duplicate public role')
        address, size = int(row[1], 16), int(row[2], 16)
        require(address > 0 and address % 2 == 0 and 0 < size <= 628, 'invalid public extent')
        rows[role] = row[3], address, size
    require(set(rows) == {(k, b) for k in ('ephemeral', 'cached') for b in (128, 192, 256)},
            'incomplete public population')
    return rows


def template(compiler, panic, kind, bits, address, targets):
    p = policy(compiler, panic, kind, bits)
    require(set(targets) == {c['role'] for c in p['calls']}, 'wrong public target population')
    raw = bytearray.fromhex(p['bytes'])
    for c in p['calls']:
        offset = c['offset']
        raw[offset:offset + 8] = sessions.call(address + offset, targets[c['role']])
    return bytes(raw)


def check_body(image, address, size, compiler, panic, kind, bits, targets):
    pos = machine.mapped(image, address, size)
    raw = image[pos:pos + size]
    require(raw == template(compiler, panic, kind, bits, address, targets), 'public template mismatch')
    return hashlib.sha256(raw).hexdigest()


def inspect(nm, image, compiler, panic):
    kernels = machine.inspect(nm, image)['kernels']
    symbols = {name: (address, size) for name, address, size, _, _ in machine.select(nm)}
    leaves = {(r['kind'], r['bits']): symbols[r['symbol']][0] for r in kernels}
    cleanup.inspect(nm, image, compiler, panic)
    clearing = cleanup.select(nm)
    rows, imports, reports = select(nm), {}, []
    for (kind, bits), (symbol, address, size) in sorted(rows.items()):
        p = policy(compiler, panic, kind, bits)
        require(size == len(bytes.fromhex(p['bytes'])), 'wrong public body size')
        pos = machine.mapped(image, address, size)
        targets = {'clear': clearing['clear'][0], 'transform': leaves['transform', bits]}
        if kind == 'ephemeral':
            targets['expand'] = leaves['expand', bits]
        for c in p['calls']:
            role, offset = c['role'], c['offset']
            if role not in ('memcpy', 'memset', '_Unwind_Resume'):
                continue
            target = sessions.call_target(image[pos + offset:pos + offset + 8], address + offset)
            if role not in imports:
                imports[role] = sessions.runtime_import(image, target, role)
            require(target == imports[role]['address'], 'inconsistent public import entry')
            targets[role] = target
        digest = check_body(image, address, size, compiler, panic, kind, bits, targets)
        reports.append({'kind': kind, 'bits': bits, 'symbol': symbol, 'address': address,
                        'size': size, 'targets': targets, 'body_sha256': digest})
    extents = [(a, a + size) for a, size in symbols.values()]
    extents += [(a, a + size) for _, a, size in rows.values()]
    extents += [(a, a + size) for a, size, _ in clearing.values()]
    extents += [(r['address'], r['address'] + r['size']) for r in imports.values()]
    extents.sort()
    require(all(end <= start for (_, end), (start, _) in zip(extents, extents[1:])),
            'overlapping public/kernel/cleanup/import bodies')
    return {'public': reports, 'imports': imports,
            'scope': 'six public-encryption boundaries: guarded staging, pre/post authority checks, '
                     'publication after success, scratch cleanup and unchanged output on rejection; '
                     'not secret-output callers, exception dispatch, libc implementation, spill erasure, '
                     'timing or native admission'}
