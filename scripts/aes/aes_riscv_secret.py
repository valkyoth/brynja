"""Reviewed RV64 secret-output callers, including destination and scratch cleanup.

These are exact bounded policies for retained bodies, not arbitrary caller,
unwind-dispatch, spill-erasure, fault-resistance or native timing qualification.
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


sessions = module('secret_sessions', 'aes_riscv_sessions.py')
cleanup = module('secret_cleanup', 'aes_riscv_cleanup.py')
machine, require = sessions.machine, sessions.require
POLICY = json.loads(Path(__file__).with_name('riscv-secret-review.json').read_text())


def policy(compiler, panic, kind, bits):
    require(compiler in ('1.90.0', '1.99.1') and panic in ('abort', 'unwind')
            and kind in ('ephemeral', 'cached') and bits in (128, 192, 256), 'unreviewed secret profile')
    result = POLICY['bodies']['/'.join((compiler, panic, kind, str(bits)))]
    raw = bytes.fromhex(result['bytes'])
    require(0 < len(raw) <= 728, 'invalid secret template extent')
    offsets = [c['offset'] for c in result['calls']]
    require(offsets == sorted(set(offsets)) and all(o % 2 == 0 and 0 <= o <= len(raw) - 8 for o in offsets)
            and all(a + 8 <= b for a, b in zip(offsets, offsets[1:])), 'invalid secret call offsets')
    landing = (compiler, panic) == ('1.90.0', 'unwind')
    if kind == 'cached':
        expected = Counter({'clear': 7 if landing else 5, 'transform': 2, 'memcpy': 1})
    else:
        clears = 13 if landing else (7 if panic == 'unwind' else 8)
        expected = Counter({'clear': clears, 'expand': 1, 'encrypt': 1, 'decrypt': 1, 'memcpy': 1, 'memset': 1})
    if landing:
        expected['_Unwind_Resume'] = 1 if kind == 'cached' else 2
    require(Counter(c['role'] for c in result['calls']) == expected, 'wrong secret call population')
    tail_offset = (320 if compiler == '1.90.0' else 368) if kind == 'cached' and not landing else None
    for c in result['calls']:
        tail = c['offset'] == tail_offset
        require(c['tail'] is tail and (not tail or c['role'] == 'clear')
                and raw[c['offset']:c['offset'] + 8] == bytes(8), 'invalid secret call placeholder')
    require(tail_offset is None or tail_offset in offsets, 'missing secret tail transfer')
    return result


def select(nm):
    owner = r'(9Aes(?:128|192|256)Key|17Aes(?:128|192|256)ExpandedKey)6secret'
    legacy = r'_ZN13brynja_crypto3aes9execution' + owner + r'17h[0-9a-f]{16}E'
    current = r'_RNvM\w+_NtNtC\w+_13brynja_crypto3aes9executionNtB\w+_' + owner
    rows = {}
    for line in nm.splitlines():
        if not ('brynja_crypto3aes9execution' in line and '6secret' in line):
            continue
        row = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(row is not None, 'malformed secret symbol row')
        match = re.fullmatch(legacy, row[3]) or re.fullmatch(current, row[3])
        require(match is not None, 'unexpected secret symbol')
        kind = 'cached' if 'ExpandedKey' in match[1] else 'ephemeral'
        bits = int(re.search(r'Aes(128|192|256)', match[1])[1])
        role = kind, bits
        require(role not in rows, 'duplicate secret role')
        address, size = int(row[1], 16), int(row[2], 16)
        require(address > 0 and address % 2 == 0 and 0 < size <= 728, 'invalid secret extent')
        rows[role] = row[3], address, size
    require(set(rows) == {(k, b) for k in ('ephemeral', 'cached') for b in (128, 192, 256)},
            'incomplete secret population')
    return rows


def template(compiler, panic, kind, bits, address, targets):
    p = policy(compiler, panic, kind, bits)
    require(set(targets) == {c['role'] for c in p['calls']}, 'wrong secret target population')
    raw = bytearray.fromhex(p['bytes'])
    for c in p['calls']:
        offset = c['offset']
        encoder = cleanup.tail if c['tail'] else sessions.call
        raw[offset:offset + 8] = encoder(address + offset, targets[c['role']])
    return bytes(raw)


def check_body(image, address, size, compiler, panic, kind, bits, targets):
    pos = machine.mapped(image, address, size)
    raw = image[pos:pos + size]
    require(raw == template(compiler, panic, kind, bits, address, targets), 'secret template mismatch')
    return hashlib.sha256(raw).hexdigest()


def inspect(nm, image, compiler, panic):
    kernels = machine.inspect(nm, image)['kernels']
    symbols = {name: (address, size) for name, address, size, _, _ in machine.select(nm)}
    leaves = {(r['kind'], r['bits']): symbols[r['symbol']][0] for r in kernels}
    permit_report = sessions.inspect(nm, image, compiler, panic)
    permits = sessions.select(nm)
    cleanup.inspect(nm, image, compiler, panic)
    clearing = cleanup.select(nm)
    rows, imports, reports = select(nm), {}, []
    for (kind, bits), (symbol, address, size) in sorted(rows.items()):
        p = policy(compiler, panic, kind, bits)
        require(size == len(bytes.fromhex(p['bytes'])), 'wrong secret body size')
        pos = machine.mapped(image, address, size)
        targets = {'clear': clearing['clear'][0]}
        if kind == 'cached':
            targets['transform'] = leaves['transform', bits]
        else:
            targets.update(expand=leaves['expand', bits], encrypt=permits['encrypt', bits][1],
                           decrypt=permits['decrypt', bits][1])
        for c in p['calls']:
            role, offset = c['role'], c['offset']
            if role not in ('memcpy', 'memset', '_Unwind_Resume'):
                continue
            target = sessions.call_target(image[pos + offset:pos + offset + 8], address + offset)
            if role not in imports:
                imports[role] = sessions.runtime_import(image, target, role)
            require(target == imports[role]['address'], 'inconsistent secret import entry')
            targets[role] = target
        digest = check_body(image, address, size, compiler, panic, kind, bits, targets)
        reports.append({'kind': kind, 'bits': bits, 'symbol': symbol, 'address': address,
                        'size': size, 'targets': targets, 'body_sha256': digest})
    if permit_report['resume_import']:
        require(imports['_Unwind_Resume']['address'] == permit_report['resume_import']['address'],
                'inconsistent secret/session resume import')
    extents = [(a, a + size) for a, size in symbols.values()]
    extents += [(a, a + size) for _, a, size in (*rows.values(), *permits.values())]
    extents += [(a, a + size) for a, size, _ in clearing.values()]
    extents += [(r['address'], r['address'] + r['size']) for r in imports.values()]
    extents.sort()
    require(all(end <= start for (_, end), (start, _) in zip(extents, extents[1:])),
            'overlapping secret/session/kernel/cleanup/import bodies')
    return {'secret': reports, 'imports': imports,
            'scope': 'six secret-output bodies covering both directions: destination admission clearing, '
                     'authority checks, staging, matched kernels/sessions, result gating, scratch cleanup '
                     'and clearing-owner transfer; not arbitrary caller code, exception dispatch, libc '
                     'implementation, spill erasure, timing, physical faults or native admission'}
