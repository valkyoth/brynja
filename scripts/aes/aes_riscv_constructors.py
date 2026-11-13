"""Reviewed RV64 key constructors, including scratch cleanup and expansion edges.

The checked-in policy records already-reviewed bodies, never auto-learns output.
Every external transfer is re-encoded against separately validated ELF targets.
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


sessions = module('constructor_sessions', 'aes_riscv_sessions.py')
cleanup = module('constructor_cleanup', 'aes_riscv_cleanup.py')
machine, require = sessions.machine, sessions.require
POLICY = json.loads(Path(__file__).with_name('riscv-constructors-review.json').read_text())


def policy(compiler, panic, kind, bits):
    require(compiler in ('1.90.0', '1.99.1') and panic in ('abort', 'unwind')
            and kind in ('key', 'cached') and bits in (128, 192, 256), 'unreviewed constructor profile')
    # Only MSRV cached constructors retain distinct unwind landing pads.
    profile = 'unwind' if (compiler, panic, kind) == ('1.90.0', 'unwind', 'cached') else 'base'
    result = POLICY['bodies']['/'.join((compiler, profile, kind, str(bits)))]
    raw = bytes.fromhex(result['bytes'])
    require(0 < len(raw) <= 394, 'invalid constructor template extent')
    offsets = [c['offset'] for c in result['calls']]
    require(offsets == sorted(set(offsets)) and all(o % 2 == 0 and 0 <= o <= len(raw) - 8 for o in offsets)
            and all(a + 8 <= b for a, b in zip(offsets, offsets[1:])), 'invalid constructor call offsets')
    expected = Counter({'clear': 2, 'memcpy': 1}) if kind == 'key' else Counter(
        {'clear': 8 if profile == 'unwind' else 4, 'memset': 1, 'expand': 1, 'memcpy': 1})
    if profile == 'unwind':
        expected['resume'] = 2
    require(Counter(c['role'] for c in result['calls']) == expected, 'wrong constructor call population')
    for c in result['calls']:
        tail = kind == 'key' and c['offset'] == len(raw) - 8
        require(c['tail'] == tail and (not tail or c['role'] == 'clear')
                and raw[c['offset']:c['offset'] + 8] == bytes(8), 'invalid constructor call placeholder')
    return result


def select(nm):
    role = r'30brynja_aes_accelerated_fixture9lifecycle6aes(128|192|256)(7new_key|10new_cached)'
    pattern = r'(?:_ZN' + role + r'17h[0-9a-f]{16}E|_RNvNtNtC\w+_' + role + r')'
    rows = {}
    for line in nm.splitlines():
        if not ('lifecycle' in line and any(k in line for k in ('new_key', 'new_cached'))):
            continue
        row = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(row is not None, 'malformed constructor symbol row')
        match = re.fullmatch(pattern, row[3])
        require(match is not None, 'unexpected constructor symbol')
        bits, kind = (match[1], match[2]) if match[1] else (match[3], match[4])
        role = 'key' if kind == '7new_key' else 'cached', int(bits)
        require(role not in rows, 'duplicate constructor role')
        address, size = int(row[1], 16), int(row[2], 16)
        require(address > 0 and address % 2 == 0 and 0 < size <= 394, 'invalid constructor extent')
        rows[role] = row[3], address, size
    require(set(rows) == {(k, b) for k in ('key', 'cached') for b in (128, 192, 256)},
            'incomplete constructor population')
    return rows


def template(compiler, panic, kind, bits, address, targets):
    p = policy(compiler, panic, kind, bits)
    require(set(targets) == {c['role'] for c in p['calls']}, 'wrong constructor target population')
    raw = bytearray.fromhex(p['bytes'])
    for c in p['calls']:
        offset = c['offset']
        encoder = cleanup.tail if c['tail'] else sessions.call
        raw[offset:offset + 8] = encoder(address + offset, targets[c['role']])
    return bytes(raw)


def check_body(image, address, size, compiler, panic, kind, bits, targets):
    pos = machine.mapped(image, address, size)
    raw = image[pos:pos + size]
    require(raw == template(compiler, panic, kind, bits, address, targets), 'constructor template mismatch')
    return hashlib.sha256(raw).hexdigest()


def inspect(nm, image, compiler, panic):
    kernels = machine.inspect(nm, image)['kernels']
    symbols = {name: (address, size) for name, address, size, _, _ in machine.select(nm)}
    expansions = {r['bits']: symbols[r['symbol']][0] for r in kernels if r['kind'] == 'expand'}
    cleanup.inspect(nm, image, compiler, panic)
    clearing = cleanup.select(nm)
    rows, imports, reports = select(nm), {}, []
    for (kind, bits), (symbol, address, size) in sorted(rows.items()):
        p = policy(compiler, panic, kind, bits)
        require(size == len(bytes.fromhex(p['bytes'])), 'wrong constructor body size')
        pos = machine.mapped(image, address, size)
        targets = {'clear': clearing['clear'][0]}
        if kind == 'cached':
            targets['expand'] = expansions[bits]
        for c in p['calls']:
            role, offset = c['role'], c['offset']
            if role not in ('memcpy', 'memset', 'resume'):
                continue
            target = sessions.call_target(image[pos + offset:pos + offset + 8], address + offset)
            name = '_Unwind_Resume' if role == 'resume' else role
            if role not in imports:
                imports[role] = sessions.runtime_import(image, target, name)
            require(target == imports[role]['address'], 'inconsistent constructor import entry')
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
            'overlapping constructor/kernel/cleanup/import bodies')
    return {'constructors': reports, 'imports': imports,
            'scope': 'six key-owner constructors, width-specific expansion and clearing calls; '
                     'not authority startup, higher-level block staging, exception dispatch, '
                     'libc implementation, spill erasure, timing or native admission'}
