"""Exact reviewed RV64 startup bodies with independently bound calls/constants.

Public KAT data only. No policy learning, libc implementation review, general
caller coverage, timing proof or physical-fault qualification.
"""
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('startup_sessions', HERE / 'aes_riscv_sessions.py')
sessions = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sessions)
machine, require = sessions.machine, sessions.require
POLICY = json.loads((HERE / 'riscv-startup-review.json').read_text())['bodies']
VECTORS = {k: bytes.fromhex(v) for k, v in json.loads((HERE / 'startup-arm-reference.json').read_text()).items()}
REFERENCE = {**{k: v for k, v in VECTORS.items() if k.startswith('schedule')},
             **{f'{k}:{i}': v[i:i+8] for k, v in VECTORS.items()
                if not k.startswith('schedule') for i in (0, 8)}}


def policy(compiler, panic):
    require(compiler in ('1.90.0', '1.99.1') and panic in ('abort', 'unwind'), 'unreviewed startup profile')
    p = POLICY[compiler]
    raw = bytes.fromhex(p['bytes'])
    require(len(raw) == (980 if compiler == '1.90.0' else 946), 'wrong startup template size')
    expected = Counter({'memset': 3, 'bcmp': 3})
    expected.update({f'{kind}{bits}': 1 if kind == 'expand' else 2
                     for kind in ('expand', 'transform') for bits in (128, 192, 256)})
    require(Counter(c['role'] for c in p['calls']) == expected, 'wrong startup call population')
    require(Counter(r['role'] for r in p['references']) == Counter(REFERENCE.keys()),
            'wrong startup reference population')
    extents = []
    for c in p['calls']:
        offset = c['offset']
        require(raw[offset:offset+8] == bytes(8), 'invalid startup call placeholder')
        extents.append((offset, offset+8))
    for r in p['references']:
        high, low = r['high'], r['low']
        require(high < low < high + 24, 'invalid startup reference pair')
        a = int.from_bytes(raw[high:high+4], 'little')
        b = int.from_bytes(raw[low:low+4], 'little')
        reg = (a >> 7) & 31
        require(a & 127 == 0x17 and a < 4096 and reg not in (0, 1)
                and b < 2**20 and (b >> 15) & 31 == reg
                and b & 0x707f == (0x13 if r['role'].startswith('schedule') else 0x3003),
                'invalid startup reference encoding')
        extents += [(high, high+4), (low, low+4)]
    extents.sort()
    require(all(0 <= a < b <= len(raw) and a % 2 == 0 for a, b in extents)
            and all(b <= c for (_, b), (c, _) in zip(extents, extents[1:])),
            'overlapping startup placeholders')
    return p


def select(nm):
    pattern = r'(?:_ZN30brynja_aes_accelerated_fixture7startup17h[0-9a-f]{16}E|_RNvC\w+_30brynja_aes_accelerated_fixture7startup)'
    rows = []
    for line in nm.splitlines():
        if 'fixture7startup' not in line:
            continue
        row = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(row is not None and re.fullmatch(pattern, row[3]), 'invalid startup symbol')
        rows.append((row[3], int(row[1], 16), int(row[2], 16)))
    require(len(rows) == 1 and rows[0][1] % 2 == 0, 'wrong startup symbol population')
    return rows[0]


def materialize(raw, high, low, source, target):
    delta = target - source
    upper = (delta + 0x800) >> 12
    lower = delta - (upper << 12)
    require(-2**19 <= upper < 2**19 and -2048 <= lower < 2048, 'startup reference out of range')
    a = int.from_bytes(raw[high:high+4], 'little')
    b = int.from_bytes(raw[low:low+4], 'little')
    raw[high:high+4] = (a | ((upper & 0xfffff) << 12)).to_bytes(4, 'little')
    raw[low:low+4] = (b | ((lower & 4095) << 20)).to_bytes(4, 'little')


def inspect(nm, image, compiler, panic):
    p = policy(compiler, panic)
    symbol, address, size = select(nm)
    require(size == len(bytes.fromhex(p['bytes'])), 'wrong startup body size')
    pos = machine.mapped(image, address, size)
    actual = image[pos:pos+size]
    expected = bytearray.fromhex(p['bytes'])
    dependencies = machine.inspect(nm, image)
    symbols = {name: (a, n) for name, a, n, _, _ in machine.select(nm)}
    targets = {r['kind']+str(r['bits']): symbols[r['symbol']][0] for r in dependencies['kernels']}
    imports, references = {}, []
    for c in p['calls']:
        offset, role = c['offset'], c['role']
        if role in ('bcmp', 'memset'):
            target = sessions.call_target(actual[offset:offset+8], address+offset)
            if role not in imports:
                imports[role] = sessions.runtime_import(image, target, role)
            require(target == imports[role]['address'], 'inconsistent startup import')
            targets[role] = target
        expected[offset:offset+8] = sessions.call(address+offset, targets[role])
    for r in p['references']:
        high, low, role = r['high'], r['low'], r['role']
        a = int.from_bytes(actual[high:high+4], 'little')
        b = int.from_bytes(actual[low:low+4], 'little')
        target = address + high + machine.signed(a & 0xfffff000, 32) + machine.signed(b >> 20, 12)
        value = REFERENCE[role]
        offset = sessions.load_offset(image, target, len(value), (4, 5))
        require(image[offset:offset+len(value)] == value, 'startup reference mismatch')
        materialize(expected, high, low, address+high, target)
        references.append({'role': role, 'offset': offset, 'address': target, 'size': len(value)})
    require(actual == expected, 'startup template mismatch')
    extents = [(address, address+size)] + [(a, a+n) for a, n in symbols.values()]
    extents += [(r['address'], r['address']+r['size']) for r in imports.values()]
    extents += [(r['address'], r['address']+r['size']) for r in references]
    extents.sort()
    require(all(b <= c for (_, b), (c, _) in zip(extents, extents[1:])), 'overlapping startup objects')
    return {'symbol': symbol, 'address': address, 'size': size, 'body_sha256': hashlib.sha256(actual).hexdigest(),
            'imports': imports, 'references': references, 'dependencies': dependencies,
            'scope': 'evidence-only static startup; three full schedules and six independent block answers; '
                     'libc/loader trusted; not hosted admission, timing, general callers or physical fault detection'}


def corruption_cases(image, references):
    require(Counter(r['role'] for r in references) == Counter(REFERENCE.keys()), 'wrong corruption population')
    ranges = []
    for r in references:
        offset, size, role = r['offset'], r['size'], r['role']
        require(type(offset) is int and offset >= 0 and size == len(REFERENCE[role])
                and image[offset:offset+size] == REFERENCE[role], 'changed corruption reference')
        ranges.append((offset, offset+size))
    ranges.sort()
    require(all(b <= c for (_, b), (c, _) in zip(ranges, ranges[1:])), 'overlapping corruption references')
    for r in references:
        for i in range(r['size']):
            pos = r['offset']+i
            yield f'{r["role"]}/{i}', image[:pos]+bytes([image[pos]^1])+image[pos+1:]
