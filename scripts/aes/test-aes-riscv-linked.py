#!/usr/bin/env python3
"""Actual-byte negative controls for the bounded RV64 leaf review."""
import importlib.util
import json
from pathlib import Path
import struct
import tomllib
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('riscv_linked_test', HERE / 'check-aes-riscv-linked.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
startup_runner = runner.packaged.module('rv64_startup_runner_test', HERE / 'check-aes-riscv-startup.py')
startup = startup_runner.review
m = runner.review
FIXTURES = json.loads((HERE / 'riscv-machine-fixtures.json').read_text())['bodies']


def body(kind='transform', bits=128):
    return bytes.fromhex(next(r['bytes'] for r in FIXTURES if (r['kind'], r['bits']) == (kind, bits)))


def fixture():
    image = bytearray(0x3000)
    image[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', image, 16, 2, 243, 1)
    struct.pack_into('<Q', image, 32, 64)
    struct.pack_into('<HHH', image, 52, 64, 56, 1)
    struct.pack_into('<IIQQQQQQ', image, 64, 1, 5, 0, 0x1000, 0, len(image), len(image), 0x1000)
    nm, position = [], 0x100
    for r in FIXTURES:
        kind, bits, raw = r['kind'], r['bits'], bytes.fromhex(r['bytes'])
        generic = (f'6expandKj{bits // 8:x}_Kj{(bits // 32 + 7) * 16:x}' if kind == 'expand'
                   else f'9transformKj{bits // 32 + 7:x}')
        symbol = f'_RINvNtNtCstest_17brynja_crypto_cpu3aes7riscv64{generic}_EB6_'
        nm.append(f'{position + 0x1000:016x} {len(raw):016x} t {symbol}')
        image[position:position + len(raw)] = raw
        position += len(raw)
    return '\n'.join(nm), bytes(image)


def replace(raw, at, word, n):
    return raw[:at] + word.to_bytes(n, 'little') + raw[at + n:]


def first(raw, predicate):
    return next(pc for pc, (n, inst) in m.decode(raw).items() if predicate(n, inst))


def cleanup_fixture(compiler, panic):
    # Small standalone ELF with independent known symbol addresses.
    _, original = fixture()
    image = bytearray(original)
    names = ('11brynja_core22secret_memory_volatile23zeroize_region_volatile',
             '30brynja_aes_accelerated_fixture9lifecycle13destroy_block',
             '30brynja_aes_accelerated_fixture9lifecycle6aes12811destroy_key')
    nm = []
    for index, name in enumerate(names):
        address = 0x1100 + index * 0x100
        raw = runner.cleanup.CLEAR[compiler] if index == 0 else runner.cleanup.destroy(compiler, panic, address, 0x1100)
        image[address - 0x1000:address - 0x1000 + len(raw)] = raw
        nm.append(f'{address:x} {len(raw):x} t _ZN{name}17h0123456789abcdefE')
    return '\n'.join(nm), bytes(image)


def session_fixture(compiler, panic):
    nm, original = fixture()
    image = bytearray(original + bytes(0x1000))
    # Original RX load remains [0x1000,0x4000); add RW data and PT_DYNAMIC.
    struct.pack_into('<H', image, 56, 3)
    struct.pack_into('<IIQQQQQQ', image, 120, 1, 6, 0x3000, 0x5000, 0, 0x1000, 0x1000, 0x1000)
    struct.pack_into('<IIQQQQQQ', image, 176, 2, 6, 0x3000, 0x5000, 0, 128, 128, 8)
    tags = ((2, 24), (5, 0x3c00), (6, 0x3c40), (10, 16), (11, 24), (20, 7), (23, 0x3c80), (0, 0))
    for i, (tag, value) in enumerate(tags):
        struct.pack_into('<qQ', image, 0x3000 + i*16, tag, value)
    image[0x2c00:0x2c10] = b'\0_Unwind_Resume\0'
    struct.pack_into('<IBBHQQ', image, 0x2c58, 1, 0x12, 0, 0, 0, 0)
    struct.pack_into('<QQq', image, 0x2c80, 0x5200, (1 << 32) | 5, 0)
    # Independently known stub at 0x3e00 loads GOT slot 0x5200.
    struct.pack_into('<IIII', image, 0x2e00, 0x1e17, 0x400e3e03, 0xe0367, 0x13)
    kernels = {bits: address for _, address, _, kind, bits in m.select(nm) if kind == 'transform'}
    resume = 0x3e00 if (compiler, panic) == ('1.90.0', 'unwind') else None
    for i, (direction, bits) in enumerate((d, b) for d in ('encrypt', 'decrypt') for b in (128, 192, 256)):
        address = 0x3000 + i*256
        raw = runner.sessions.template(compiler, panic, direction, address, kernels[bits], resume)
        image[address - 0x1000:address - 0x1000 + len(raw)] = raw
        symbol = f'_ZN17brynja_crypto_cpu3aes7Session10{direction}{bits}17h0123456789abcdefE'
        nm += f'\n{address:x} {len(raw):x} t {symbol}'
    return nm, bytes(image)


def constructor_fixture(compiler, panic):
    nm, original = fixture()
    image = bytearray(original + bytes(0x5000))
    struct.pack_into('<H', image, 56, 3)
    struct.pack_into('<IIQQQQQQ', image, 64, 1, 5, 0, 0x1000, 0, 0x6000, 0x6000, 0x1000)
    struct.pack_into('<IIQQQQQQ', image, 120, 1, 6, 0x6000, 0x9000, 0, 0x1000, 0x1000, 0x1000)
    struct.pack_into('<IIQQQQQQ', image, 176, 2, 6, 0x6000, 0x9000, 0, 128, 128, 8)
    text = b'\0_Unwind_Resume\0memcpy\0memset\0'
    image[0x5c00:0x5c00 + len(text)] = text
    tags = ((2, 72), (5, 0x6c00), (6, 0x6c40), (10, len(text)), (11, 24), (20, 7), (23, 0x6d00), (0, 0))
    for i, (tag, value) in enumerate(tags):
        struct.pack_into('<qQ', image, 0x6000 + i*16, tag, value)
    for i, name in enumerate((b'_Unwind_Resume', b'memcpy', b'memset')):
        struct.pack_into('<IBBHQQ', image, 0x5c40 + (i + 1)*24, text.index(name), 0x12, 0, 0, 0, 0)
        struct.pack_into('<QQq', image, 0x5d00 + i*24, 0x9200 + i*8, ((i + 1) << 32) | 5, 0)
        # Stub i at 0x6e00+i*16 loads slot 0x9200+i*8.
        struct.pack_into('<IIII', image, 0x5e00 + i*16, 0x2e17, ((0x400 - i*8) << 20) | 0xe3e03, 0xe0367, 0x13)
    names = ('11brynja_core22secret_memory_volatile23zeroize_region_volatile',
             '30brynja_aes_accelerated_fixture9lifecycle13destroy_block',
             '30brynja_aes_accelerated_fixture9lifecycle6aes12811destroy_key')
    for i, name in enumerate(names):
        address = 0x5000 + i*256
        raw = runner.cleanup.CLEAR[compiler] if i == 0 else runner.cleanup.destroy(compiler, panic, address, 0x5000)
        image[address - 0x1000:address - 0x1000 + len(raw)] = raw
        nm += f'\n{address:x} {len(raw):x} t _ZN{name}17h0123456789abcdefE'
    expansions = {bits: a for _, a, _, kind, bits in m.select(nm) if kind == 'expand'}
    for i, (kind, bits) in enumerate((k, b) for k in ('key', 'cached') for b in (128, 192, 256)):
        address = 0x3000 + i*512
        targets = {'clear': 0x5000, 'memcpy': 0x6e10}
        if kind == 'cached':
            targets.update(expand=expansions[bits], memset=0x6e20)
            if (compiler, panic) == ('1.90.0', 'unwind'):
                targets['resume'] = 0x6e00
        raw = runner.constructors.template(compiler, panic, kind, bits, address, targets)
        image[address - 0x1000:address - 0x1000 + len(raw)] = raw
        ending = '7new_key' if kind == 'key' else '10new_cached'
        nm += f'\n{address:x} {len(raw):x} t _ZN30brynja_aes_accelerated_fixture9lifecycle6aes{bits}{ending}17h0123456789abcdefE'
    return nm, bytes(image)


def public_fixture(compiler, panic):
    nm, original = constructor_fixture(compiler, panic)
    nm = '\n'.join(line for line in nm.splitlines() if 'new_key' not in line and 'new_cached' not in line)
    image = bytearray(original)
    leaves = {(kind, bits): a for _, a, _, kind, bits in m.select(nm)}
    for i, (kind, bits) in enumerate((k, b) for k in ('cached', 'ephemeral') for b in (128, 192, 256)):
        address = 0x3000 + i*0x300
        targets = {'clear': 0x5000, 'memcpy': 0x6e10, 'transform': leaves['transform', bits]}
        if kind == 'ephemeral':
            targets.update(expand=leaves['expand', bits], memset=0x6e20)
        if (compiler, panic) == ('1.90.0', 'unwind'):
            targets['_Unwind_Resume'] = 0x6e00
        raw = runner.public.template(compiler, panic, kind, bits, address, targets)
        image[address-0x1000:address-0x1000+len(raw)] = raw
        name = (f'30brynja_aes_accelerated_fixture9public{bits}' if kind == 'ephemeral'
                else f'13brynja_crypto3aes9execution17Aes{bits}ExpandedKey20encrypt_block_public')
        nm += f'\n{address:x} {len(raw):x} t _ZN{name}17h0123456789abcdefE'
    return nm, bytes(image)


def secret_fixture(compiler, panic):
    nm, original = constructor_fixture(compiler, panic)
    nm = '\n'.join(line for line in nm.splitlines() if 'new_key' not in line and 'new_cached' not in line)
    image = bytearray(original)
    leaves = {(kind, bits): a for _, a, _, kind, bits in m.select(nm)}
    permits = {}
    for i, (direction, bits) in enumerate((d, b) for d in ('encrypt', 'decrypt') for b in (128, 192, 256)):
        address = 0x5300 + i*0x100
        resume = 0x6e00 if (compiler, panic) == ('1.90.0', 'unwind') else None
        raw = runner.sessions.template(compiler, panic, direction, address, leaves['transform', bits], resume)
        image[address-0x1000:address-0x1000+len(raw)] = raw
        nm += f'\n{address:x} {len(raw):x} t _ZN17brynja_crypto_cpu3aes7Session10{direction}{bits}17h0123456789abcdefE'
        permits[direction, bits] = address
    for i, (kind, bits) in enumerate((k, b) for k in ('cached', 'ephemeral') for b in (128, 192, 256)):
        address = 0x3000 + i*0x300
        targets = {'clear': 0x5000, 'memcpy': 0x6e10}
        if kind == 'cached':
            targets['transform'] = leaves['transform', bits]
        else:
            targets.update(expand=leaves['expand', bits], memset=0x6e20,
                           encrypt=permits['encrypt', bits], decrypt=permits['decrypt', bits])
        if (compiler, panic) == ('1.90.0', 'unwind'):
            targets['_Unwind_Resume'] = 0x6e00
        raw = runner.secret.template(compiler, panic, kind, bits, address, targets)
        image[address-0x1000:address-0x1000+len(raw)] = raw
        name = f'17Aes{bits}ExpandedKey' if kind == 'cached' else f'9Aes{bits}Key'
        nm += f'\n{address:x} {len(raw):x} t _ZN13brynja_crypto3aes9execution{name}6secret17h0123456789abcdefE'
    return nm, bytes(image)


def startup_fixture(compiler, panic):
    nm, original = constructor_fixture(compiler, panic)
    image = bytearray(original + bytes(0x1000))
    # Leave room for the fourth program header before the first code body.
    relocated = []
    for name, address, size, _, _ in m.select(nm):
        pos = m.mapped(original, address, size)
        image[pos+0x200:pos+0x200+size] = original[pos:pos+size]
        relocated.append(f'{address+0x200:x} {size:x} t {name}')
    nm = '\n'.join(relocated)
    struct.pack_into('<H', image, 56, 4)
    struct.pack_into('<IIQQQQQQ', image, 232, 1, 4, 0x7000, 0xa000, 0, 0x1000, 0x1000, 0x1000)
    # Existing second import's fixed-size name slot now binds bcmp.
    name = image.index(b'memcpy\0', 0x5c00)
    image[name:name+7] = b'bcmp\0\0\0'
    address = 0x3000
    p = startup.policy(compiler, panic)
    raw = bytearray.fromhex(p['bytes'])
    targets = {kind+str(bits): a for _, a, _, kind, bits in m.select(nm)}
    targets.update(bcmp=0x6e10, memset=0x6e20)
    for c in p['calls']:
        offset = c['offset']
        raw[offset:offset+8] = runner.sessions.call(address+offset, targets[c['role']])
    offset = 0x7000
    for r in p['references']:
        value = startup.REFERENCE[r['role']]
        image[offset:offset+len(value)] = value
        startup.materialize(raw, r['high'], r['low'], address+r['high'], offset+0x3000)
        offset += len(value)
    image[0x2000:0x2000+len(raw)] = raw
    nm += f'\n{address:x} {len(raw):x} t _ZN30brynja_aes_accelerated_fixture7startup17h0123456789abcdefE'
    return nm, bytes(image)


class RiscVLinkedTests(unittest.TestCase):
    def test_secret_all_profiles_widths_owners_and_manglings(self):
        c = runner.secret
        self.assertEqual(len(c.POLICY['bodies']), 24)
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                nm, image = secret_fixture(compiler, panic)
                report = c.inspect(nm, image, compiler, panic)
                self.assertEqual({(r['kind'], r['bits']) for r in report['secret']},
                                 {(k, b) for k in ('cached', 'ephemeral') for b in (128, 192, 256)})
                imports = {'memcpy', 'memset'} | ({'_Unwind_Resume'} if (compiler, panic) == ('1.90.0', 'unwind') else set())
                self.assertEqual(set(report['imports']), imports)
                current = nm
                for bits in (128, 192, 256):
                    for name in (f'9Aes{bits}Key', f'17Aes{bits}ExpandedKey'):
                        current = current.replace(f'_ZN13brynja_crypto3aes9execution{name}6secret17h0123456789abcdefE',
                                                  f'_RNvMsa_NtNtCstest_13brynja_crypto3aes9executionNtB5_{name}6secret')
                self.assertEqual(len(c.inspect(current, image, compiler, panic)['secret']), 6)

    def test_secret_every_body_bit_including_destination_result_and_direction(self):
        c = runner.secret
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                nm, image = secret_fixture(compiler, panic)
                for r in c.inspect(nm, image, compiler, panic)['secret']:
                    pos = m.mapped(image, r['address'], r['size'])
                    for offset in range(pos, pos+r['size']):
                        for bit in range(8):
                            changed = bytearray(image)
                            changed[offset] ^= 1 << bit
                            with self.assertRaisesRegex(ValueError, 'template mismatch'):
                                c.check_body(bytes(changed), r['address'], r['size'], compiler,
                                             panic, r['kind'], r['bits'], r['targets'])

    def test_secret_wrong_width_direction_copy_fill_and_clear_edges(self):
        c = runner.secret
        nm, image = secret_fixture('1.99.1', 'abort')
        leaves = {(kind, bits): a for _, a, _, kind, bits in m.select(nm)}
        permits = runner.sessions.select(nm)
        for kind in ('cached', 'ephemeral'):
            cases = [('clear', 0x5002), ('clear', 0x5100), ('memcpy', 0x6e20)]
            if kind == 'cached':
                cases += [('transform', leaves['transform', 192]), ('transform', leaves['expand', 128])]
            else:
                cases += [('expand', leaves['expand', 256]), ('memset', 0x6e10),
                          ('encrypt', permits['decrypt', 128][1]), ('decrypt', permits['encrypt', 128][1]),
                          ('encrypt', permits['encrypt', 256][1]), ('decrypt', leaves['transform', 128])]
            _, address, size = c.select(nm)[kind, 128]
            for role, target in cases:
                for edge in (e for e in c.policy('1.99.1', 'abort', kind, 128)['calls'] if e['role'] == role):
                    changed = bytearray(image)
                    pos = m.mapped(image, address, size) + edge['offset']
                    encoder = runner.cleanup.tail if edge['tail'] else runner.sessions.call
                    changed[pos:pos+8] = encoder(address+edge['offset'], target)
                    with self.assertRaises(ValueError):
                        c.inspect(nm, bytes(changed), '1.99.1', 'abort')

    def test_secret_unwind_and_tail_edges_bound(self):
        c = runner.secret
        nm, image = secret_fixture('1.90.0', 'unwind')
        count = 0
        for (kind, bits), (_, address, size) in c.select(nm).items():
            for edge in (e for e in c.policy('1.90.0', 'unwind', kind, bits)['calls'] if e['role'] == '_Unwind_Resume'):
                changed = bytearray(image)
                pos = m.mapped(image, address, size) + edge['offset']
                changed[pos:pos+8] = runner.sessions.call(address+edge['offset'], 0x6e10)
                with self.assertRaises(ValueError):
                    c.inspect(nm, bytes(changed), '1.90.0', 'unwind')
                count += 1
        self.assertEqual(count, 9)
        for compiler, panic in (('1.90.0', 'abort'), ('1.99.1', 'abort'), ('1.99.1', 'unwind')):
            nm, image = secret_fixture(compiler, panic)
            for bits in (128, 192, 256):
                _, address, size = c.select(nm)['cached', bits]
                edge = next(e for e in c.policy(compiler, panic, 'cached', bits)['calls'] if e['tail'])
                changed = bytearray(image)
                pos = m.mapped(image, address, size) + edge['offset']
                changed[pos:pos+8] = runner.sessions.call(address+edge['offset'], 0x5000)
                with self.assertRaisesRegex(ValueError, 'template mismatch'):
                    c.inspect(nm, bytes(changed), compiler, panic)

    def test_secret_corrupt_leaf_session_cleanup_and_import_rejected(self):
        c = runner.secret
        nm, image = secret_fixture('1.90.0', 'unwind')
        targets = [a for _, a, _, _, _ in m.select(nm)]
        targets += [a for _, a, _ in runner.sessions.select(nm).values()]
        targets += [0x5000, 0x5100, 0x5200, 0x6e00, 0x6e10, 0x6e20]
        for address in targets:
            changed = bytearray(image)
            pos = m.mapped(image, address, 4)
            changed[pos:pos+4] = bytes.fromhex('73000000')
            with self.assertRaises(ValueError):
                c.inspect(nm, bytes(changed), '1.90.0', 'unwind')
        for name in (b'memcpy\0', b'memset\0', b'_Unwind_Resume\0'):
            changed = bytearray(image)
            changed[image.index(name, 0x5c00)] = ord('z')
            with self.assertRaises(ValueError):
                c.inspect(nm, bytes(changed), '1.90.0', 'unwind')

    def test_secret_symbols_and_extents_fail_closed(self):
        c = runner.secret
        nm, image = secret_fixture('1.99.1', 'abort')
        for bad in ('\n'.join(nm.splitlines()[:-1]), nm+'\n'+nm.splitlines()[-1],
                    nm.replace('9Aes256Key6secret', '9Aes512Key6secret'),
                    nm.replace(' t _ZN13brynja_crypto3aes9execution', ' D _ZN13brynja_crypto3aes9execution'),
                    nm.replace('3000 208', '3001 208'), nm.replace('3000 208', '3000 0'),
                    nm.replace('3000 208', '3000 20a'), nm.replace('3300 208', '3000 208')):
            self.assertNotEqual(bad, nm)
            with self.assertRaises(ValueError):
                c.inspect(bad, image, '1.99.1', 'abort')

    def test_secret_policy_offsets_population_tail_and_targets_fail_closed(self):
        c = runner.secret
        for args in (('nightly', 'abort', 'cached', 128), ('1.99.1', 'other', 'cached', 128),
                     ('1.99.1', 'abort', 'other', 128), ('1.99.1', 'abort', 'cached', 512)):
            with self.assertRaises(ValueError):
                c.policy(*args)
        for targets in ({'clear': 0x5000}, {'clear': 0x5000, 'memcpy': 0x6e10, 'transform': 0x1100, 'extra': 0x6000}):
            with self.assertRaises(ValueError):
                c.template('1.99.1', 'abort', 'cached', 128, 0x3000, targets)
        key = '1.99.1/abort/cached/128'
        original = c.POLICY['bodies'][key]
        variants = []
        for field, value in (('offset', 1), ('offset', -2), ('offset', 1000), ('role', 'memset'), ('tail', True)):
            variant = json.loads(json.dumps(original))
            variant['calls'][0][field] = value
            variants.append(variant)
        variant = json.loads(json.dumps(original))
        next(e for e in variant['calls'] if e['tail'])['tail'] = False
        variants.append(variant)
        variant = json.loads(json.dumps(original))
        variant['calls'][1]['offset'] = variant['calls'][0]['offset']+2
        variants.append(variant)
        variant = json.loads(json.dumps(original))
        variant['calls'].append(dict(variant['calls'][0]))
        variants.append(variant)
        variant = json.loads(json.dumps(original))
        raw = bytearray.fromhex(variant['bytes'])
        raw[variant['calls'][0]['offset']] = 1
        variant['bytes'] = raw.hex()
        variants.append(variant)
        for variant in variants:
            with patch.dict(c.POLICY['bodies'], {key: variant}), self.assertRaises(ValueError):
                c.policy('1.99.1', 'abort', 'cached', 128)

    def test_public_complete_population_all_profiles_and_manglings(self):
        c = runner.public
        self.assertEqual(len(c.POLICY['bodies']), 24)
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                nm, image = public_fixture(compiler, panic)
                report = c.inspect(nm, image, compiler, panic)
                self.assertEqual({(r['kind'], r['bits']) for r in report['public']},
                                 {(k, b) for k in ('cached', 'ephemeral') for b in (128, 192, 256)})
                imports = {'memcpy', 'memset'} | ({'_Unwind_Resume'} if (compiler, panic) == ('1.90.0', 'unwind') else set())
                self.assertEqual(set(report['imports']), imports)
                current = nm
                for bits in (128, 192, 256):
                    current = current.replace(f'_ZN30brynja_aes_accelerated_fixture9public{bits}17h0123456789abcdefE',
                                              f'_RNvCstest_30brynja_aes_accelerated_fixture9public{bits}')
                    current = current.replace(f'_ZN13brynja_crypto3aes9execution17Aes{bits}ExpandedKey20encrypt_block_public17h0123456789abcdefE',
                                              f'_RNvMsa_NtNtCstest_13brynja_crypto3aes9executionNtB5_17Aes{bits}ExpandedKey20encrypt_block_public')
                self.assertEqual(len(c.inspect(current, image, compiler, panic)['public']), 6)

    def test_public_every_body_bit_including_guards_counts_and_calls_is_bound(self):
        c = runner.public
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                nm, image = public_fixture(compiler, panic)
                for r in c.inspect(nm, image, compiler, panic)['public']:
                    pos = m.mapped(image, r['address'], r['size'])
                    for offset in range(pos, pos+r['size']):
                        for bit in range(8):
                            changed = bytearray(image)
                            changed[offset] ^= 1 << bit
                            with self.assertRaisesRegex(ValueError, 'template mismatch'):
                                c.check_body(bytes(changed), r['address'], r['size'], compiler,
                                             panic, r['kind'], r['bits'], r['targets'])

    def test_public_wrong_width_copy_fill_and_clear_targets(self):
        c = runner.public
        nm, image = public_fixture('1.99.1', 'abort')
        leaves = {(kind, bits): a for _, a, _, kind, bits in m.select(nm)}
        for kind in ('cached', 'ephemeral'):
            cases = [('transform', leaves['transform', 192]), ('transform', leaves['expand', 128]),
                     ('clear', 0x5002), ('clear', 0x5100), ('memcpy', 0x6e20)]
            if kind == 'ephemeral':
                cases += [('expand', leaves['expand', 256]), ('memset', 0x6e10)]
            _, address, size = c.select(nm)[kind, 128]
            for role, target in cases:
                for edge in (e for e in c.policy('1.99.1', 'abort', kind, 128)['calls'] if e['role'] == role):
                    changed = bytearray(image)
                    pos = m.mapped(image, address, size) + edge['offset']
                    changed[pos:pos+8] = runner.sessions.call(address+edge['offset'], target)
                    with self.assertRaises(ValueError):
                        c.inspect(nm, bytes(changed), '1.99.1', 'abort')

    def test_public_all_unwind_edges_bound(self):
        c = runner.public
        nm, image = public_fixture('1.90.0', 'unwind')
        count = 0
        for (kind, bits), (_, address, size) in c.select(nm).items():
            for edge in (e for e in c.policy('1.90.0', 'unwind', kind, bits)['calls'] if e['role'] == '_Unwind_Resume'):
                changed = bytearray(image)
                pos = m.mapped(image, address, size) + edge['offset']
                changed[pos:pos+8] = runner.sessions.call(address+edge['offset'], 0x6e10)
                with self.assertRaises(ValueError):
                    c.inspect(nm, bytes(changed), '1.90.0', 'unwind')
                count += 1
        self.assertEqual(count, 12)

    def test_public_corrupt_dependencies_rejected(self):
        c = runner.public
        nm, image = public_fixture('1.90.0', 'unwind')
        targets = [a for _, a, _, _, _ in m.select(nm)] + [0x5000, 0x5100, 0x5200, 0x6e00, 0x6e10, 0x6e20]
        for address in targets:
            changed = bytearray(image)
            pos = m.mapped(image, address, 4)
            changed[pos:pos+4] = bytes.fromhex('73000000')
            with self.assertRaises(ValueError):
                c.inspect(nm, bytes(changed), '1.90.0', 'unwind')
        # Keep code unchanged, but corrupt the dynamic symbol name for memcpy.
        changed = bytearray(image)
        changed[image.index(b'memcpy\0', 0x5c00)] = ord('z')
        with self.assertRaisesRegex(ValueError, 'import'):
            c.inspect(nm, bytes(changed), '1.90.0', 'unwind')

    def test_public_symbol_and_extent_rejections(self):
        c = runner.public
        nm, image = public_fixture('1.99.1', 'abort')
        for bad in ('\n'.join(nm.splitlines()[:-1]), nm+'\n'+nm.splitlines()[-1],
                    nm.replace('9public256', '9public512'), nm.replace(' t _ZN30brynja_aes_accelerated_fixture9public', ' D _ZN30brynja_aes_accelerated_fixture9public'),
                    nm.replace('3000 1b0', '3001 1b0'), nm.replace('3000 1b0', '3000 0'),
                    nm.replace('3000 1b0', '3000 1b2'), nm.replace('3300 1b0', '3000 1b0')):
            self.assertNotEqual(bad, nm)
            with self.assertRaises(ValueError):
                c.inspect(bad, image, '1.99.1', 'abort')

    def test_public_policy_offsets_population_and_targets_fail_closed(self):
        c = runner.public
        for args in (('nightly', 'abort', 'cached', 128), ('1.99.1', 'other', 'cached', 128),
                     ('1.99.1', 'abort', 'other', 128), ('1.99.1', 'abort', 'cached', 512)):
            with self.assertRaises(ValueError):
                c.policy(*args)
        for targets in ({'clear': 0x5000}, {'clear': 0x5000, 'memcpy': 0x6e10, 'transform': 0x1100, 'extra': 0x6000}):
            with self.assertRaises(ValueError):
                c.template('1.99.1', 'abort', 'cached', 128, 0x3000, targets)
        key = '1.99.1/abort/cached/128'
        original = c.POLICY['bodies'][key]
        variants = []
        for field, value in (('offset', 1), ('offset', -2), ('offset', 1000), ('role', 'memset')):
            variant = json.loads(json.dumps(original))
            variant['calls'][0][field] = value
            variants.append(variant)
        variant = json.loads(json.dumps(original))
        variant['calls'][1]['offset'] = variant['calls'][0]['offset']+2
        variants.append(variant)
        variant = json.loads(json.dumps(original))
        variant['calls'].append(dict(variant['calls'][0]))
        variants.append(variant)
        variant = json.loads(json.dumps(original))
        raw = bytearray.fromhex(variant['bytes'])
        raw[variant['calls'][0]['offset']] = 1
        variant['bytes'] = raw.hex()
        variants.append(variant)
        for variant in variants:
            with patch.dict(c.POLICY['bodies'], {key: variant}), self.assertRaises(ValueError):
                c.policy('1.99.1', 'abort', 'cached', 128)

    def test_startup_all_profiles_and_manglings(self):
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                nm, image = startup_fixture(compiler, panic)
                report = startup.inspect(nm, image, compiler, panic)
                self.assertEqual(len(report['references']), 11)
                self.assertEqual(set(report['imports']), {'bcmp', 'memset'})
                current = nm.replace('_ZN30brynja_aes_accelerated_fixture7startup17h0123456789abcdefE',
                                     '_RNvCstest_30brynja_aes_accelerated_fixture7startup')
                self.assertEqual(startup.select(current)[1:], startup.select(nm)[1:])

    def test_startup_every_code_byte_and_reference_byte_is_bound(self):
        for compiler in ('1.90.0', '1.99.1'):
            nm, image = startup_fixture(compiler, 'abort')
            report = startup.inspect(nm, image, compiler, 'abort')
            # Cache the independently checked, unchanged leaf bodies while
            # mutating only startup code/public data (not kernel bytes).
            with patch.object(startup.machine, 'inspect', return_value=report['dependencies']):
                for pos in range(0x2000, 0x2000+report['size']):
                    with self.subTest(compiler=compiler, byte=pos):
                        changed = image[:pos]+bytes([image[pos]^1])+image[pos+1:]
                        with self.assertRaises(ValueError):
                            startup.inspect(nm, changed, compiler, 'abort')
                cases = list(startup.corruption_cases(image, report['references']))
                self.assertEqual(len(cases), 688)
                self.assertEqual(len({label for label, _ in cases}), 688)
                for label, changed in cases:
                    with self.subTest(compiler=compiler, reference=label):
                        self.assertEqual(sum(a != b for a, b in zip(image, changed)), 1)
                        with self.assertRaisesRegex(ValueError, 'reference mismatch'):
                            startup.inspect(nm, changed, compiler, 'abort')

    def test_startup_wrong_width_direction_import_and_constant_roles(self):
        nm, image = startup_fixture('1.99.1', 'abort')
        report = startup.inspect(nm, image, '1.99.1', 'abort')
        p = startup.policy('1.99.1', 'abort')
        for c in p['calls']:
            target = 0x6e10 if c['role'] == 'memset' else 0x6e20
            if c['role'].startswith(('expand', 'transform')):
                kind = 'expand' if c['role'].startswith('expand') else 'transform'
                target = next(a for _, a, _, k, b in m.select(nm)
                              if k == kind and str(b) not in c['role'])
            pos = 0x2000+c['offset']
            changed = image[:pos]+runner.sessions.call(0x3000+c['offset'], target)+image[pos+8:]
            with self.assertRaises(ValueError):
                startup.inspect(nm, changed, '1.99.1', 'abort')
        for c in (c for c in p['calls'] if c['role'].startswith('transform')):
            # Reviewed caller sequence sets a2=0 immediately before encryption;
            # decryption sets a2=1 before the last schedule-pointer move.
            pos = 0x2000+c['offset']-2
            if image[pos:pos+2] != bytes.fromhex('0146'):
                pos -= 2
                self.assertEqual(image[pos:pos+2], bytes.fromhex('0546'))
            changed = image[:pos]+bytes([image[pos]^4])+image[pos+1:]
            with self.assertRaisesRegex(ValueError, 'template mismatch'):
                startup.inspect(nm, changed, '1.99.1', 'abort')
        r = p['references'][0]
        raw = bytearray.fromhex(p['bytes'])
        startup.materialize(raw, r['high'], r['low'], 0x3000+r['high'], report['references'][1]['address'])
        changed = bytearray(image)
        for off in (r['high'], r['low']):
            changed[0x2000+off:0x2004+off] = raw[off:off+4]
        with self.assertRaisesRegex(ValueError, 'reference mismatch'):
            startup.inspect(nm, bytes(changed), '1.99.1', 'abort')

    def test_startup_does_not_trust_corrupt_kernels_or_import_names(self):
        nm, image = startup_fixture('1.99.1', 'abort')
        for _, address, _, _, _ in m.select(nm):
            pos = m.mapped(image, address, 2)
            changed = image[:pos]+b'\0\0'+image[pos+2:]
            with self.assertRaises(ValueError):
                startup.inspect(nm, changed, '1.99.1', 'abort')
        changed = image.replace(b'bcmp\0', b'fake\0')
        with self.assertRaises(ValueError):
            startup.inspect(nm, changed, '1.99.1', 'abort')

    def test_startup_symbols_policy_mappings_and_corruption_fail_closed(self):
        nm, image = startup_fixture('1.99.1', 'abort')
        row = nm.splitlines()[-1]
        for changed in (nm+'\n'+row, nm.replace(row, ''), nm.replace('7startup17h', '7startup_extra17h')):
            with self.assertRaises(ValueError):
                startup.select(changed)
        with self.assertRaises(ValueError):
            startup.policy('future', 'abort')
        with self.assertRaises(ValueError):
            startup.policy('1.99.1', 'future')
        changed = bytearray(image)
        struct.pack_into('<I', changed, 236, 6)  # public references must be read-only
        with self.assertRaises(ValueError):
            startup.inspect(nm, bytes(changed), '1.99.1', 'abort')
        refs = startup.inspect(nm, image, '1.99.1', 'abort')['references']
        for changed in (refs[:-1], refs+[refs[0]], [dict(r, offset=-1) for r in refs]):
            with self.assertRaises(ValueError):
                list(startup.corruption_cases(image, changed))

    def test_startup_runner_exact_success_and_quarantine_markers(self):
        startup_runner.output_check('AES_RISCV_STARTUP_PASS\n')
        startup_runner.output_check('AES_RISCV_STARTUP_QUARANTINED\n', True)
        for corrupt in (True, False):
            for output in ('', 'AES_RISCV_STARTUP_PASS\nAES_RISCV_STARTUP_PASS\n',
                           'AES_RISCV_STARTUP_UNAVAILABLE\n', 'extra\nAES_RISCV_STARTUP_PASS\n'):
                with self.assertRaises(ValueError):
                    startup_runner.output_check(output, corrupt)
        with self.assertRaises(ValueError):
            startup_runner.output_check('AES_RISCV_STARTUP_PASS\n', True)
        with self.assertRaises(ValueError):
            startup_runner.output_check('AES_RISCV_STARTUP_QUARANTINED\n')

    def test_startup_registry_requires_every_consumer_and_tracks_review_inputs(self):
        registry = tomllib.loads((runner.packaged.ROOT / 'verification/checks.toml').read_text())
        checks = [c for c in registry['checks'] if c.get('category') == 'aes-riscv-startup']
        self.assertEqual(len(checks), 2)
        self.assertEqual({c['command'][-1] for c in checks}, {'1.90.0', '1.99.1'})
        for c in checks:
            compiler = c['command'][-1]
            expected = [f'AES_RISCV_STARTUP_LINKED_PASS: {compiler}; four evidence-only QEMU consumers']
            expected += [f'AES_RISCV_STARTUP_CONSUMER_PASS: {compiler} {r}-{p}; 688 corrupted-answer executions quarantined'
                         for r in ('direct', 'facade') for p in ('abort', 'unwind')]
            self.assertEqual(c['success']['unique_lines'], expected)
            self.assertIn('aes-riscv-linked', c['inputs'])
        paths = registry['groups']['aes-riscv-linked']['paths']
        for name in ('check-aes-riscv-startup.py', 'aes_riscv_startup.py', 'riscv-startup-review.json',
                     'startup-arm-reference.json', 'aes_riscv_sessions.py'):
            self.assertIn('scripts/aes/'+name, paths)
        self.assertIn('assurance/aes-accelerated-campaigns/startup-riscv.rs', paths)

    def test_constructors_complete_population_all_profiles_and_manglings(self):
        c = runner.constructors
        self.assertEqual(len(c.POLICY['bodies']), 15)
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                nm, image = constructor_fixture(compiler, panic)
                report = c.inspect(nm, image, compiler, panic)
                self.assertEqual({(r['kind'], r['bits']) for r in report['constructors']},
                                 {(k, b) for k in ('key', 'cached') for b in (128, 192, 256)})
                imports = {'memcpy', 'memset'} | ({'resume'} if (compiler, panic) == ('1.90.0', 'unwind') else set())
                self.assertEqual(set(report['imports']), imports)
                current = nm.replace('_ZN30brynja_aes_accelerated_fixture9lifecycle6aes',
                                     '_RNvNtNtCstest_30brynja_aes_accelerated_fixture9lifecycle6aes')
                current = current.replace('17h0123456789abcdefE', '')
                self.assertEqual(len(c.select(current)), 6)

    def test_constructor_every_bit_and_call_relocation_is_bound(self):
        c = runner.constructors
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                nm, image = constructor_fixture(compiler, panic)
                report = c.inspect(nm, image, compiler, panic)
                for r in report['constructors']:
                    pos = m.mapped(image, r['address'], r['size'])
                    for offset in range(pos, pos + r['size']):
                        for bit in range(8):
                            changed = bytearray(image)
                            changed[offset] ^= 1 << bit
                            with self.assertRaisesRegex(ValueError, 'template mismatch'):
                                c.check_body(bytes(changed), r['address'], r['size'], compiler,
                                             panic, r['kind'], r['bits'], r['targets'])

    def test_constructor_wrong_expansion_clear_and_copy_targets(self):
        c = runner.constructors
        nm, image = constructor_fixture('1.99.1', 'abort')
        rows = c.select(nm)
        expansions = {bits: a for _, a, _, kind, bits in m.select(nm) if kind == 'expand'}
        for kind, role, replacement in (('cached', 'expand', expansions[192]),
                ('cached', 'clear', 0x5002), ('key', 'clear', 0x5100),
                ('key', 'memcpy', 0x6e20), ('cached', 'memset', 0x6e10)):
            _, address, size = rows[kind, 128]
            edge = next(e for e in c.policy('1.99.1', 'abort', kind, 128)['calls'] if e['role'] == role)
            pos = m.mapped(image, address, size) + edge['offset']
            changed = bytearray(image)
            encoder = runner.cleanup.tail if edge['tail'] else runner.sessions.call
            changed[pos:pos + 8] = encoder(address + edge['offset'], replacement)
            with self.assertRaises(ValueError):
                c.inspect(nm, bytes(changed), '1.99.1', 'abort')

    def test_constructor_all_repeated_import_calls_are_bound(self):
        c = runner.constructors
        nm, image = constructor_fixture('1.90.0', 'unwind')
        _, address, size = c.select(nm)['cached', 128]
        edges = [e for e in c.policy('1.90.0', 'unwind', 'cached', 128)['calls'] if e['role'] == 'resume']
        self.assertEqual(len(edges), 2)
        for edge in edges:
            changed = bytearray(image)
            pos = m.mapped(image, address, size) + edge['offset']
            changed[pos:pos + 8] = runner.sessions.call(address + edge['offset'], 0x6e10)
            with self.assertRaises(ValueError):
                c.inspect(nm, bytes(changed), '1.90.0', 'unwind')

    def test_constructor_corrupt_helpers_are_not_trusted(self):
        c = runner.constructors
        nm, image = constructor_fixture('1.99.1', 'abort')
        expansion = next(a for _, a, _, kind, bits in m.select(nm) if (kind, bits) == ('expand', 128))
        for address in (expansion, 0x5000, 0x6e10, 0x6e20):
            changed = bytearray(image)
            pos = m.mapped(image, address, 4)
            changed[pos:pos + 4] = bytes.fromhex('73000000')
            with self.assertRaises(ValueError):
                c.inspect(nm, bytes(changed), '1.99.1', 'abort')

    def test_constructor_symbols_extents_and_import_identity(self):
        c = runner.constructors
        nm, image = constructor_fixture('1.99.1', 'abort')
        for bad in ('\n'.join(nm.splitlines()[:-1]), nm + '\n' + nm.splitlines()[-1],
                    nm.replace('6aes25610new_cached', '6aes51210new_cached'),
                    nm.replace('3000 92', '3001 92'), nm.replace('3000 92', '3000 0'),
                    nm.replace('3200 92', '3000 92')):
            with self.assertRaises(ValueError):
                c.inspect(bad, image, '1.99.1', 'abort')
        for address, name in ((0x6e00, 'memcpy'), (0x6e10, 'memset'), (0x6e20, '_Unwind_Resume'), (0x6e10, 'other')):
            with self.assertRaises(ValueError):
                runner.sessions.runtime_import(image, address, name)

    def test_constructor_policy_and_target_population_fail_closed(self):
        c = runner.constructors
        for args in (('nightly', 'abort', 'key', 128), ('1.99.1', 'other', 'key', 128),
                     ('1.99.1', 'abort', 'other', 128), ('1.99.1', 'abort', 'key', 512)):
            with self.assertRaises(ValueError):
                c.policy(*args)
        for targets in ({'clear': 0x5000}, {'clear': 0x5000, 'memcpy': 0x6e10, 'extra': 0x6000}):
            with self.assertRaises(ValueError):
                c.template('1.99.1', 'abort', 'key', 128, 0x3000, targets)
        key = '1.99.1/base/key/128'
        original = c.POLICY['bodies'][key]
        variants = []
        for field, value in (('offset', 1), ('role', 'memset'), ('tail', True)):
            variant = json.loads(json.dumps(original))
            variant['calls'][0][field] = value
            variants.append(variant)
        variant = json.loads(json.dumps(original))
        variant['calls'].append(dict(variant['calls'][0]))
        variants.append(variant)
        for variant in variants:
            with patch.dict(c.POLICY['bodies'], {key: variant}), self.assertRaises(ValueError):
                c.policy('1.99.1', 'abort', 'key', 128)

    def test_sessions_all_widths_directions_compilers_and_panic_profiles(self):
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                nm, image = session_fixture(compiler, panic)
                report = runner.sessions.inspect(nm, image, compiler, panic)
                self.assertEqual({(r['bits'], r['direction']) for r in report['sessions']},
                                 {(b, d) for b in (128, 192, 256) for d in ('encrypt', 'decrypt')})
                self.assertEqual(report['resume_import'] is not None, (compiler, panic) == ('1.90.0', 'unwind'))
                current = nm.replace('_ZN17brynja_crypto_cpu3aes7Session',
                                     '_RNvMs0_NtCstest_17brynja_crypto_cpu3aesNtB5_7Session')
                current = current.replace('17h0123456789abcdefE', '')
                self.assertEqual(len(runner.sessions.select(current)), 6)

    def test_session_known_call_encodings_and_policy_extents(self):
        s = runner.sessions
        for source, target, raw in ((0x13870, 0x125c4, '97f0ffffe78040d5'),
                                    (0x138fc, 0x47a0, '9710ffffe78040ea'),
                                    (0x10b14, 0x10b82, '97000000e780e006')):
            self.assertEqual(s.call(source, target).hex(), raw)
            self.assertEqual(s.call_target(bytes.fromhex(raw), source), target)
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                for direction in ('encrypt', 'decrypt'):
                    landing = (compiler, panic) == ('1.90.0', 'unwind')
                    raw = s.template(compiler, panic, direction, 0x3000, 0x1800, 0x3e00 if landing else None)
                    self.assertEqual(len(raw), 194 if landing else
                                     (150 if compiler == '1.90.0' else 156) + (2 if direction == 'decrypt' else 0))
        for args in ((1, 2), (2, 3), (0, 1 << 32), (-2, 4)):
            with self.assertRaises(ValueError):
                s.call(*args)
        for raw in (b'', bytes.fromhex('97000000'), bytes.fromhex('1703000067000300')):
            with self.assertRaises(ValueError):
                s.call_target(raw, 0x3000)

    def test_session_every_bit_including_landing_pad_is_bound(self):
        s = runner.sessions
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                nm, image = session_fixture(compiler, panic)
                kernels = {bits: address for _, address, _, kind, bits in m.select(nm) if kind == 'transform'}
                resume = 0x3e00 if (compiler, panic) == ('1.90.0', 'unwind') else None
                # Widths share exact templates; complete population checked above.
                for (direction, bits), (_, address, size) in s.select(nm).items():
                    if bits != 128:
                        continue
                    pos = m.mapped(image, address, size)
                    for offset in range(pos, pos + size):
                        for bit in range(8):
                            changed = bytearray(image)
                            changed[offset] ^= 1 << bit
                            with self.assertRaisesRegex(ValueError, 'template mismatch'):
                                s.check_body(bytes(changed), address, size, compiler, panic,
                                             direction, kernels[bits], resume)

    def test_session_kernel_width_and_actual_leaf_validation(self):
        s = runner.sessions
        nm, image = session_fixture('1.99.1', 'abort')
        kernels = {bits: (address, size) for _, address, size, kind, bits in m.select(nm) if kind == 'transform'}
        changed = bytearray(image)
        changed[0x202e:0x2036] = s.call(0x302e, kernels[192][0])
        with self.assertRaisesRegex(ValueError, 'template mismatch'):
            s.inspect(nm, bytes(changed), '1.99.1', 'abort')
        changed = bytearray(image)
        address, size = kernels[128]
        pos = m.mapped(image, address, size)
        changed[pos:pos + 4] = bytes.fromhex('73000000')
        with self.assertRaisesRegex(ValueError, 'unmodeled instruction'):
            s.inspect(nm, bytes(changed), '1.99.1', 'abort')

    def test_session_symbol_population_overlap_and_unknown_profiles(self):
        s = runner.sessions
        nm, image = session_fixture('1.99.1', 'abort')
        for bad in ('\n'.join(nm.splitlines()[:-1]), nm + '\n' + nm.splitlines()[-1],
                    nm.replace('encrypt128', 'encrypt512'), nm.replace('3000 9c', '3001 9c'),
                    nm.replace('3000 9c', '3000 0'), nm.replace('3100 9c', '3000 9c')):
            with self.assertRaises(ValueError):
                s.inspect(bad, image, '1.99.1', 'abort')
        for compiler, panic, direction, resume in (('nightly', 'abort', 'encrypt', None),
                ('1.99.1', 'other', 'encrypt', None), ('1.99.1', 'abort', 'expand', None),
                ('1.99.1', 'abort', 'encrypt', 0x3e00), ('1.90.0', 'unwind', 'encrypt', None)):
            with self.assertRaises(ValueError):
                s.template(compiler, panic, direction, 0x3000, 0x1800, resume)

    def test_resume_stub_every_bit_and_live_dynamic_binding(self):
        s = runner.sessions
        _, image = session_fixture('1.90.0', 'unwind')
        self.assertEqual(s.resume_import(image, 0x3e00)['slot'], 0x5200)
        for offset in range(0x2e00, 0x2e10):
            for bit in range(8):
                changed = bytearray(image)
                changed[offset] ^= 1 << bit
                with self.assertRaises(ValueError):
                    s.resume_import(bytes(changed), 0x3e00)
        # Live PT_DYNAMIC must name these tables. Section-name/text substitutions
        # cannot rescue invalid tags, symbol identity, relocation or memory access.
        mutations = ((0x3000, '<q', 23), (0x3008, '<Q', 25), (0x3028, '<Q', 0x3c30),
                     (0x3048, '<Q', 16), (0x3058, '<Q', 17), (0x3070, '<q', 1),
                     (0x2c88, '<Q', (1 << 32) | 6), (0x2c90, '<q', 1),
                     (0x2c80, '<Q', 0x5208), (0x2c58, '<I', 100),
                     (0x2c5c, '<B', 0x22), (0x2c5d, '<B', 1), (0x2c5e, '<H', 1),
                     (0x2c60, '<Q', 1), (124, '<I', 4), (184, '<Q', 0x3010),
                     (0x2c01, '<B', ord('X')))
        for offset, fmt, value in mutations:
            changed = bytearray(image)
            struct.pack_into(fmt, changed, offset, value)
            with self.assertRaises(ValueError, msg=(offset, value)):
                s.resume_import(bytes(changed), 0x3e00)

    def test_resume_duplicate_imports_slots_and_missing_terminator(self):
        s = runner.sessions
        _, image = session_fixture('1.90.0', 'unwind')
        for target in (0x5200, 0x5208):
            changed = bytearray(image)
            struct.pack_into('<Q', changed, 0x3008, 48)
            struct.pack_into('<QQq', changed, 0x2c98, target, (1 << 32) | 5, 0)
            with self.assertRaises(ValueError):
                s.resume_import(bytes(changed), 0x3e00)
        changed = bytearray(image)
        changed[0x2c00:0x2c10] = b'X' * 16
        with self.assertRaisesRegex(ValueError, 'unterminated import name'):
            s.resume_import(bytes(changed), 0x3e00)

    def test_cleanup_both_endpoints_and_panic_profiles(self):
        for compiler in runner.cleanup.CLEAR:
            for panic in ('abort', 'unwind'):
                nm, image = cleanup_fixture(compiler, panic)
                report = runner.cleanup.inspect(nm, image, compiler, panic)
                self.assertEqual({r['role'] for r in report['bodies']}, {'clear', 'block', 'key'})
                current_nm = nm.replace('_ZN', '_RNvNtCstest_').replace('17h0123456789abcdefE', '')
                self.assertEqual(len(runner.cleanup.inspect(current_nm, image, compiler, panic)['bodies']), 3)

    def test_cleanup_independent_known_relocations(self):
        # Real linked AUIPC/JALR encodings with positive and negative low halves.
        self.assertEqual(runner.cleanup.tail(0xb2e4, 0xf8ce).hex(), '174300006700a35e')
        self.assertEqual(runner.cleanup.tail(0xbf16, 0x10c84).hex(), '175300006700e3d6')
        self.assertEqual(runner.cleanup.tail(0x2000, 0x1800).hex(), '1703000067000380')
        for source, target in ((1, 2), (2, 3), (-2, 2), (0, 1 << 32)):
            with self.assertRaises(ValueError):
                runner.cleanup.tail(source, target)

    def test_cleanup_every_instruction_bit_is_bound(self):
        for compiler in runner.cleanup.CLEAR:
            for panic in ('abort', 'unwind'):
                nm, image = cleanup_fixture(compiler, panic)
                for address, size, _ in runner.cleanup.select(nm).values():
                    start = m.mapped(image, address, size)
                    for offset in range(start, start + size):
                        for bit in range(8):
                            changed = bytearray(image)
                            changed[offset] ^= 1 << bit
                            with self.assertRaisesRegex(ValueError, 'template mismatch'):
                                runner.cleanup.inspect(nm, bytes(changed), compiler, panic)

    def test_cleanup_symbol_population_and_extents(self):
        nm, image = cleanup_fixture('1.99.1', 'abort')
        for bad in ('\n'.join(nm.splitlines()[:2]), nm + '\n' + nm.splitlines()[0],
                    nm.replace('6aes128', '6aes192'), nm.replace(' t ', ' d '),
                    nm.replace('1200 c', '1100 c'), nm.replace('1200 c', '1201 c'),
                    nm.replace('1200 c', '1200 0'), nm.replace('1200 c', '1200 19')):
            with self.assertRaises(ValueError):
                runner.cleanup.inspect(bad, image, '1.99.1', 'abort')

    def test_cleanup_wrong_target_or_profile_is_rejected(self):
        nm, image = cleanup_fixture('1.99.1', 'unwind')
        for compiler, panic in (('1.90.0', 'unwind'), ('1.99.1', 'abort'), ('nightly', 'unwind'), ('1.99.1', 'other')):
            with self.assertRaises(ValueError):
                runner.cleanup.inspect(nm, image, compiler, panic)
        for offset in (4, 14):
            changed = bytearray(image)
            changed[0x200 + offset:0x208 + offset] = runner.cleanup.tail(0x1200 + offset, 0x1102)
            with self.assertRaisesRegex(ValueError, 'template mismatch'):
                runner.cleanup.inspect(nm, bytes(changed), '1.99.1', 'unwind')

    def test_all_widths_directions_and_exact_access_populations(self):
        nm, image = fixture()
        report = m.inspect(nm, image)
        self.assertEqual(len(report['kernels']), 6)
        for row in report['kernels']:
            bits = row['bits']
            for path in row['paths']:
                self.assertEqual(path['writes'], (bits // 32 + 7) * 16 if row['kind'] == 'expand' else 16)
                self.assertEqual(path['reads'], {128: 336, 192: 392, 256: 448}[bits]
                                 if row['kind'] == 'expand' else (bits // 32 + 8) * 16)
                self.assertLess(path['steps'], 20000)

    def test_decoder_known_words_and_compressed_signs(self):
        cases = {0x4281: ('addi', 5, 0, 0), 0x167d: ('addi', 12, 12, -1),
                 0x1f62: ('slli', 30, 30, 56), 0x8eae: ('add', 29, 0, 11),
                 0x8082: ('ret',), 0x31a39393: ('aes64ks1i', 7, 7, 10),
                 0x30029293: ('aes64im', 5, 5), 0x366283b3: ('aes64esm', 7, 5, 6),
                 0x326283b3: ('aes64es', 7, 5, 6), 0x3e6283b3: ('aes64dsm', 7, 5, 6),
                 0x3a6283b3: ('aes64ds', 7, 5, 6), 0x007f81a3: ('sb', 7, 31, 3)}
        for word, expected in cases.items():
            n = 2 if word < 65536 else 4
            self.assertEqual(m.decode(word.to_bytes(n, 'little'))[0], (n, expected))
        # Both compressed backward branches in the fixture land on instructions.
        self.assertEqual([inst[3] for _, inst in m.decode(body()).values()
                          if inst[0] == 'bne'], [0x13e, 0x454])

    def test_legacy_symbols_use_unique_bounded_width_not_sort_order(self):
        nm, image = fixture()
        legacy = []
        for index, line in enumerate(nm.splitlines()):
            prefix = line.split(' t ')[0]
            kind = '6expand' if 'expand' in line else '9transform'
            legacy.append(f'{prefix} t _ZN17brynja_crypto_cpu3aes7riscv64{kind}17h{index:016x}E')
        result = m.inspect('\n'.join(reversed(legacy)), image)
        self.assertEqual({(r['kind'], r['bits']) for r in result['kernels']},
                         {(kind, bits) for kind in ('expand', 'transform') for bits in (128, 192, 256)})
        # Replacing one body with another width must not yield a six-width pass.
        rows = m.select('\n'.join(legacy))
        pos = m.mapped(image, rows[1][1], rows[1][2])
        changed = image[:pos] + body('expand', 128) + image[pos + len(body('expand', 128)):]
        with self.assertRaisesRegex(ValueError, 'width population'):
            m.inspect('\n'.join(legacy), changed)

    def test_unknown_truncated_privileged_call_and_stack_instructions_fail(self):
        for raw in (b'\x13', b'\x13\x00', b'\x00\x00', bytes.fromhex('73000000'),
                    bytes.fromhex('ef000000'), bytes.fromhex('23301100')):
            with self.subTest(raw=raw.hex()), self.assertRaises(ValueError):
                m.decode(raw)

    def test_secret_branch_and_secret_address_mutations_fail(self):
        raw = body()
        at = first(raw, lambda n, ins: ins == ('or', 5, 5, 30))
        # beq t0,zero,+4, after the first secret-byte loads.
        branch = (5 << 15) | (2 << 8) | 0x63
        with self.assertRaisesRegex(ValueError, 'branch uses secret'):
            m.execute(m.decode(replace(raw, at, branch, 4)), 'transform', 128, 1)
        at = first(raw, lambda n, ins: ins == ('lbu', 30, 10, 1))
        word = (1 << 20) | (5 << 15) | (4 << 12) | (30 << 7) | 3
        with self.assertRaisesRegex(ValueError, 'memory address is secret'):
            m.execute(m.decode(replace(raw, at, word, 4)), 'transform', 128, 1)

    def test_out_of_bounds_read_write_and_readonly_write_fail(self):
        raw = body()
        for old, word, reason in (
                (('lbu', 5, 10, 0), (16 << 20) | (10 << 15) | (4 << 12) | (5 << 7) | 3, 'out-of-bounds'),
                (('sb', 5, 10, 0), (5 << 20) | (10 << 15) | (16 << 7) | 0x23, 'out-of-bounds'),
                (('sb', 5, 10, 0), (5 << 20) | (11 << 15) | 0x23, 'read-only')):
            at = first(raw, lambda n, ins: ins == old)
            with self.subTest(old=old, reason=reason), self.assertRaisesRegex(ValueError, reason):
                m.execute(m.decode(replace(raw, at, word, 4)), 'transform', 128, 1)

    def test_schedule_read_before_initialization_fails(self):
        raw = body('expand')
        at = first(raw, lambda n, ins: ins == ('add', 31, 10, 5))
        word = (5 << 20) | (11 << 15) | (31 << 7) | 0x33
        with self.assertRaisesRegex(ValueError, 'read before schedule initialization'):
            m.execute(m.decode(replace(raw, at, word, 4)), 'expand', 128)

    def test_both_return_paths_and_all_scratch_clears_checked(self):
        for kind in ('expand', 'transform'):
            raw = body(kind)
            clears = [(pc, n, inst) for pc, (n, inst) in m.decode(raw).items()
                      if inst[0] == 'addi' and inst[2:] == (0, 0) and pc > len(raw) // 4]
            rejected = 0
            for at, n, _ in clears:
                # c.li scratch,1 rather than zero.
                changed = replace(raw, at, int.from_bytes(raw[at:at + n], 'little') | 4, n)
                failures = 0
                for inverse in ((0, 1) if kind == 'transform' else (0,)):
                    try:
                        m.execute(m.decode(changed), kind, 128, inverse)
                    except ValueError:
                        failures += 1
                self.assertGreater(failures, 0)
                rejected += 1
            self.assertGreaterEqual(rejected, 7 if kind == 'expand' else 14)

    def test_round_count_branch_extent_and_nontermination_fail(self):
        raw = body()
        at = first(raw, lambda n, ins: ins == ('addi', 12, 0, 9))
        with self.assertRaises(ValueError):
            m.execute(m.decode(replace(raw, at, 0x4629, 2)), 'transform', 128, 1)
        for word in (0x00060163, 0x7e060ee3):  # Middle of first instruction / outside body.
            with self.assertRaisesRegex(ValueError, 'branch escapes'):
                m.decode(replace(raw, 0, word, 4))
        with self.assertRaisesRegex(ValueError, 'step bound'):
            m.execute({0: (4, ('beq', 0, 0, 0))}, 'expand', 128)

    def test_unmodeled_register_and_public_arithmetic_semantics(self):
        self.assertEqual(m.calculate('add', ('key', 16), -4), ('key', 12))
        self.assertEqual(m.calculate('add', m.MASK, 1), 0)
        self.assertEqual(m.calculate('srl', m.MASK, 63), 1)
        self.assertEqual(m.calculate('xor', m.SECRET, 1), m.SECRET)
        with self.assertRaises(ValueError):
            m.calculate('or', ('key', 0), m.SECRET)
        with self.assertRaises(ValueError):
            m.calculate('add', m.UNKNOWN, 1)
        with self.assertRaisesRegex(ValueError, 'outside declared scratch'):
            m.execute({0: (4, ('addi', 2, 0, 0))}, 'expand', 128)

    def test_elf_machine_permissions_truncation_and_aliasing_rejected(self):
        nm, image = fixture()
        for offset, encoded in ((18, struct.pack('<H', 183)), (68, struct.pack('<I', 7)),
                                (96, struct.pack('<Q', len(image) + 1))):
            changed = image[:offset] + encoded + image[offset + len(encoded):]
            with self.assertRaises(ValueError):
                m.inspect(nm, changed)
        for changed in (image[:63], image[:100], image[:-1]):
            with self.assertRaises(ValueError):
                m.inspect(nm, changed)
        for changed in (nm.splitlines()[0], nm + '\n' + nm.splitlines()[0],
                        nm.replace('Kj10_Kjb0', 'Kj10_Kjd0')):
            with self.assertRaises(ValueError):
                m.inspect(changed, image)

    def test_changed_elf_bytes_are_analyzed_not_fixture_hashes_or_text(self):
        nm, image = fixture()
        symbol, address, size, _, _ = m.select(nm)[0]
        pos = m.mapped(image, address, size)
        changed = image[:pos] + b'\x00\x00' + image[pos + 2:]
        with self.assertRaisesRegex(ValueError, 'unmodeled instruction'):
            m.inspect(nm, changed)

    def test_execution_output_and_ambient_configuration_fail_closed(self):
        good = '\n'.join(line for bits in (128, 192, 256) for line in (
            'AES_FORCED_AUTHORITY: RiscVScalarAes',
            f'AES_ACCELERATED_LINKED_KAT: {bits}; six operations; clearing and quarantine checked')) + '\n'
        runner.output_check(good)
        for bad in ('', good + good, good.replace('RiscVScalarAes', 'ArmAes'), good.replace('256', '128')):
            with self.assertRaises(ValueError):
                runner.output_check(bad)
        with patch.object(runner.os, 'environ', {'RUSTFLAGS': ''}), \
             patch.object(runner.packaged, 'package_sources') as package, self.assertRaises(ValueError):
            runner.check('1.99.1')
        package.assert_not_called()

    def test_registry_covers_both_endpoints_and_all_four_consumers(self):
        registry = tomllib.loads((runner.packaged.ROOT / 'verification/checks.toml').read_text())
        checks = [c for c in registry['checks'] if c.get('category') == 'aes-riscv-linked']
        self.assertEqual(len(checks), 2)
        for endpoint, compiler in (('msrv', '1.90.0'), ('current', '1.99.1')):
            check = next(c for c in checks if c['id'] == f'riscv-linked-{endpoint}')
            self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-riscv-linked.py', '--toolchain', compiler])
            self.assertIn('aes-riscv-linked', check['inputs'])
            self.assertIn('aes-accelerated-linked', check['inputs'])
            self.assertIn('aes-riscv', check['inputs'])
            markers = [f'AES_RISCV_LINKED_PASS: {compiler}; four QEMU consumers; bounded leaf and clearing review']
            markers += [f'AES_RISCV_LINKED_CONSUMER_PASS: {compiler} {route}-{panic}; six leaf bodies; nine public paths'
                        for route in ('direct', 'facade') for panic in ('abort', 'unwind')]
            markers += [f'AES_RISCV_LINKED_CLEANUP_PASS: {compiler} {route}-{panic}; three exact bodies'
                        for route in ('direct', 'facade') for panic in ('abort', 'unwind')]
            markers += [f'AES_RISCV_LINKED_SESSION_PASS: {compiler} {route}-{panic}; six bound block sessions'
                        for route in ('direct', 'facade') for panic in ('abort', 'unwind')]
            markers += [f'AES_RISCV_LINKED_CONSTRUCTOR_PASS: {compiler} {route}-{panic}; six bound key constructors'
                        for route in ('direct', 'facade') for panic in ('abort', 'unwind')]
            markers += [f'AES_RISCV_LINKED_PUBLIC_PASS: {compiler} {route}-{panic}; six bound public encryption paths'
                        for route in ('direct', 'facade') for panic in ('abort', 'unwind')]
            markers += [f'AES_RISCV_LINKED_SECRET_PASS: {compiler} {route}-{panic}; six bound secret output bodies; both directions'
                        for route in ('direct', 'facade') for panic in ('abort', 'unwind')]
            self.assertEqual(check['success']['unique_lines'], markers)
            self.assertIn('scripts/aes/aes_riscv_cleanup.py', registry['groups']['aes-riscv-linked']['paths'])
            self.assertIn('scripts/aes/aes_riscv_sessions.py', registry['groups']['aes-riscv-linked']['paths'])
            self.assertIn('scripts/aes/aes_riscv_constructors.py', registry['groups']['aes-riscv-linked']['paths'])
            self.assertIn('scripts/aes/riscv-constructors-review.json', registry['groups']['aes-riscv-linked']['paths'])
            self.assertIn('scripts/aes/aes_riscv_public.py', registry['groups']['aes-riscv-linked']['paths'])
            self.assertIn('scripts/aes/riscv-public-review.json', registry['groups']['aes-riscv-linked']['paths'])
            self.assertIn('scripts/aes/aes_riscv_secret.py', registry['groups']['aes-riscv-linked']['paths'])
            self.assertIn('scripts/aes/riscv-secret-review.json', registry['groups']['aes-riscv-linked']['paths'])
            self.assertNotIn('exact_tests', check['success'])
            self.assertIn('CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUSTFLAGS', check['reject_environment'])


if __name__ == '__main__':
    unittest.main()
