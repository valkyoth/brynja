#!/usr/bin/env python3
"""Constructor byte, call-binding, admission, cleanup and CLI controls."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('constructor_session_fixture',
    Path(__file__).with_name('test-aes-apple-linked-sessions.py'))
prior = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prior)
runner = prior.prior.runner
review = runner.constructors_review
BASE = prior.prior.fixture_module.BASE


def fixture(compiler='1.99.1', panic='abort', admission='static'):
    old, _ = prior.fixture(compiler, panic, admission)
    codeinfo, _, symbols = review.mapping.parse(old, symbol_filter=lambda _: True)
    code = bytearray(old[0x400:0x400 + codeinfo['size'] - 4])  # Replace terminal sentinel.
    clear = review.sessions.cleanup.select(old)['zeroize'][1]
    expansions = {r['bits']: int(r['address'], 16) for r in review.mapping.inspect(old)['bodies']
                  if r['role'] == 'expand'}
    copy = BASE + 0x400 + len(code)
    symbol = ('__ZN11brynja_core22secret_memory_transfer10copy_bytes17h4444444444444444E'
              if compiler == '1.90.0' else '__RNvNtCtest_11brynja_core22secret_memory_transfer10copy_bytes')
    symbols.append((symbol, copy))
    code.extend(review.copy_template())
    for role in ('raw', 'cached'):
        for bits in (128, 192, 256):
            suffix = f'6aes{bits}' + ('7new_key' if role == 'raw' else '10new_cached')
            symbol = ('__ZN30brynja_aes_accelerated_fixture9lifecycle' + suffix + f'17h{bits:016x}E'
                      if compiler == '1.90.0' else
                      '__RNvNtNtCtest_30brynja_aes_accelerated_fixture9lifecycle' + suffix)
            address = BASE + 0x400 + len(code)
            symbols.append((symbol, address))
            code.extend(review.template(role, bits, compiler, panic, admission, address, clear, copy,
                        expansions[bits] if role == 'cached' else None,
                        prior.RESUME if role == 'cached' and (compiler, panic) == ('1.90.0', 'unwind') else None))
    ends = [address for _, address in symbols] + [BASE + 0x400 + len(code)]
    code.extend(bytes.fromhex('c0035fd6'))
    assert 0x400 + len(code) < 0x4000
    image = bytearray(0x6000)
    image[:0x400] = old[:0x400]
    image[0x400:0x400 + len(code)] = code
    strings = bytearray(b' \0')
    for i, (symbol, address) in enumerate(symbols):
        struct.pack_into('<IBBHQ', image, 0x4000 + 16 * i, len(strings), 0xe, 1, 0, address)
        strings.extend(symbol.encode() + b'\0')
    assert len(strings) < 0x1400
    image[0x4400:0x4400 + len(strings)] = strings
    deltas, previous = bytearray(), BASE
    for address in ends:
        deltas.extend(prior.prior.fixture_module.uleb(address - previous))
        previous = address
    deltas.append(0)
    image[0x5800:0x5800 + len(deltas)] = deltas
    struct.pack_into('<Q', image, 64, 0x4000)
    struct.pack_into('<Q', image, 80, 0x4000)
    struct.pack_into('<Q', image, 144, len(code))
    struct.pack_into('<4Q', image, 208, BASE + 0x4000, 0x2000, 0x4000, 0x2000)
    struct.pack_into('<6I', image, 256, 2, 24, 0x4000, len(symbols), 0x4400, len(strings))
    struct.pack_into('<4I', image, 280, 0x26, 16, 0x5800, len(deltas))
    return image


class AppleConstructorTests(unittest.TestCase):
    def inspect(self, image, compiler='1.99.1', panic='abort', admission='static'):
        # Separate import tests validate its full Mach-O representation; actual
        # retained-binary replay combines all dependencies without mocking.
        with patch.object(review.sessions.imports, 'inspect', return_value={'stub_address': hex(prior.RESUME)}):
            return review.inspect(image, compiler, panic, admission)

    def test_all_configurations_and_widths(self):
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                for admission in ('static', 'hosted'):
                    config = compiler, panic, admission
                    rows = self.inspect(fixture(*config), *config)['constructors_and_copy']
                    self.assertEqual(len(rows), 7)
                    self.assertEqual(rows[0]['role'], 'copy')
                    raw_size = 180 if admission == 'static' else 200 if compiler == '1.90.0' else 188
                    cached_size = ({('1.90.0', 'abort'): 380, ('1.90.0', 'unwind'): 496,
                                    ('1.99.1', 'abort'): 380, ('1.99.1', 'unwind'): 360}[compiler, panic]
                                   + (40 if compiler == '1.90.0' else 16) * (admission == 'hosted'))
                    for row in rows:
                        self.assertEqual(row['size'], 84 if row['role'] == 'copy' else raw_size
                                         if row['role'] == 'raw' else cached_size + (row['bits'] - 128) // 16)

    def test_every_constructor_and_copy_byte_in_all_profiles(self):
        count = 0
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                for admission in ('static', 'hosted'):
                    config = compiler, panic, admission
                    image = fixture(*config)
                    for _, _, size, pos in review.selected(image).values():
                        for i in range(size):
                            changed = bytearray(image)
                            changed[pos + i] ^= 1
                            with self.assertRaisesRegex(ValueError, 'constructor/copy encoding/extent changed'):
                                self.inspect(changed, *config)
                            count += 1
        self.assertEqual(count, 15288)

    def test_width_length_clear_before_admission_and_copy_after_admission(self):
        image = fixture()
        for bits in (128, 192, 256):
            _, _, _, pos = review.selected(image)['raw', bits]
            words = struct.unpack_from('<45I', image, pos)
            self.assertEqual(words[10], review.movw(1, bits // 8))
            self.assertEqual(words[11] & 0xfc000000, 0x94000000)  # clear before health load
            self.assertEqual(words[12], 0x394022a8)
            self.assertEqual(words[22], review.movw(2, bits // 8))
            self.assertEqual(words[23] & 0xfc000000, 0x94000000)  # copy after checks
            self.assertEqual(words[-1] & 0xfc000000, 0x14000000)  # rejection clears via tail B

    def test_wrong_call_target_or_opcode_rejected(self):
        image = fixture()
        for role in ('raw', 'cached'):
            _, _, size, pos = review.selected(image)[role, 128]
            for offset in range(pos, pos + size, 4):
                word = struct.unpack_from('<I', image, offset)[0]
                if word & 0xfc000000 != 0x94000000:
                    continue
                for changed_word in (word + 1, word ^ 0x80000000):
                    changed = bytearray(image)
                    struct.pack_into('<I', changed, offset, changed_word)
                    with self.assertRaisesRegex(ValueError, 'constructor/copy encoding/extent changed'):
                        self.inspect(changed)

    def test_dependency_corruption_prevents_constructor_pass(self):
        image = fixture()
        offsets = [0x400, review.sessions.cleanup.select(image)['zeroize'][3],
                   review.sessions.selected(image)['encrypt', 128][3]]
        for offset in offsets:
            changed = bytearray(image)
            changed[offset] ^= 1
            with self.assertRaises(ValueError):
                self.inspect(changed)

    def test_missing_duplicate_and_aliased_symbols(self):
        image = fixture()
        for changed in (image.replace(b'7new_key', b'7new_bad', 1),
                        image.replace(b'6aes1287new_key', b'6aes1927new_key', 1)):
            with self.assertRaises(ValueError):
                self.inspect(changed)
        for offset, fmt, value in ((268, '<I', 21), (0x4108, '<Q', BASE + 0x400)):
            changed = bytearray(image)
            struct.pack_into(fmt, changed, offset, value)
            with self.assertRaises(ValueError):
                self.inspect(changed)

    def test_wrong_profiles_and_dependency_population(self):
        for kwargs in ({'role': 'bad'}, {'bits': 64}, {'compiler': 'bad'}, {'panic': 'bad'},
                       {'admission': 'bad'}, {'start': 3}, {'clear': None}, {'copy': 2**50},
                       {'expand': 8192}, {'resume': 8192}):
            args = dict(role='raw', bits=128, compiler='1.99.1', panic='abort', admission='static',
                        start=4096, clear=8192, copy=12288)
            with self.assertRaises(ValueError):
                review.template(**(args | kwargs))
        with self.assertRaises(ValueError):
            review.template('cached', 128, '1.90.0', 'unwind', 'static', 4096, 8192, 12288, 16384)

    def test_unwind_dependency_failure_and_truncated_landing_pad(self):
        image = fixture('1.90.0', 'unwind', 'static')
        with patch.object(review.sessions.imports, 'inspect', side_effect=ValueError('bad import')):
            with self.assertRaisesRegex(ValueError, 'bad import'):
                review.inspect(image, '1.90.0', 'unwind', 'static')
        row = review.selected(image)['cached', 256]
        changed = bytearray(image)
        struct.pack_into('<I', changed, row[3] + row[2] - 4, 0xd65f03c0)
        with self.assertRaisesRegex(ValueError, 'constructor/copy encoding/extent changed'):
            self.inspect(changed, '1.90.0', 'unwind', 'static')

    def test_cli_identity_configuration_and_no_failure_json(self):
        image = fixture()
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'constructors.macho'
            binary.write_bytes(image)
            command = [sys.executable, str(Path(__file__).with_name('check-aes-apple-linked.py')),
                       str(binary), '--sha256', hashlib.sha256(image).hexdigest(), '--review-constructors']
            config = ['--compiler', '1.99.1', '--panic', 'abort', '--admission', 'static']
            result = subprocess.run(command + config, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('"constructors_and_copy":', result.stdout)
            for args in (command, command + config + ['--review-sessions'],
                         command + config + ['--sha256', '0' * 64]):
                result = subprocess.run(args, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
