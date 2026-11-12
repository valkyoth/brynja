#!/usr/bin/env python3
"""Secret caller direction, result admission, clearing and bound dependency controls."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('ephemeral_secret_public_fixture',
    Path(__file__).with_name('test-aes-apple-linked-ephemeral-public.py'))
prior = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prior)
runner, BASE, CONFIGS, RESUME = prior.runner, prior.BASE, prior.CONFIGS, prior.RESUME
review = runner.ephemeral_secret_review


def fixture(compiler='1.99.1', panic='abort', admission='static'):
    image = prior.fixture(compiler, panic, admission)
    codeinfo, _, symbols = review.mapping.parse(image, symbol_filter=lambda _: True)
    code = bytearray(image[0x400:0x400 + codeinfo['size'] - 4])
    constructors = review.prior.prior.prior
    clear = constructors.sessions.cleanup.select(image)['zeroize'][1]
    copy = constructors.selected(image)['copy', 0][1]
    calls = constructors.sessions.selected(image)
    expansions = {r['bits']: int(r['address'], 16) for r in review.mapping.inspect(image)['bodies']
                  if r['role'] == 'expand'}
    for bits in (128, 192, 256):
        symbol = (f'__ZN13brynja_crypto3aes9execution9Aes{bits}Key6secret17h{bits:016x}E'
                  if compiler == '1.90.0' else f'__RNvMs9_NtNtCtest_13brynja_crypto3aes9executionNtB5_9Aes{bits}Key6secret')
        address = BASE + 0x400 + len(code)
        symbols.append((symbol, address))
        code.extend(review.template(bits, compiler, panic, admission, address,
                    expansions[bits], calls['encrypt', bits][1], calls['decrypt', bits][1], clear, copy,
                    RESUME if (compiler, panic) == ('1.90.0', 'unwind') else None))
    ends = [address for _, address in symbols] + [BASE + 0x400 + len(code)]
    code.extend(bytes.fromhex('c0035fd6'))
    assert 0x400 + len(code) < 0x4000
    image[0x400:0x400 + len(code)] = code
    strings = bytearray(b' \0')
    for i, (symbol, address) in enumerate(symbols):
        struct.pack_into('<IBBHQ', image, 0x4000 + 16 * i, len(strings), 0xe, 1, 0, address)
        strings.extend(symbol.encode() + b'\0')
    assert 16 * len(symbols) < 0x400 and len(strings) < 0x1400
    image[0x4400:0x4400 + len(strings)] = strings
    deltas, previous = bytearray(), BASE
    for address in ends:
        deltas.extend(prior.prior.prior.prior.prior.fixture_module.uleb(address - previous))
        previous = address
    deltas.append(0)
    image[0x5800:0x5800 + len(deltas)] = deltas
    struct.pack_into('<Q', image, 144, len(code))
    struct.pack_into('<6I', image, 256, 2, 24, 0x4000, len(symbols), 0x4400, len(strings))
    struct.pack_into('<4I', image, 280, 0x26, 16, 0x5800, len(deltas))
    return image


class AppleEphemeralSecretTests(unittest.TestCase):
    def inspect(self, image, compiler='1.99.1', panic='abort', admission='static'):
        # Separate import tests and actual retained replay validate real imports.
        with patch.object(review.prior.prior.prior.sessions.imports, 'inspect',
                          return_value={'stub_address': hex(RESUME)}):
            return review.inspect(image, compiler, panic, admission)

    def test_all_profiles_and_widths(self):
        totals = []
        for config in CONFIGS:
            rows = self.inspect(fixture(*config), *config)['ephemeral_secret_callers']
            self.assertEqual([r['bits'] for r in rows], [128, 192, 256])
            totals.append(sum(r['size'] for r in rows))
        self.assertEqual(totals, [1716, 1836, 2100, 2220, 1728, 1776, 1656, 1728])

    def test_every_body_byte_in_every_profile(self):
        count = 0
        for config in CONFIGS:
            image = fixture(*config)
            for _, _, size, pos in review.selected(image).values():
                for i in range(size):
                    changed = bytearray(image)
                    changed[pos + i] ^= 1
                    with self.assertRaisesRegex(ValueError, 'ephemeral secret encoding/extent changed'):
                        self.inspect(changed, *config)
                    count += 1
        self.assertEqual(count, 14760)

    def test_destination_clear_precedes_admission_and_raw_lengths_are_exact(self):
        image = fixture()
        for bits in (128, 192, 256):
            _, _, size, pos = review.selected(image)[bits]
            words = list(struct.unpack_from('<' + 'I' * (size // 4), image, pos))
            self.assertEqual(words[12:14], [0xaa0303e0, review.movw(1, 16)])
            self.assertEqual(words[14] & 0xfc000000, 0x94000000)
            self.assertEqual(words[16], 0x394022a8)
            length = words.index(0xf100013f | (bits // 8) << 10)
            changed = bytearray(image)
            struct.pack_into('<I', changed, pos + length * 4, 0xf100013f | ((bits // 8) + 8) << 10)
            with self.assertRaisesRegex(ValueError, 'ephemeral secret encoding/extent changed'):
                self.inspect(changed)

    def test_direction_result_check_and_calls_cannot_change(self):
        image = fixture()
        _, _, size, pos = review.selected(image)[128]
        words = list(struct.unpack_from('<' + 'I' * (size // 4), image, pos))
        selector = next(i for i, w in enumerate(words) if w & 0xfff8001f == 0x36000016)
        self.assertEqual(words[7], 0xaa0403f6)  # preserve requested direction
        self.assertIn(0x6a20011f, words)  # check session success representation
        for index, value in ((selector, words[selector] ^ 0x01000000),
                             (words.index(0x6a20011f), 0x6b00001f)):
            changed = bytearray(image)
            struct.pack_into('<I', changed, pos + index * 4, value)
            with self.assertRaisesRegex(ValueError, 'ephemeral secret encoding/extent changed'):
                self.inspect(changed)
        for index, word in enumerate(words):
            if word & 0xfc000000 == 0x94000000:
                for value in (word + 1, word ^ 0x80000000):
                    changed = bytearray(image)
                    struct.pack_into('<I', changed, pos + index * 4, value)
                    with self.assertRaisesRegex(ValueError, 'ephemeral secret encoding/extent changed'):
                        self.inspect(changed)

    def test_success_returns_clearing_owner_only_after_copy_and_cleanup(self):
        for bits in (128, 192, 256):
            image = fixture()
            _, _, size, pos = review.selected(image)[bits]
            words = list(struct.unpack_from('<' + 'I' * (size // 4), image, pos))
            index = words.index(review.movw(21, 16))
            self.assertEqual(words[index + 1:index + 4], [0xd10143a1, 0xaa1303e0, review.movw(2, 16)])
            self.assertEqual(words[index + 4] & 0xfc000000, 0x94000000)  # copy
            self.assertEqual(words[index + 6], review.movw(1, 16))
            self.assertEqual(words[index + 9], review.movw(1, {128: 176, 192: 208, 256: 240}[bits]))
            self.assertEqual(words[index + 11:index + 13], [0xa900d693, 0x3900029f])
            changed = bytearray(image)
            struct.pack_into('<I', changed, pos + (index + 9) * 4, review.movw(1, 16))
            with self.assertRaisesRegex(ValueError, 'ephemeral secret encoding/extent changed'):
                self.inspect(changed)

    def test_corrupt_dependencies_prevent_pass(self):
        image = fixture()
        constructors = review.prior.prior.prior
        offsets = [0x400, review.prior.selected(image)[128][3],
                   review.prior.prior.selected(image)['secret', 128][3],
                   constructors.selected(image)['copy', 0][3],
                   constructors.sessions.selected(image)['decrypt', 128][3],
                   constructors.sessions.cleanup.select(image)['zeroize'][3]]
        for offset in offsets:
            changed = bytearray(image)
            changed[offset] ^= 1
            with self.assertRaises(ValueError):
                self.inspect(changed)

    def test_invalid_profiles_targets_and_symbols(self):
        args = dict(bits=128, compiler='1.99.1', panic='abort', admission='static', start=4096,
                    expand=8192, encrypt=12288, decrypt=16384, clear=20480, copy=24576)
        for edit in ({'bits': 64}, {'compiler': 'bad'}, {'panic': 'bad'}, {'admission': 'bad'},
                     {'expand': 8193}, {'encrypt': 2**40}, {'decrypt': None}, {'copy': -1}, {'resume': 8192}):
            with self.assertRaises(ValueError):
                review.template(**(args | edit))
        image = fixture()
        for changed in (image.replace(b'9Aes128Key6secret', b'9Aes192Key6secret', 1),
                        image.replace(b'9Aes128Key6secret', b'9Aes064Key6secret', 1)):
            with self.assertRaises(ValueError):
                self.inspect(changed)

    def test_unwind_pad_and_import_are_required(self):
        image = fixture('1.90.0', 'unwind', 'static')
        with patch.object(review.prior.prior.prior.sessions.imports, 'inspect', side_effect=ValueError('bad import')):
            with self.assertRaisesRegex(ValueError, 'bad import'):
                review.inspect(image, '1.90.0', 'unwind', 'static')
        for _, _, size, pos in review.selected(image).values():
            changed = bytearray(image)
            struct.pack_into('<I', changed, pos + size - 4, 0xd65f03c0)
            with self.assertRaisesRegex(ValueError, 'ephemeral secret encoding/extent changed'):
                self.inspect(changed, '1.90.0', 'unwind', 'static')

    def test_cli_identity_configuration_and_failure_output(self):
        image = fixture()
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'secret.macho'
            binary.write_bytes(image)
            command = [sys.executable, str(Path(__file__).with_name('check-aes-apple-linked.py')),
                       str(binary), '--sha256', hashlib.sha256(image).hexdigest(), '--review-ephemeral-secret']
            config = ['--compiler', '1.99.1', '--panic', 'abort', '--admission', 'static']
            result = subprocess.run(command + config, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('ephemeral_secret_callers', result.stdout)
            for args in (command, command + config + ['--review-ephemeral-public'],
                         command + config + ['--sha256', '0' * 64]):
                result = subprocess.run(args, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')
            with self.assertRaises(ValueError):
                runner.check(binary, hashlib.sha256(image).hexdigest(),
                             ephemeral_public=('1.99.1', 'abort', 'static'), ephemeral_secret=('1.99.1', 'abort', 'static'))


if __name__ == '__main__':
    unittest.main()
