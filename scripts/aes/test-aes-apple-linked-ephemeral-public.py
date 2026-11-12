#!/usr/bin/env python3
"""Per-operation public caller admission, expansion, publication and cleanup controls."""
import hashlib
import importlib.util
import itertools
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('ephemeral_public_cached_fixture',
    Path(__file__).with_name('test-aes-apple-linked-cached.py'))
prior = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prior)
runner, BASE = prior.runner, prior.BASE
review = runner.ephemeral_public_review
CONFIGS = tuple(itertools.product(('1.90.0', '1.99.1'), ('abort', 'unwind'), ('static', 'hosted')))
RESUME = prior.prior.prior.RESUME


def fixture(compiler='1.99.1', panic='abort', admission='static'):
    image = prior.fixture(compiler, panic, admission)
    codeinfo, _, symbols = review.mapping.parse(image, symbol_filter=lambda _: True)
    code = bytearray(image[0x400:0x400 + codeinfo['size'] - 4])
    clear = review.prior.prior.sessions.cleanup.select(image)['zeroize'][1]
    kernels = {(r['role'], r['bits']): int(r['address'], 16)
               for r in review.mapping.inspect(image)['bodies']}
    for bits in (128, 192, 256):
        symbol = (f'__ZN30brynja_aes_accelerated_fixture9public{bits}17h{bits:016x}E'
                  if compiler == '1.90.0' else f'__RNvCtest_30brynja_aes_accelerated_fixture9public{bits}')
        address = BASE + 0x400 + len(code)
        symbols.append((symbol, address))
        code.extend(review.template(bits, compiler, panic, admission, address,
                    kernels['expand', bits], kernels['transform', bits], clear,
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
        deltas.extend(prior.prior.prior.prior.fixture_module.uleb(address - previous))
        previous = address
    deltas.append(0)
    image[0x5800:0x5800 + len(deltas)] = deltas
    struct.pack_into('<Q', image, 144, len(code))
    struct.pack_into('<6I', image, 256, 2, 24, 0x4000, len(symbols), 0x4400, len(strings))
    struct.pack_into('<4I', image, 280, 0x26, 16, 0x5800, len(deltas))
    return image


class AppleEphemeralPublicTests(unittest.TestCase):
    def inspect(self, image, compiler='1.99.1', panic='abort', admission='static'):
        # Actual replay and the separate import suite do not mock this boundary.
        with patch.object(review.prior.prior.sessions.imports, 'inspect',
                          return_value={'stub_address': hex(RESUME)}):
            return review.inspect(image, compiler, panic, admission)

    def test_all_profiles_and_widths(self):
        totals = []
        for config in CONFIGS:
            rows = self.inspect(fixture(*config), *config)['ephemeral_public_callers']
            self.assertEqual([r['bits'] for r in rows], [128, 192, 256])
            totals.append(sum(r['size'] for r in rows))
        self.assertEqual(totals, [1460, 1636, 1732, 1852, 1472, 1600, 1168, 1240])

    def test_every_body_byte_in_every_profile(self):
        count = 0
        for config in CONFIGS:
            image = fixture(*config)
            for _, _, size, pos in review.selected(image).values():
                for i in range(size):
                    changed = bytearray(image)
                    changed[pos + i] ^= 1
                    with self.assertRaisesRegex(ValueError, 'ephemeral public encoding/extent changed'):
                        self.inspect(changed, *config)
                    count += 1
        self.assertEqual(count, 12160)

    def test_exact_raw_length_and_expansion_then_revalidation(self):
        image = fixture()
        for bits in (128, 192, 256):
            _, _, size, pos = review.selected(image)[bits]
            words = list(struct.unpack_from('<' + 'I' * (size // 4), image, pos))
            length = words.index(0xf100015f | (bits // 8) << 10)
            expand = next(i for i, w in enumerate(words) if w & 0xfc000000 == 0x94000000)
            self.assertLess(length, expand)
            self.assertEqual(words[expand + 1:expand + 3], [0x39402269, review.movw(8, 2)])
            self.assertEqual(words[expand + 3] & 0xff00001f, 0x34000009)
            changed = bytearray(image)
            struct.pack_into('<I', changed, pos + 4 * length, 0xf100015f | ((bits // 8) + 8) << 10)
            with self.assertRaisesRegex(ValueError, 'ephemeral public encoding/extent changed'):
                self.inspect(changed)

    def test_publication_and_both_clears_follow_encrypt(self):
        image = fixture()
        for bits in (128, 192, 256):
            _, _, size, pos = review.selected(image)[bits]
            words = list(struct.unpack_from('<' + 'I' * (size // 4), image, pos))
            selector = words.index(review.movw(2, 0))
            self.assertEqual(words[selector + 1] & 0xfc000000, 0x94000000)
            self.assertEqual(words[selector + 3], 0x3d8002a0)  # publish to saved destination
            self.assertEqual(words[selector + 5], review.movw(1, 16))
            self.assertEqual(words[selector + 8], review.movw(1, {128: 176, 192: 208, 256: 240}[bits]))
            for index, value in ((selector, review.movw(2, 1)), (selector + 3, 0xd503201f),
                                 (selector + 8, review.movw(1, 16))):
                changed = bytearray(image)
                struct.pack_into('<I', changed, pos + 4 * index, value)
                with self.assertRaisesRegex(ValueError, 'ephemeral public encoding/extent changed'):
                    self.inspect(changed)

    def test_bound_calls_and_dependencies(self):
        image = fixture()
        for _, _, size, pos in review.selected(image).values():
            for offset in range(pos, pos + size, 4):
                word = struct.unpack_from('<I', image, offset)[0]
                if word & 0xfc000000 == 0x94000000:
                    for value in (word + 1, word ^ 0x80000000):
                        changed = bytearray(image)
                        struct.pack_into('<I', changed, offset, value)
                        with self.assertRaisesRegex(ValueError, 'ephemeral public encoding/extent changed'):
                            self.inspect(changed)
        offsets = [0x400, review.prior.selected(image)['public', 128][3],
                   review.prior.prior.selected(image)['raw', 128][3],
                   review.prior.prior.sessions.cleanup.select(image)['zeroize'][3]]
        for offset in offsets:
            changed = bytearray(image)
            changed[offset] ^= 1
            with self.assertRaises(ValueError):
                self.inspect(changed)

    def test_invalid_profiles_targets_and_symbols(self):
        args = dict(bits=128, compiler='1.99.1', panic='abort', admission='static',
                    start=4096, expand=8192, kernel=12288, clear=16384)
        for edit in ({'bits': 64}, {'compiler': 'bad'}, {'panic': 'bad'}, {'admission': 'bad'},
                     {'expand': 8193}, {'kernel': 2**40}, {'clear': None}, {'resume': 8192}):
            with self.assertRaises(ValueError):
                review.template(**(args | edit))
        image = fixture()
        for changed in (image.replace(b'fixture9public128', b'fixture9public192', 1),
                        image.replace(b'fixture9public128', b'fixture9public064', 1)):
            with self.assertRaises(ValueError):
                self.inspect(changed)

    def test_landing_pad_and_unwind_import_are_required(self):
        image = fixture('1.90.0', 'unwind', 'static')
        with patch.object(review.prior.prior.sessions.imports, 'inspect', side_effect=ValueError('bad import')):
            with self.assertRaisesRegex(ValueError, 'bad import'):
                review.inspect(image, '1.90.0', 'unwind', 'static')
        for _, _, size, pos in review.selected(image).values():
            changed = bytearray(image)
            struct.pack_into('<I', changed, pos + size - 4, 0xd65f03c0)
            with self.assertRaisesRegex(ValueError, 'ephemeral public encoding/extent changed'):
                self.inspect(changed, '1.90.0', 'unwind', 'static')

    def test_cli_identity_configuration_and_failure_output(self):
        image = fixture()
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'public.macho'
            binary.write_bytes(image)
            command = [sys.executable, str(Path(__file__).with_name('check-aes-apple-linked.py')),
                       str(binary), '--sha256', hashlib.sha256(image).hexdigest(), '--review-ephemeral-public']
            config = ['--compiler', '1.99.1', '--panic', 'abort', '--admission', 'static']
            result = subprocess.run(command + config, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('ephemeral_public_callers', result.stdout)
            for args in (command, command + config + ['--review-cached'],
                         command + config + ['--sha256', '0' * 64]):
                result = subprocess.run(args, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')
            with self.assertRaises(ValueError):
                runner.check(binary, hashlib.sha256(image).hexdigest(),
                             cached=('1.99.1', 'abort', 'static'), ephemeral_public=('1.99.1', 'abort', 'static'))


if __name__ == '__main__':
    unittest.main()
