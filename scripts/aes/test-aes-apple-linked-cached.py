#!/usr/bin/env python3
"""Cached caller publication, admission, direction, cleanup and binding controls."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('cached_constructor_fixture',
    Path(__file__).with_name('test-aes-apple-linked-constructors.py'))
prior = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prior)
runner, BASE = prior.runner, prior.BASE
review = runner.cached_review


def fixture(compiler='1.99.1', panic='abort', admission='static'):
    image = prior.fixture(compiler, panic, admission)
    codeinfo, _, symbols = review.mapping.parse(image, symbol_filter=lambda _: True)
    code = bytearray(image[0x400:0x400 + codeinfo['size'] - 4])
    clear = review.prior.sessions.cleanup.select(image)['zeroize'][1]
    kernels = {r['bits']: int(r['address'], 16) for r in review.mapping.inspect(image)['bodies'] if r['role'] == 'transform'}
    copy = review.prior.selected(image)['copy', 0][1]
    for kind in ('public', 'secret'):
        for bits in (128, 192, 256):
            suffix = f'17Aes{bits}ExpandedKey' + ('20encrypt_block_public' if kind == 'public' else '6secret')
            symbol = ('__ZN13brynja_crypto3aes9execution' + suffix + f'17h{bits:016x}E'
                      if compiler == '1.90.0' else '__RNvMsa_NtNtCtest_13brynja_crypto3aes9executionNtB5_' + suffix)
            address = BASE + 0x400 + len(code)
            symbols.append((symbol, address))
            code.extend(review.template(kind, bits, compiler, panic, admission, address, kernels[bits], clear,
                        copy if kind == 'secret' else None,
                        prior.prior.RESUME if (compiler, panic) == ('1.90.0', 'unwind') else None))
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
        deltas.extend(prior.prior.prior.fixture_module.uleb(address - previous))
        previous = address
    deltas.append(0)
    image[0x5800:0x5800 + len(deltas)] = deltas
    struct.pack_into('<Q', image, 144, len(code))
    struct.pack_into('<6I', image, 256, 2, 24, 0x4000, len(symbols), 0x4400, len(strings))
    struct.pack_into('<4I', image, 280, 0x26, 16, 0x5800, len(deltas))
    return image


class AppleCachedTests(unittest.TestCase):
    def inspect(self, image, compiler='1.99.1', panic='abort', admission='static'):
        # Full static import parsing is covered separately and by actual replay.
        with patch.object(review.prior.sessions.imports, 'inspect', return_value={'stub_address': hex(prior.prior.RESUME)}):
            return review.inspect(image, compiler, panic, admission)

    def test_all_configurations_and_widths(self):
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                for admission in ('static', 'hosted'):
                    config = compiler, panic, admission
                    rows = self.inspect(fixture(*config), *config)['cached_callers']
                    self.assertEqual(len(rows), 6)
                    sizes = (320, 404) if (compiler, panic) == ('1.90.0', 'unwind') else (
                        (208, 304) if compiler == '1.90.0' else (204, 304))
                    extra = (20 if compiler == '1.90.0' else 16) * (admission == 'hosted')
                    for row in rows:
                        self.assertEqual(row['size'], sizes[row['kind'] == 'secret'] + extra)

    def test_every_caller_byte_in_every_profile(self):
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
                            with self.assertRaisesRegex(ValueError, 'cached caller encoding/extent changed'):
                                self.inspect(changed, *config)
                            count += 1
        self.assertEqual(count, 13944)

    def test_public_encrypt_selector_and_staged_publication(self):
        image = fixture()
        for bits in (128, 192, 256):
            _, _, size, pos = review.selected(image)['public', bits]
            words = struct.unpack_from('<' + str(size // 4) + 'I', image, pos)
            self.assertEqual(words[14], 0xf100015f | {128: 176, 192: 208, 256: 240}[bits] << 10)
            self.assertEqual(words[25], review.movw(2, 0))
            self.assertEqual(words[26] & 0xfc000000, 0x94000000)
            self.assertEqual(words[27:29], (0x3dc003e0, 0x3d800260))  # publish only after transform
            changed = bytearray(image)
            struct.pack_into('<I', changed, pos + 25 * 4, review.movw(2, 1))
            with self.assertRaisesRegex(ValueError, 'cached caller encoding/extent changed'):
                self.inspect(changed)

    def test_secret_clear_precedes_admission_and_direction_reaches_kernel(self):
        image = fixture()
        _, _, size, pos = review.selected(image)['secret', 128]
        words = struct.unpack_from('<' + str(size // 4) + 'I', image, pos)
        self.assertEqual(words[13] & 0xfc000000, 0x94000000)  # clear
        self.assertEqual(words[15], 0x39402109)  # health read
        self.assertEqual(words[33], 0xaa1503e2)  # bool selector x21 -> x2
        changed = bytearray(image)
        struct.pack_into('<I', changed, pos + 33 * 4, review.movw(2, 0))
        with self.assertRaisesRegex(ValueError, 'cached caller encoding/extent changed'):
            self.inspect(changed)

    def test_calls_cannot_retarget_or_change_kind(self):
        image = fixture()
        for kind in ('public', 'secret'):
            _, _, size, pos = review.selected(image)[kind, 128]
            for offset in range(pos, pos + size, 4):
                word = struct.unpack_from('<I', image, offset)[0]
                if word & 0xfc000000 != 0x94000000:
                    continue
                for new in (word + 1, word ^ 0x80000000):
                    changed = bytearray(image)
                    struct.pack_into('<I', changed, offset, new)
                    with self.assertRaisesRegex(ValueError, 'cached caller encoding/extent changed'):
                        self.inspect(changed)

    def test_corrupt_dependencies_prevent_pass(self):
        image = fixture()
        offsets = [0x400, review.prior.sessions.cleanup.select(image)['zeroize'][3],
                   review.prior.sessions.selected(image)['encrypt', 128][3],
                   review.prior.selected(image)['raw', 128][3], review.prior.selected(image)['copy', 0][3]]
        for offset in offsets:
            changed = bytearray(image)
            changed[offset] ^= 1
            with self.assertRaises(ValueError):
                self.inspect(changed)

    def test_invalid_profiles_roles_and_targets(self):
        args = dict(kind='public', bits=128, compiler='1.99.1', panic='abort', admission='static',
                    start=4096, kernel=8192, clear=12288)
        for edit in ({'kind': 'bad'}, {'bits': 64}, {'compiler': 'bad'}, {'panic': 'bad'},
                     {'admission': 'bad'}, {'kernel': 8193}, {'clear': 2**40}, {'copy': 8192},
                     {'resume': 8192}, {'kind': 'secret'}):
            with self.assertRaises(ValueError):
                review.template(**(args | edit))
        image = fixture()
        for changed in (image.replace(b'17Aes128ExpandedKey6secret', b'17Aes192ExpandedKey6secret', 1),
                        image.replace(b'20encrypt_block_public', b'20encrypt_block_badxxx', 1)):
            with self.assertRaises(ValueError):
                self.inspect(changed)

    def test_unwind_import_and_landing_pad_are_required(self):
        image = fixture('1.90.0', 'unwind', 'static')
        with patch.object(review.prior.sessions.imports, 'inspect', side_effect=ValueError('bad import')):
            with self.assertRaisesRegex(ValueError, 'bad import'):
                review.inspect(image, '1.90.0', 'unwind', 'static')
        for kind in ('public', 'secret'):
            _, _, size, pos = review.selected(image)[kind, 128]
            changed = bytearray(image)
            struct.pack_into('<I', changed, pos + size - 4, 0xd65f03c0)
            with self.assertRaisesRegex(ValueError, 'cached caller encoding/extent changed'):
                self.inspect(changed, '1.90.0', 'unwind', 'static')

    def test_cli_identity_config_and_failure_output(self):
        image = fixture()
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'cached.macho'
            binary.write_bytes(image)
            command = [sys.executable, str(Path(__file__).with_name('check-aes-apple-linked.py')),
                       str(binary), '--sha256', hashlib.sha256(image).hexdigest(), '--review-cached']
            config = ['--compiler', '1.99.1', '--panic', 'abort', '--admission', 'static']
            result = subprocess.run(command + config, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('"cached_callers":', result.stdout)
            for args in (command, command + config + ['--review-constructors'],
                         command + config + ['--sha256', '0' * 64]):
                result = subprocess.run(args, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
