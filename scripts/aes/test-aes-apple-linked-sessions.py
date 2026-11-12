#!/usr/bin/env python3
"""Exact session admission/direction/landing-pad and bound-call controls."""
import importlib.util
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('session_cleanup_fixture',
    Path(__file__).with_name('test-aes-apple-linked-cleanup.py'))
prior = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prior)
review = prior.runner.sessions_review
RESUME = prior.fixture_module.BASE + 0xe00


def fixture(compiler, panic, admission):
    image, _ = prior.fixture(compiler, panic)
    extra = []
    for role in prior.review.ROLES:
        name, _, size, pos = prior.review.select(image)[role]
        raw = bytes(image[pos:pos + size])
        extra.append((name, lambda address, raw=raw: raw))
    kernels = {b['bits']: int(b['address'], 16) for b in review.mapping.inspect(image)['bodies']
               if b['role'] == 'transform'}
    for direction in ('encrypt', 'decrypt'):
        for bits in (128, 192, 256):
            symbol = (f'__ZN17brynja_crypto_cpu3aes7Session10{direction}{bits}17h{bits:016x}E'
                      if compiler == '1.90.0' else
                      f'__RNvMs0_NtCtest_17brynja_crypto_cpu3aesNtB5_7Session10{direction}{bits}')
            extra.append((symbol, lambda address, direction=direction, bits=bits:
                          review.template(compiler, panic, admission, direction, address, kernels[bits],
                                          RESUME if (compiler, panic) == ('1.90.0', 'unwind') else None)))
    return prior.fixture_module.fixture(compiler == '1.90.0', extra)


class AppleSessionTests(unittest.TestCase):
    def test_cli_session_configuration_hash_and_failure_output(self):
        image, _ = fixture('1.99.1', 'abort', 'static')
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'consumer.macho'
            binary.write_bytes(image)
            command = [sys.executable, str(Path(__file__).with_name('check-aes-apple-linked.py')),
                       str(binary), '--sha256', hashlib.sha256(image).hexdigest(), '--review-sessions']
            config = ['--compiler', '1.99.1', '--panic', 'abort', '--admission', 'static']
            result = subprocess.run(command + config, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('"sessions":', result.stdout)
            for args in (command, command + config + ['--review-cleanup'],
                         command + config + ['--sha256', '0' * 64]):
                result = subprocess.run(args, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, '')

    def inspect(self, image, compiler, panic, admission):
        # Synthetic session images do not fabricate a complete runtime. The
        # separate import suite tests full Mach-O binding; real replay combines both.
        with patch.object(review.imports, 'inspect', return_value={'stub_address': hex(RESUME)}) as imported:
            result = review.inspect(image, compiler, panic, admission)
            self.assertEqual(imported.call_count, int((compiler, panic) == ('1.90.0', 'unwind')))
            return result

    def test_all_profiles_widths_and_directions(self):
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                for admission in ('static', 'hosted'):
                    result = self.inspect(fixture(compiler, panic, admission)[0], compiler, panic, admission)
                    expected = (148 if admission == 'static' else 168) if (compiler, panic) == ('1.90.0', 'unwind') else (
                        (108 if admission == 'static' else 128) if compiler == '1.90.0' else
                        (104 if admission == 'static' else 120))
                    self.assertEqual(len(result['sessions']), 6)
                    self.assertEqual({r['size'] for r in result['sessions']}, {expected})

    def test_every_session_byte_in_every_profile(self):
        count = 0
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                for admission in ('static', 'hosted'):
                    image, bodies = fixture(compiler, panic, admission)
                    for pos, size in bodies[-6:]:
                        for i in range(size):
                            changed = bytearray(image)
                            changed[pos + i] ^= 1
                            with self.assertRaisesRegex(ValueError, 'session encoding/extent changed'):
                                self.inspect(changed, compiler, panic, admission)
                            count += 1
        self.assertEqual(count, 6000)

    def test_direction_and_call_words_are_not_wildcards(self):
        encrypt = review.template('1.99.1', 'abort', 'static', 'encrypt', 0x1000, 0x2000)
        decrypt = review.template('1.99.1', 'abort', 'static', 'decrypt', 0x1000, 0x2000)
        differences = [(i, a, b) for i, (a, b) in enumerate(zip(encrypt, decrypt)) if a != b]
        self.assertEqual(differences, [(52, 2, 34)])
        image, _ = fixture('1.99.1', 'abort', 'static')
        row = review.selected(image)['encrypt', 128]
        altered = bytearray(image)
        # The single BL must not call the next instruction in the kernel.
        struct.pack_into('<I', altered, row[3] + 56,
                         struct.unpack_from('<I', image, row[3] + 56)[0] + 1)
        with self.assertRaisesRegex(ValueError, 'session encoding/extent changed'):
            self.inspect(altered, '1.99.1', 'abort', 'static')

    def test_unwind_import_failure_cannot_be_ignored(self):
        image, _ = fixture('1.90.0', 'unwind', 'static')
        with patch.object(review.imports, 'inspect', side_effect=ValueError('bad import')), self.assertRaisesRegex(ValueError, 'bad import'):
            review.inspect(image, '1.90.0', 'unwind', 'static')
        with patch.object(review.imports, 'inspect', return_value={'stub_address': hex(RESUME + 4)}), self.assertRaisesRegex(ValueError, 'session encoding/extent changed'):
            review.inspect(image, '1.90.0', 'unwind', 'static')

    def test_profile_direction_and_call_range_rejection(self):
        for config in (('bad', 'abort', 'static', 'encrypt'), ('1.99.1', 'bad', 'static', 'encrypt'),
                       ('1.99.1', 'abort', 'static', 'bad')):
            with self.assertRaises(ValueError):
                review.template(*config, 0x1000, 0x2000)
        for target in (0x2001, 2**40):
            with self.assertRaises(ValueError):
                review.template('1.99.1', 'abort', 'static', 'encrypt', 0x1000, target)
        with self.assertRaises(ValueError):
            review.template('1.90.0', 'unwind', 'static', 'encrypt', 0x1000, 0x2000)

    def test_missing_roles_and_aliases_fail(self):
        image, _ = fixture('1.99.1', 'abort', 'static')
        changed = image.replace(b'encrypt128', b'encrypt192', 1)
        with self.assertRaises(ValueError):
            self.inspect(changed, '1.99.1', 'abort', 'static')
        changed = bytearray(image)
        struct.pack_into('<I', changed, 268, 14)
        with self.assertRaises(ValueError):
            self.inspect(changed, '1.99.1', 'abort', 'static')

    def test_corrupt_cleanup_or_kernel_prevents_session_pass(self):
        image, _ = fixture('1.99.1', 'abort', 'static')
        for pos in (0x400, prior.review.select(image)['zeroize'][3]):
            changed = bytearray(image)
            changed[pos] ^= 1
            with self.assertRaises(ValueError):
                self.inspect(changed, '1.99.1', 'abort', 'static')

    def test_unwind_body_contains_quarantine_after_return(self):
        image, _ = fixture('1.90.0', 'unwind', 'hosted')
        row = review.selected(image)['encrypt', 128]
        changed = bytearray(image)
        # Remove quarantine's generation store, after the normal return.
        struct.pack_into('<I', changed, row[3] + row[2] - 8, 0xd503201f)
        with self.assertRaisesRegex(ValueError, 'session encoding/extent changed'):
            self.inspect(changed, '1.90.0', 'unwind', 'hosted')


if __name__ == '__main__':
    unittest.main()
