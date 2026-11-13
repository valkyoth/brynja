"""Corpus and fail-closed output regressions; mocks never count as AES evidence."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('rv64_corpus', Path(__file__).with_name('aes_riscv_oracle.py'))
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)


class RiscVOracleTests(unittest.TestCase):
    def test_fixed_patterns_sizes_and_determinism(self):
        for bits in (128, 192, 256):
            self.assertEqual(r.sample(bits, 0), bytes(bits // 8))
            self.assertEqual(r.sample(bits, 1), bytes([255]) * (bits // 8))
            self.assertEqual(r.sample(bits, 2), bytes(range(bits // 8)))
            self.assertEqual(len({r.sample(bits, key) for key in range(r.KEYS)}), r.KEYS)
            for index in range(r.KEYS):
                self.assertEqual(len(r.sample(bits, index)), bits // 8)
                self.assertEqual(r.sample(bits, index), r.sample(bits, index))
                for block in range(r.BLOCKS):
                    self.assertEqual(len(r.sample(bits, index, block)), 16)

    def test_batched_answers_keep_both_directions_independent(self):
        calls = []
        def answer(executable, env, bits, key, inputs, inverse):
            calls.append((bits, key, inputs, inverse))
            return bytes([0xde if inverse else 0xec]) * len(inputs)
        with tempfile.TemporaryDirectory() as temporary, patch.object(r, 'answer', side_effect=answer):
            directory = Path(temporary)
            hashes = r.generate(directory, Path('/mock/openssl'), {})
            self.assertEqual(set(hashes), {'oracle128.bin', 'oracle192.bin', 'oracle256.bin'})
            for bits in (128, 192, 256):
                data = (directory / f'tests/fixtures/oracle{bits}.bin').read_bytes()
                size = bits // 8 + 48
                self.assertEqual(len(data), 2048 * size)
                self.assertEqual(hashes[f'oracle{bits}.bin'], r.hashlib.sha256(data).hexdigest())
                for case in range(2048):
                    record = data[case * size:(case + 1) * size]
                    self.assertEqual(record[:bits // 8], r.sample(bits, case // r.BLOCKS))
                    self.assertEqual(record[bits // 8:bits // 8 + 16], r.sample(bits, case // r.BLOCKS, case % r.BLOCKS))
                    self.assertEqual(record[-32:-16], bytes([0xec]) * 16)
                    self.assertEqual(record[-16:], bytes([0xde]) * 16)
        self.assertEqual(len(calls), 3 * r.KEYS * 2)
        for encrypt, decrypt in zip(calls[::2], calls[1::2]):
            self.assertEqual(encrypt[:3], decrypt[:3])
            self.assertEqual((encrypt[3], decrypt[3]), (False, True))

    def test_oracle_exit_length_and_command_are_enforced(self):
        for inverse in (False, True):
            result = subprocess.CompletedProcess([], 0, bytes(32), b'')
            with patch.object(r.subprocess, 'run', return_value=result) as run:
                self.assertEqual(r.answer(Path('/openssl'), {}, 192, bytes(24), bytes(32), inverse), bytes(32))
            self.assertEqual(run.call_args.args[0], ['/openssl', 'enc', '-aes-192-ecb', '-nopad', '-nosalt',
                                                    '-K', bytes(24).hex(), '-d' if inverse else '-e'])
            self.assertTrue(run.call_args.kwargs['check'])
            self.assertEqual(run.call_args.kwargs['timeout'], 15)
        for size in (0, 31, 33):
            with patch.object(r.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, bytes(size), b'')), self.assertRaises(ValueError):
                r.answer(Path('/openssl'), {}, 128, bytes(16), bytes(32), False)
        with patch.object(r.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, ['openssl'])), self.assertRaises(subprocess.CalledProcessError):
            r.answer(Path('/openssl'), {}, 128, bytes(16), bytes(32), False)

    def test_failed_skipped_missing_or_duplicate_results_are_rejected(self):
        valid = '\n'.join([*(f'test {name} ... ok' for name in sorted(r.TESTS)),
            'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;', *r.MARKERS])
        r.check_output(valid)
        for output in ('', valid.replace('... ok', '... ignored', 1), valid.replace('... ok', '... FAILED', 1),
                       valid.replace('4 passed', '3 passed'), valid.replace('0 filtered out', '1 filtered out'),
                       valid + '\ntest aes128_oracle ... ok',
                       valid.replace(r.MARKERS[0], ''), valid + '\n' + r.MARKERS[0]):
            with self.assertRaises(ValueError):
                r.check_output(output)


if __name__ == '__main__':
    unittest.main()
