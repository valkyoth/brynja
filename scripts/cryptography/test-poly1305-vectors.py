"""Offline acceptance fixtures only. Never use this variable-time model with secrets."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / 'crates/brynja-mac-poly1305/tests/data/rfc8439.tsv'
LENGTHS = [34, 64, 375, 375, 127, 16, 16, 48, 48, 16, 64, 48]
IDS = ['2.5.2'] + [f'A.3.{i}' for i in range(1, 12)]


def vectors():
    for line in CORPUS.read_text(encoding='ascii').splitlines():
        label, key, message, tag = line.split('\t')
        yield label, bytes.fromhex(key), bytes.fromhex(message), bytes.fromhex(tag)


def reference(key, message):
    if len(key) != 32:
        raise ValueError('expected a 32-byte one-time key')
    r = int.from_bytes(key[:16], 'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff
    acc = 0
    for start in range(0, len(message), 16):
        block = int.from_bytes(message[start:start + 16] + b'\x01', 'little')
        acc = (acc + block) * r % (2**130 - 5)
    tag = (acc + int.from_bytes(key[16:], 'little')) % 2**128
    return tag.to_bytes(16, 'little')


def boundaries():
    # Deterministic public test inputs, with a distinct key for every message.
    for length in (*range(34), 47, 48, 49, 63, 64, 65, 255, 256, 257, 4096):
        seed = f'brynja-poly1305-test:{length}'.encode('ascii')
        yield (str(length), hashlib.sha256(b'key:' + seed).digest(),
               hashlib.shake_256(b'message:' + seed).digest(length))


class CorpusTests(unittest.TestCase):
    def test_pinned_known_answers(self):
        self.assertEqual(hashlib.sha256(CORPUS.read_bytes()).hexdigest(),
                         '40ccb0876ea63f674eb2be449de9062d8e1971c2857c54d50bf798676da4c452')
        cases = list(vectors())
        self.assertEqual([row[0] for row in cases], IDS)
        self.assertEqual([len(row[2]) for row in cases], LENGTHS)
        for label, key, message, tag in cases:
            with self.subTest(label=label):
                self.assertEqual(len(tag), 16)
                self.assertEqual(reference(key, message), tag)

    def test_clamp_and_empty_message(self):
        key = bytes(range(32))
        masked = bytearray(key)
        for i in (3, 7, 11, 15):
            masked[i] ^= 0xf0
        for i in (4, 8, 12):
            masked[i] ^= 3
        self.assertEqual(reference(key, b''), key[16:])
        self.assertEqual(reference(key, b'clamping'), reference(masked, b'clamping'))


def comparison_records():
    records = list(vectors())
    records.extend((label, k, m, reference(k, m)) for label, k, m in boundaries())
    return records


def compare_openssl():
    records = comparison_records()
    for label, key, message, tag in records:
        # Public fixtures only; OpenSSL is a test executable, not a crate dependency.
        result = subprocess.run(['openssl', 'mac', '-binary', '-macopt',
                                 'hexkey:' + key.hex(), 'POLY1305'],
                                input=message, check=True, capture_output=True, timeout=10)
        if result.stdout != tag:
            raise ValueError(f'OpenSSL disagrees on public vector {label}')
    print(f'OpenSSL matched all {len(records)} public cases.')


def compare_rust(toolchain):
    manifest = ROOT / 'assurance/poly1305/Cargo.toml'
    command = ['cargo', '+' + toolchain, 'run', '--quiet', '--locked', '--offline',
               '--release', '--manifest-path', str(manifest)]
    replay(toolchain, command)


def replay(toolchain, command):
    records = comparison_records()
    def encode(rows):
        return ''.join(f'{k.hex()}\t{m.hex()}\t{t.hex()}\n' for _, k, m, t in rows)
    result = subprocess.run(command, input=encode(records), text=True, capture_output=True,
                            check=True, timeout=180)
    if result.stdout.strip() != f'matched {len(records)} public vectors':
        raise ValueError('Rust consumer did not replay the complete corpus')
    label, key, message, tag = records[-1]
    wrong = bytes([tag[0] ^ 1]) + tag[1:]
    rejected = subprocess.run(command, input=encode([(label, key, message, wrong)]),
                              text=True, capture_output=True, timeout=180)
    if rejected.returncode == 0 or 'vector mismatch or bad input' not in rejected.stderr:
        raise ValueError('Rust consumer did not reject a wrong known answer')
    print(f'Rust {toolchain} matched all {len(records)} public cases and rejected the control.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openssl', action='store_true', help='also compare with OpenSSL 3')
    parser.add_argument('--rust', choices=('1.90.0', '1.100.0'), help='replay through the Rust leaf')
    args = parser.parse_args()
    if not unittest.main(argv=['vectors'], exit=False).result.wasSuccessful():
        raise SystemExit(1)
    if args.openssl:
        compare_openssl()
    if args.rust:
        compare_rust(args.rust)
