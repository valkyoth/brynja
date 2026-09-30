"""Independent retained-batch vectors; generated only in the test workspace."""
import hashlib
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/sha3' / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def generate(destination):
    custom = module('batch_cshake_oracle', 'check-cshake-differential.py')
    oracle = custom.oracle
    rows = []

    def add(identity, name, nbits, label, sbits, message, mbits, obits, expected):
        rows.append(f'{identity} {nbits} {name.hex() or "-"} {sbits} '
                    f'{label.hex() or "-"} {mbits} {message.hex() or "-"} '
                    f'{obits} {expected.hex() or "-"}')

    # Cross-check the separately implemented oracle before using its bit cases.
    for algorithm, mbits, obits, message, expected in oracle.selected_vectors():
        if oracle.keccak(algorithm, message, mbits, obits) != expected:
            raise AssertionError('Keccak oracle differs from NIST')
    official = (
        (168, 256, 'c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5'),
        (136, 512, 'd008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c'),
    )
    for rate, obits, expected in official:
        actual = custom.cshake(rate, custom.byte_bits(bytes(range(4))), [],
                               custom.byte_bits(b'Email Signature'), obits)
        if actual.hex() != expected:
            raise AssertionError('cSHAKE oracle differs from NIST')
    for identity, name in enumerate(('sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'shake_128', 'shake_256'), 1):
        algorithm = name.replace('_', '-') if identity <= 4 else name.replace('_', '')
        rate = oracle.RATES[algorithm]
        for length in (0, 1, rate - 1, rate, rate + 1, 1024, 2049):
            message = bytes(i % 251 for i in range(length))
            reference = hashlib.new(name, message)
            expected = reference.digest(333) if identity > 4 else reference.digest()
            if oracle.keccak(algorithm, message, length * 8, len(expected) * 8) != expected:
                raise AssertionError('Keccak oracle differs from hashlib')
            add(identity, b'', 0, b'', 0, message, length * 8, len(expected) * 8, expected)
        for mbits in (1, 7, 9, rate * 8 - 1, rate * 8 + 3):
            for obits in ((0, 1, 7, 257, rate * 8 + 3, 8192) if identity > 4 else (oracle.OUTPUTS[algorithm],)):
                message = custom.canonical(0x33, mbits)
                add(identity, b'', 0, b'', 0, message, mbits, obits,
                    oracle.keccak(algorithm, message, mbits, obits))
    for algorithm, name, nb, label, sb, message, mb, ob, expected in custom.cases():
        add(7 if algorithm == 'cshake128' else 8, name, nb, label, sb, message, mb, ob, expected)
    # Setup beyond one transport snapshot and output at the full retained bound.
    for identity, rate in ((7, 168), (8, 136)):
        nb, sb, mb, ob = 8201, 8197, 13, 8192
        name, label, message = (custom.canonical(seed, bits) for seed, bits in ((1, nb), (2, sb), (3, mb)))
        expected = custom.cshake(rate, custom.byte_bits(message)[:mb],
                                 custom.byte_bits(name)[:nb], custom.byte_bits(label)[:sb], ob)
        add(identity, name, nb, label, sb, message, mb, ob, expected)
    destination.write_text('\n'.join(rows) + '\n')
    return len(rows)
