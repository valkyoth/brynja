"""Independent bounded four-lane vectors; generated only in test directories."""
import hashlib
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ('scripts/sha3/check-cshake-differential.py',
           'scripts/sha3/check-sha3-bit-differential.py',
           'crates/brynja-hash-sha3/tests/vectors/nist-bit-selected.txt',
           'scripts/cryptography/windows_enclave_keccak_simd_oracle.py')


def generate(directory):
    spec = importlib.util.spec_from_file_location('keccak_simd_oracle', ROOT/SOURCES[0])
    custom = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(custom)
    oracle = custom.oracle
    for name, mb, ob, message, expected in oracle.selected_vectors():
        assert oracle.keccak(name, message, mb, ob) == expected
    for rate, ob, expected in (
        (168, 256, 'c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5'),
        (136, 512, 'd008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c'),
    ):
        assert custom.cshake(rate, custom.byte_bits(bytes(range(4))), [],
                             custom.byte_bits(b'Email Signature'), ob).hex() == expected
    names = ('sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'shake128', 'shake256', 'cshake128', 'cshake256')
    rates = (144, 136, 104, 72, 168, 136, 168, 136)
    fixed = (224, 256, 384, 512)
    cases = []
    # Every final bit width at each rate/padding boundary and exact maximum.
    for identity, rate in enumerate(rates, 1):
        for size in (0, 1, rate-1, rate, rate+1, 1023, 1024):
            for last in (range(1, 9) if size else (0,)):
                mb = (size-1)*8+last if size else 0
                lanes = []
                for lane in range(4):
                    ob = fixed[identity-1] if identity <= 4 else (0, 1, rate*8+3, 2048)[lane]
                    nb, sb = ((0, 0), (1, 7), (8, 9), (8191, 8192))[lane] if identity > 6 else (0, 0)
                    lanes.append((identity, mb, nb, sb, ob))
                cases.append(lanes)
    # Mixed rates, identities and unequal lengths; lane data remain distinct.
    for number in range(128):
        lanes = []
        for lane in range(4):
            identity = 1+(number+lane*3)%8
            mb = (0, 1, 7, 8, 575, 1087, 1345, 8192)[(number+lane)%8]
            ob = fixed[identity-1] if identity <= 4 else (0, 7, 8, 9, 255, 257, 2047, 2048)[(number//8+lane)%8]
            nb, sb = ((0, 0), (9, 0), (0, 13), (8192, 8191))[(number+lane)%4] if identity > 6 else (0, 0)
            lanes.append((identity, mb, nb, sb, ob))
        cases.append(lanes)
    rows = []
    for lanes in cases:
        for lane, (identity, mb, nb, sb, ob) in enumerate(lanes):
            message = custom.canonical(11+lane*31, mb)
            name = custom.canonical(19+lane*17, nb)
            label = custom.canonical(23+lane*13, sb)
            if identity > 6:
                expected = custom.cshake(rates[identity-1], custom.byte_bits(message)[:mb],
                    custom.byte_bits(name)[:nb], custom.byte_bits(label)[:sb], ob)
            else:
                expected = oracle.keccak(names[identity-1], message, mb, ob)
                if mb % 8 == 0 and ob % 8 == 0:
                    algorithm = names[identity-1].replace('-', '_').replace('shake128', 'shake_128').replace('shake256', 'shake_256')
                    h = hashlib.new(algorithm, message)
                    assert expected == (h.digest() if identity <= 4 else h.digest(ob//8))
            rows.append(f'{identity} {mb} {message.hex() or "-"} {nb} {name.hex() or "-"} '
                        f'{sb} {label.hex() or "-"} {ob} {expected.hex() or "-"}')
    path = directory/'keccak-simd-vectors.txt'
    path.write_text('\n'.join(rows)+'\n')
    return len(cases)
