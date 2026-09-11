#!/usr/bin/env python3
"""Reproduce ordinary cSHAKE execution vectors using the independent bit oracle."""
import argparse
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'crates/brynja-hash-sha3/tests/vectors/cshake-execution.txt'
spec = importlib.util.spec_from_file_location('cshake_oracle', ROOT / 'scripts/sha3/check-cshake-differential.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def render():
    cases = oracle.cases()
    for algorithm, rate in (('cshake128', 168), ('cshake256', 136)):
        for offset in range(-8, 1):
            for residue in range(8):
                # Prefix bytepad edges, aligned/partial N/S concatenation, multiple
                # prefix blocks, and suffix collisions at every last-byte residue.
                nb = (rate - 6) * 8 + offset
                sb = rate * 8 + residue
                xb = rate * 8 - 8 + residue
                ob = rate * 16 + residue
                n, s, x = (oracle.canonical(seed, bits) for seed, bits in ((11, nb), (22, sb), (33, xb)))
                expected = oracle.cshake(rate, oracle.byte_bits(x)[:xb], oracle.byte_bits(n)[:nb], oracle.byte_bits(s)[:sb], ob)
                cases.append((algorithm, n, nb, s, sb, x, xb, ob, expected))
    official = (
        ('cshake128', 168, 4, 256, 'c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5'),
        ('cshake128', 168, 200, 256, 'c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b'),
        ('cshake256', 136, 4, 512, 'd008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c'),
        ('cshake256', 136, 200, 512, '07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac86430273091727f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb'),
    )
    for algorithm, rate, length, ob, expected in official:
        x, s = bytes(range(length)), b'Email Signature'
        actual = oracle.cshake(rate, oracle.byte_bits(x), [], oracle.byte_bits(s), ob)
        if actual.hex() != expected:
            raise ValueError('independent oracle differs from NIST example')
        cases.append((algorithm, b'', 0, s, len(s)*8, x, length*8, ob, actual))
    if len(cases) != 628:
        raise ValueError('cSHAKE vector coverage changed')
    return '# SP 800-185: four NIST examples plus 624 independent bit-oracle cases.\n' + '\n'.join(
        f'{a} {nb} {n.hex() or "-"} {sb} {s.hex() or "-"} {xb} {x.hex() or "-"} {ob} {expected.hex() or "-"}'
        for a, n, nb, s, sb, x, xb, ob, expected in cases) + '\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    expected = render()
    if args.write:
        PATH.write_text(expected)
    elif PATH.read_text() != expected:
        raise ValueError('cSHAKE execution vector oracle mismatch')
    print('cSHAKE execution: 628 independent/official vectors reproduced')


if __name__ == '__main__':
    main()
