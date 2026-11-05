#!/usr/bin/env python3
"""Execute five exact production AES field/index/admission proofs; no full AES claim."""
import argparse
from pathlib import Path
import re
import sys
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hmac'))
import hmac_verifiers as verifier

HARNESSES = ('multiplication_matches_polynomial_reduction',
             'shift_indices_are_bounded_inverse_permutations',
             'admitted_round_key_indices_are_exact_and_bounded',
             'wide_parameter_admission_is_exact',
             'wide_schedule_indices_reference_initialized_words')
SUMMARY = 'Complete - 1 successfully verified harnesses, 0 failures, 1 total.'
MARKER = 'AES field/layout: PASS; 5 proofs; not full AES or constant-time proof'


def policy():
    directory = verifier.ROOT / 'assurance/aes-policy'
    manifest = tomllib.loads((directory / 'Cargo.toml').read_text())
    package = {'name': 'brynja-aes-policy-fixture', 'version': '0.0.0',
               'edition': '2024', 'rust-version': '1.90', 'publish': False}
    if (set(manifest) != {'package', 'workspace', 'lints'}
            or manifest['package'] != package or manifest['workspace'] != {}):
        raise ValueError('AES proof fixture must remain dependency-free')
    lock = tomllib.loads((directory / 'Cargo.lock').read_text())
    if lock != {'version': 4, 'package': [{'name': package['name'], 'version': '0.0.0'}]}:
        raise ValueError('AES proof lock identity changed')
    source = (directory / 'src/lib.rs').read_text()
    names = re.findall(r'#\[kani::proof\]\s+(?:#\[kani::unwind\(\d+\)\]\s+)?fn ([a-z_]+)\(\)', source)
    if tuple(names) != HARNESSES or source.count('#[kani::proof]') != 5:
        raise ValueError('AES proof population drift')
    for name in ('field', 'layout'):
        if f'#[path = "../../../crates/brynja-crypto/src/aes/portable/{name}.rs"]\nmod {name};' not in source:
            raise ValueError('AES proofs must compile the production source')


def successful(output):
    # Reject zero/duplicate summaries or any unexpected harness population.
    summaries = [line.strip() for line in output.splitlines() if line.startswith('Complete - ')]
    return summaries == [SUMMARY] and 'VERIFICATION:- FAILED' not in output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy-only', action='store_true')
    args = parser.parse_args()
    policy()
    if args.policy_only:
        print('AES field/layout inventory: 5 proofs; NOT executed')
        return
    pin = verifier.tool('kani')
    with verifier.cargo_environment.private_directory(verifier.ROOT) as temporary:
        env = verifier.environment(Path(temporary))
        env.update(CARGO_NET_OFFLINE='true', RUSTUP_AUTO_INSTALL='0')
        cargo = ['cargo', '+' + pin['execution_toolchain'], 'kani']
        banner = verifier.run([*cargo, '--version'], env).strip()
        if banner != f'Kani Rust Verifier {pin["version"]} (cargo plugin)\nCBMC 6.11.0':
            raise ValueError('Kani binary identity differs from repository pin')
        for name in HARNESSES:
            output = verifier.run([*cargo, '--manifest-path', 'assurance/aes-policy/Cargo.toml',
                                   '--harness', 'proofs::' + name, '--exact'], env)
            print(output, flush=True)
            if not successful(output):
                raise ValueError('Expected exactly one verified AES harness')
        print(MARKER)


if __name__ == '__main__':
    main()
