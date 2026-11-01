#!/usr/bin/env python3
"""Run only one existing proof group, in a fresh private target directory."""
import argparse
import importlib.util
import json
from pathlib import Path
import re

VERSION, TOOLCHAIN = '0.68.0', '1.90.0'

ROOT = Path(__file__).resolve().parents[2]


def verified(output, count):
    summaries = re.findall(r'^Complete - (\d+) successfully verified harnesses, (\d+) failures, (\d+) total\.$', output, re.M)
    if summaries != [(str(count), '0', str(count))]:
        raise ValueError('Kani did not complete the required proof population')


def execute(component, steps, verifier):
    if not re.fullmatch('[a-z0-9_-]+', component) or not steps:
        raise ValueError('missing explicit proof selection')
    for argv, count in steps:
        if (not isinstance(argv, list) or len(argv) < 2 or argv[0] != '-p'
                or not all(isinstance(arg, str) for arg in argv)
                or '--workspace' in argv or type(count) is not int or count < 1):
            raise ValueError('invalid explicit proof selection')
    with verifier.cargo_environment.private_directory(ROOT) as directory:
        env = verifier.environment(Path(directory))
        env.update(CARGO_NET_OFFLINE='true', RUSTUP_AUTO_INSTALL='0')
        cargo = ['cargo', '+' + TOOLCHAIN, 'kani']
        if verifier.run(cargo + ['--version'], env).strip() != f'Kani Rust Verifier {VERSION} (cargo plugin)\nCBMC 6.11.0':
            raise ValueError('installed Kani/CBMC version differs from binding')
        for argv, count in steps:
            output = verifier.run(cargo + argv, env)
            print(output, flush=True)
            verified(output, count)
    print(f'Scoped Kani {component}: PASS; {sum(n for _, n in steps)} existing bounded proofs', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('component')
    parser.add_argument('--steps-json', required=True, help='explicit registered command/count pairs; never discovers proofs')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('kani_verifier_setup', ROOT / 'scripts/hmac/hmac_verifiers.py')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    execute(args.component, json.loads(args.steps_json), verifier)


if __name__ == '__main__':
    main()
