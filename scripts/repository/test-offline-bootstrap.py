#!/usr/bin/env python3
"""Keep the locked workspace fetch ahead of offline assurance consumers."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]


def validate(driver):
    commands = [line.strip() for line in driver.splitlines()
                if line.strip() and not line.lstrip().startswith('#')]
    if commands[:3] != ['set -eu', 'cargo fetch --locked',
                        'python3 scripts/repository/test-offline-bootstrap.py']:
        raise ValueError('repository gate must bootstrap locked dependencies first')


def regressions(driver):
    validate(driver)
    for before, after in (
        ('cargo fetch --locked', ''),
        ('cargo fetch --locked', '# cargo fetch --locked'),
        ('cargo fetch --locked', 'cargo fetch'),
        ('cargo fetch --locked', 'cargo fetch --locked --offline'),
        ('cargo fetch --locked', 'cargo fetch --locked --manifest-path assurance/static-cpu-execution/Cargo.toml'),
        ('cargo fetch --locked', 'cargo fmt --all --check\ncargo fetch --locked'),
        ('set -eu', 'set -u'),
    ):
        if before not in driver:
            raise AssertionError('stale bootstrap mutation')
        try:
            validate(driver.replace(before, after, 1))
        except ValueError:
            continue
        raise AssertionError(f'bootstrap regression accepted: {after}')
    print('Offline bootstrap rejects seven ordering, lock and failure-control regressions')


def cold_cache():
    """Opt-in integration regression; normal CI only runs the cheap policy test."""
    toolchain = tomllib.loads((ROOT / 'rust-toolchain.toml').read_text())['toolchain']['channel']
    cargo = ['cargo', '+' + toolchain]
    with tempfile.TemporaryDirectory(prefix='brynja-offline-bootstrap-') as temporary:
        root = Path(temporary)
        env = dict(os.environ, CARGO_HOME=str(root / 'cargo'),
                   CARGO_TARGET_DIR=str(root / 'target'))
        command = cargo + ['package', '--locked', '--offline', '--allow-dirty',
                           '--no-verify', '-p', 'brynja-crypto-cpu']
        def run(args):
            return subprocess.run(args, cwd=ROOT, env=env, text=True,
                                  capture_output=True, timeout=180)
        lock = (ROOT / 'Cargo.lock').read_bytes()
        missing = run(command)
        if (missing.returncode == 0
                or 'no matching package named `sanitization` found' not in missing.stderr
                or 'offline' not in missing.stderr):
            raise AssertionError('cold cache did not reproduce missing workspace dependency')
        for args in (cargo + ['fetch', '--locked'], command):
            result = run(args)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
        if (ROOT / 'Cargo.lock').read_bytes() != lock:
            raise AssertionError('bootstrap changed the committed dependency lock')
        if not list((root / 'target/package').glob('brynja-crypto-cpu-*.crate')):
            raise AssertionError('offline package archive was not produced')
    print('Cold-cache regression: missing dependency reproduced; locked fetch and offline packaging PASS')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cold-cache', action='store_true')
    args = parser.parse_args()
    regressions((ROOT / 'scripts/checks.sh').read_text())
    if args.cold_cache:
        cold_cache()


if __name__ == '__main__':
    main()
