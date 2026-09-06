#!/usr/bin/env python3
"""Run the reproducible v0.24.20 portable reference, without publication."""
import argparse
import legacy_acceptance as policy


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    policy.validate(hashes=not args.write)
    policy.execute('python3', 'scripts/legacy-hash/check-legacy-vectors.py')
    policy.execute('cargo', 'run', '--locked', '--offline', '--manifest-path', policy.FIXTURE + '/Cargo.toml')
    policy.execute('cargo', 'test', '--locked', '--offline', '--manifest-path', policy.FIXTURE + '/Cargo.toml')
    if args.write:
        (policy.ROOT / policy.HASHES).write_text(policy.inventory())
    else:
        policy.execute('python3', 'scripts/legacy-hash/check-legacy-package.py', timeout=300)
        policy.execute('python3', 'scripts/legacy-hash/check-legacy-isolation.py', timeout=300)
    print('Frozen SHA-1/MD5 portable reference and mandatory acceptance gates: PASS')


if __name__ == '__main__':
    main()
