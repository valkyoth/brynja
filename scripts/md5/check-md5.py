#!/usr/bin/env python3
"""Run MD5's source contract; --write explicitly refreshes reviewed hashes."""
import argparse
import subprocess
import md5_policy as policy


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    policy.validate(hashes=not args.write)
    subprocess.run(
        ['cargo', 'test', '--locked', '--release', '-p', 'brynja-legacy-md5',
         '--lib', 'invalid_'],
        cwd=policy.ROOT, check=True, timeout=120,
    )
    if args.write:
        destination = policy.ROOT / 'scripts/md5/md5-reviewed.toml'
        destination.write_text(policy.inventory())
    print('isolated legacy MD5 source and mandatory cleanup policy: PASS')


if __name__ == '__main__': main()
