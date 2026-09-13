#!/usr/bin/env python3
"""Explicit hardened legacy execution policy and package acceptance."""
import argparse
import subprocess
import hardened_policy as policy


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--policy-only', action='store_true')
    args = parser.parse_args()
    policy.validate(reviewed=not args.write)
    if args.write: (policy.ROOT / policy.REVIEW).write_text(policy.render())
    if not args.policy_only:
        for command in (
            ['python3', 'scripts/sha1/test-sha1-hardened-native.py'],
            ['python3', 'scripts/sha1/test-sha1-hardened-ci.py'],
            ['cargo', 'test', '--locked', '--offline', '-p', 'brynja-legacy-sha1', '--all-features', '--lib', '--test', 'hardened_execution'],
            ['cargo', 'test', '--locked', '--offline', '-p', 'brynja-legacy-sha1', '--all-features', '--doc'],
            ['cargo', 'test', '--locked', '--offline', '-p', 'brynja-legacy-sha1-std', '--all-features', '--test', 'hardened_execution', '--lib'],
            ['python3', 'scripts/sha1/check-sha1-package.py', '--hardened'],
            ['cargo', 'clippy', '--locked', '--offline', '-p', 'brynja-legacy-sha1', '-p', 'brynja-legacy-sha1-std', '--all-features', '--all-targets', '--', '-A', 'clippy::chunks_exact_to_as_chunks', '-D', 'warnings'],
        ):
            subprocess.run(command, cwd=policy.ROOT, check=True, timeout=300)
    print('Hardened legacy SHA-1 execution: PASS; seven owned regions; native qualification is separate')


if __name__ == '__main__': main()
