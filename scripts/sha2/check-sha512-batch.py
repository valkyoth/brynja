#!/usr/bin/env python3
"""SHA-512-family batch correctness, package and opt-in native execution evidence."""
import argparse
import os
import re
import sha512_batch_acceptance as acceptance
import sha512_batch_policy as policy


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--package', action='store_true')
    parser.add_argument('--policy-only', action='store_true')
    args = parser.parse_args()
    policy.validate()
    if args.policy_only: return
    env = dict(os.environ, RUSTUP_TOOLCHAIN='1.98.1')
    data, expected = acceptance.corpus()
    acceptance.check(env=env, data=data, expected=expected)
    acceptance.malformed(acceptance.FIXTURE, env)
    if args.native:
        # Required mode is tested only on full-width eligible groups; the first
        # 256 activity-mask batches intentionally include ineligible workloads.
        # Prefer still must execute the final full-width portion through SIMD.
        acceptance.check(env=env, mode='prefer', data=data, expected=expected)
        result = acceptance.run(['cargo', '+1.98.1', 'run', '--locked', '--offline', '--release', '--', 'required'],
            acceptance.FIXTURE, env, '\n'.join(data.splitlines()[256:]) + '\n')
        marker = re.search(r'SHA512_BATCH_ACCEPTANCE: batches=4590; vector_calls=([1-9][0-9]*)\b', result.stderr)
        if result.stdout.splitlines() != expected[256:] or not marker:
            raise ValueError('required SIMD oracle/execution failure')
        print('4590 full-width required SIMD batches: PASS')
    if args.package: acceptance.packaged(env, native=args.native)


if __name__ == '__main__': main()
