#!/usr/bin/env python3
"""Short native CI regression lane, not release/platform qualification."""
import argparse
import platform
from pathlib import Path
import hardened_native as native


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('architecture', choices=('x86_64', 'aarch64'))
    args = parser.parse_args()
    native.require(platform.system() == 'Linux' and platform.machine() == args.architecture,
                   'CI runner architecture mismatch')
    if args.architecture == 'x86_64':
        info = Path('/proc/cpuinfo').read_text()
        lane = 'amd-x86_64' if 'AuthenticAMD' in info else 'intel-x86_64'
    else:
        # Reuse the Linux feature-bundle validator only, not an AWS attestation.
        lane = 'aws-aarch64'
    _, features = native.host.host(lane)
    env = native.clean_environment()
    env.update(RUSTFLAGS='-C target-feature='+features, BRYNJA_REQUIRE_HARDENED_SHA1='1')
    output = native.host.run(['cargo', '+1.98.1', 'test', '--locked', '--release',
        '-p', 'brynja-legacy-sha1', '--features', 'hardened-execution', '--lib',
        '--test', 'hardened_execution', '--', '--nocapture', '--test-threads=1'], env)
    kernel = 'legacy-x86-sha1' if args.architecture=='x86_64' else 'legacy-aarch64-sha1'
    native.require(f'HARDENED_SHA1_EXECUTION: {kernel}; blocks=512' in output.splitlines(), 'CI actual kernel')
    native.require(f'SHA1_HARDENED_OPERATIONAL: {kernel}; actual hardened startup and digest passed' in output.splitlines(), 'CI accelerated API')
    native.require('test result: ok. 4 passed; 0 failed;' in output, 'CI API coverage')
    print(output)
    print('Hardened SHA-1 native CI: PASS; correctness regression, not migration or release qualification')


if __name__ == '__main__': main()
