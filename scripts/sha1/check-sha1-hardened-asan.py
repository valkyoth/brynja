#!/usr/bin/env python3
"""Require native SHA-NI, not a silently portable ASan campaign."""
import os
from pathlib import Path
import hardened_native as native


def main():
    info = Path('/proc/cpuinfo').read_text()
    lane = 'amd-x86_64' if 'AuthenticAMD' in info else 'intel-x86_64'
    _, features = native.host.host(lane)
    env = native.clean_environment()
    env['RUSTFLAGS'] = '-Zsanitizer=address -C target-feature='+features
    env['BRYNJA_REQUIRE_HARDENED_SHA1'] = '1'
    result = native.host.run(['cargo', '+nightly-2026-09-11', 'test', '--locked', '--offline',
        '-p', 'brynja-legacy-sha1', '--features', 'hardened-execution', '--lib', '--test', 'hardened_execution',
        '--target', 'x86_64-unknown-linux-gnu', '--', '--nocapture', '--test-threads=1'], env)
    native.require('HARDENED_SHA1_EXECUTION: legacy-x86-sha1; blocks=512' in result.splitlines(), 'ASan kernel execution')
    native.require('SHA1_HARDENED_OPERATIONAL: legacy-x86-sha1; actual hardened startup and digest passed' in result.splitlines(), 'ASan required route')
    native.require('test result: ok. 4 passed; 0 failed;' in result, 'ASan API coverage')
    print(result)
    print('Native SHA-1 hardened ASan: PASS; leak configuration: '+os.environ.get('ASAN_OPTIONS', 'default'))


if __name__ == '__main__': main()
