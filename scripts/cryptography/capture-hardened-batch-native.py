#!/usr/bin/env python3
"""Collect existing hardened-batch runtime checks sequentially; no release gate changes."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import subprocess
import sys

import hardened_batch_native as native


def run(command, env):
    actual = [sys.executable, *command[1:]] if command[0] == 'python3' else command
    result = subprocess.run(actual, cwd=native.ROOT, env=env, text=True, capture_output=True, timeout=1800)
    output = result.stdout + '\n' + result.stderr
    if result.returncode or len(output) > 4_000_000:
        raise RuntimeError(f'capture command failed/oversized: {command}\n{output[-6000:]}')
    return output


def snapshot(env):
    if run(['git', 'status', '--porcelain', '--untracked-files=all'], env).strip():
        raise ValueError('native capture requires a clean committed checkout')
    return tuple(run(['git', 'rev-parse', name], env).strip() for name in ('HEAD', 'HEAD^{tree}'))


def now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def capture(args):
    if not args.attest_native:
        raise ValueError('explicit native operator attestation required')
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('new output path required; never overwrite a capture')
    cpu, features = native.common.native.host(args.lane)
    env = native.common.environment(features)
    for key in tuple(env):
        if key.startswith(('LD_', 'LLVM_PROFILE_')):
            env.pop(key)
    for name in native.suites.REQUIRED:
        env['BRYNJA_REQUIRE_' + name] = '1'
    commit, tree = snapshot(env)
    compiler = run(['rustc', '+1.98.1', '-vV'], env).strip()
    if not {'release: 1.98.1', 'host: ' + native.target(args.lane)} <= set(compiler.splitlines()):
        raise ValueError('native compiler identity mismatch')
    record = dict(schema=1, version='0.24.48', lane=args.lane, commit=commit, tree=tree,
                  compiler=compiler, cpu=cpu, features=features, python=platform.python_version(),
                  started_utc=now(), finished_utc='', results={}, claims=native.CLAIMS.copy())
    for key, command in native.commands(args.lane).items():
        print('NATIVE_RUNTIME_STEP: ' + key, flush=True)
        output = run(command, env)
        native.validate_result(key, output, args.lane)
        record['results'][key] = dict(command=command, exit_code=0, output=output)
    if snapshot(env) != (commit, tree) or native.common.native.host(args.lane) != (cpu, features):
        raise ValueError('checkout or platform changed during capture')
    record['finished_utc'] = now()
    native.validate(record)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as destination:
        json.dump(record, destination, indent=2)
        destination.write('\n')
    print(f'Native hardened batch runtime capture: PASS; {args.lane}; commit={commit}; owner_review=pending')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('lane', choices=native.LANES)
    parser.add_argument('output', type=Path)
    parser.add_argument('--attest-native', action='store_true')
    parser.add_argument('--list', action='store_true', help='show steps without executing or attesting')
    args = parser.parse_args()
    if args.list:
        print(json.dumps(native.commands(args.lane), indent=2))
    else:
        capture(args)
