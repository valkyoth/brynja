#!/usr/bin/env python3
"""Collect a declared finite set of retained-binary observations; never judge timing.

Trusted local experiment tool, not a sandbox for arbitrary manifests/binaries.
No builds, retries, statistical selection, or publication-gate integration.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

CONTROLS = ('separate-values', 'shared-values', 'separate-identical', 'shared-identical')
COMPILERS = ('1.90.0', '1.99.1')
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'missing/symlinked artifact')
    h = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat()


def write(path, data):
    with path.open('x') as out:
        json.dump(data, out, indent=2, allow_nan=False)
        out.write('\n')


def launches():
    return [(round_, compiler, control) for round_ in range(1, 5)
            for compiler in COMPILERS for control in CONTROLS]


def validate(plan):
    require(plan['schema'] == 1 and plan['rounds'] == 4
            and plan['controls'] == list(CONTROLS)
            and plan['timeout_seconds'] == 180, 'wrong finite policy')
    require(list(plan['binaries']) == list(COMPILERS), 'wrong compiler order')
    require(plan['system'] in ('Linux', 'Darwin'), 'unsupported system')
    require(plan['machine'] == ('aarch64' if plan['system'] == 'Linux' else 'arm64'),
            'wrong architecture')
    require(plan['cpu'] == (0 if plan['system'] == 'Linux' else None), 'wrong affinity')
    for entry in plan['binaries'].values():
        for name in ('binary', 'probe'):
            require(Path(entry[name]).is_absolute(), 'artifact path must be absolute')
            require(digest(entry[name]) == entry[name + '_sha256'], 'artifact hash mismatch')


def execute(command, directory, name, timeout):
    """Retain partial stdout/stderr on timeout; known binaries do not spawn children."""
    started = utc()
    error = None
    code = None
    with (directory / (name + '.stdout')).open('xb') as out, \
            (directory / (name + '.stderr')).open('xb') as err:
        try:
            result = subprocess.run(command, env=ENV, stdout=out, stderr=err,
                                    timeout=timeout, check=False)
            code = result.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            error = type(exc).__name__ + ': ' + str(exc)
    data = {'command': command, 'started': started, 'ended': utc(),
            'returncode': code, 'error': error,
            'stdout_sha256': digest(directory / (name + '.stdout')),
            'stderr_sha256': digest(directory / (name + '.stderr'))}
    write(directory / (name + '.json'), data)
    return data


def collect(plan_path, expected, destination):
    require(digest(plan_path) == expected, 'declaration hash mismatch')
    plan = json.loads(Path(plan_path).read_text())
    require(digest(__file__) == plan['collector_sha256'], 'collector hash mismatch')
    validate(plan)
    require(platform.system() == plan['system'] and platform.machine() == plan['machine'],
            'host mismatch')
    destination = Path(destination)
    destination.mkdir()  # No resume, overwrite, or reuse of an earlier run.
    write(destination / 'declaration.json', plan)
    write(destination / 'host.json', {'started': utc(), 'uname': list(os.uname()),
                                    'environment': ENV, 'declaration_sha256': expected,
                                    'cpuinfo': Path('/proc/cpuinfo').read_text()
                                    if plan['system'] == 'Linux' else None})
    previous = None
    try:
        if plan['cpu'] is not None:
            previous = os.sched_getaffinity(0)
            require(plan['cpu'] in previous, 'declared CPU unavailable')
            os.sched_setaffinity(0, {plan['cpu']})
            require(os.sched_getaffinity(0) == {plan['cpu']}, 'affinity failed')
        for compiler, entry in plan['binaries'].items():
            name = 'probe-' + compiler
            data = execute([entry['probe']], destination, name, 15)
            require(data['returncode'] == 0 and data['error'] is None
                    and (destination / (name + '.stdout')).read_bytes() == b'AES_DIT_HOST_BUNDLE_PASS\n'
                    and not (destination / (name + '.stderr')).read_bytes(), 'capability probe failed')
        for index, (round_, compiler, control) in enumerate(launches(), 1):
            validate(plan)  # Abort on changed identity, never measure replacement bytes.
            entry = plan['binaries'][compiler]
            name = f'{index:02d}-round{round_}-{compiler}-{control}'
            data = execute([entry['binary'], 'measure', control], destination, name, 180)
            validate(plan)
            print(json.dumps({'launch': name, 'returncode': data['returncode'],
                              'error': data['error']}), flush=True)
            # No inspection of timing output. Failures are retained and later
            # planned launches still run; a launch is never retried.
        write(destination / 'complete.json', {'ended': utc(), 'launches': 32,
                                            'notice': 'collection complete; not a timing pass'})
    finally:
        if previous is not None:
            os.sched_setaffinity(0, previous)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('declaration', type=Path)
    parser.add_argument('sha256')
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    try:
        collect(args.declaration, args.sha256, args.destination)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(2, str(exc) + '\n')


if __name__ == '__main__':
    main()
