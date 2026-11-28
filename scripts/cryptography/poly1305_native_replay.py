"""Reproduce the native Poly1305 MAC + paired AEAD artifact observations (public data only)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import runpy
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
VERSIONS = ('1.90.0', '1.100.0')
TARGETS = {
    'x86_64-unknown-linux-gnu': ('Linux', 'x86_64', 'native-owner', 'integrated_vectors', 'paired-x86'),
    'aarch64-unknown-linux-musl': ('Linux', 'aarch64', 'neon-owner', 'neon_vectors', 'paired-neon'),
    'aarch64-apple-darwin': ('Darwin', 'arm64', 'neon-owner', 'neon_vectors', 'paired-neon'),
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(target, directory):
    _, _, feature, test, pair = TARGETS[target]
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ, CARGO_TARGET_DIR=tmp, CARGO_BUILD_BUILD_DIR=tmp + '/build')
        for version in VERSIONS:
            for kind, project, flags in [
                ('vectors', 'poly1305', ['test', '--no-run', '--test', test, '--features', feature]),
                ('paired', 'chacha20poly1305', ['build', '--bin', 'chacha20poly1305-rfc-replay', '--features', pair]),
            ]:
                cmd = ['cargo', '+' + version, *flags, '--locked', '--offline', '--release', '--target', target,
                       '--manifest-path', str(ROOT / 'assurance' / project / 'Cargo.toml'), '--message-format=json']
                result = subprocess.check_output(cmd, env=env, text=True, timeout=300)
                records = map(json.loads, result.splitlines())
                name = test if kind == 'vectors' else 'chacha20poly1305-rfc-replay'
                exe, = [r['executable'] for r in records if r.get('reason') == 'compiler-artifact'
                        and r['target']['name'] == name and r.get('executable')]
                shutil.copy2(exe, directory / f'{kind}-{version}')


def corpus(directory):
    vectors = runpy.run_path(str(ROOT / 'scripts/cryptography/check-chacha20poly1305-vectors.py'))
    for name, rows in [('rfc', vectors['records']()), ('oracle', vectors['differential_rows'](True))]:
        (directory / name).write_bytes(b''.join(
            ('\t'.join(v.hex() for v in row) + '\n').encode('ascii') for row in rows))


def replay(target, directory):
    if (platform.system(), platform.machine()) != TARGETS[target][:2]:
        raise ValueError('execute on the named platform')
    for version in VERSIONS:
        mac, pair = [directory / f'{k}-{version}' for k in ('vectors', 'paired')]
        before = [digest(mac), digest(pair)]
        output = subprocess.check_output([mac, '--exact', 'rfc_and_partitioned_long_updates'], text=True, timeout=120)
        if 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' not in output:
            raise ValueError('missing production MAC vector test')
        for name, flags, marker in [('rfc', [], 'matched 2 RFC AEAD records'),
                                    ('oracle', ['--differential'], 'matched 848 differential AEAD records')]:
            path = directory / name
            expected = {'rfc': '0a86c4fda6371e7501e1d244d68facdb221d4f901b8aaded6b33abbe65745b62',
                        'oracle': '22e6e7072138575ba58beb6ae90b58609efae7d052f34a1125fc08b6999fd683'}
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != expected[name]:
                raise ValueError('public test corpus changed')
            if subprocess.check_output([pair, *flags], input=data, timeout=120).strip() != marker.encode():
                raise ValueError('missing paired AEAD replay')
            # A syntactically valid but incorrect tag must fail for the right reason.
            fields = data.splitlines()[-1].split(b'\t')
            fields[-1] = (bytes([int(fields[-1][:2], 16) ^ 1]).hex().encode() + fields[-1][2:])
            bad = subprocess.run([pair, *flags], input=b'\t'.join(fields) + b'\n', capture_output=True, timeout=30)
            reason = b'AEAD differential mismatch' if flags else b'RFC record mismatch'
            if (bad.returncode, bad.stdout, bad.stderr.strip()) != (1, b'', b'Error: "' + reason + b'"'):
                raise ValueError('paired AEAD wrong-tag control failed')
        if before != [digest(mac), digest(pair)]:
            raise ValueError('binary changed during replay')
        print(target, version, *before, flush=True)


if __name__ == '__main__':
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('mode', choices=('build', 'corpus', 'replay'))
    cli.add_argument('target', choices=TARGETS)
    cli.add_argument('directory', type=Path)
    args = cli.parse_args()
    directory = args.directory.resolve(strict=True)
    if args.mode == 'corpus':
        corpus(directory)
    elif args.mode == 'build':
        build(args.target, directory)
    else:
        replay(args.target, directory)
