#!/usr/bin/env python3
"""Bind AES differential tests to one recorded local OpenSSL executable.

This records identity, not authenticity. The host, PATH at selection time and
dynamic libraries remain trusted. All keys and blocks here are public fixtures.
"""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SUCCESS = 'AES differential executable identity: unchanged; shared libraries not measured'
FORBIDDEN = ('BRYNJA_OPENSSL', 'OPENSSL_CONF', 'OPENSSL_MODULES', 'OPENSSL_ENGINES',
             'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'OPENSSL_ia32cap')
VECTORS = {
    128: '69c4e0d86a7b0430d8cdb78070b4c55a',
    192: 'dda97ca4864cdfe06eaf70a0ec0d7191',
    256: '8ea2b7ca516745bfeafc49904b496089',
}


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def select(env):
    for name in FORBIDDEN:
        if name in env:
            raise ValueError(f'unexpected oracle environment: {name}')
    selected = shutil.which('openssl', path=env.get('PATH', ''))
    if selected is None:
        raise ValueError('OpenSSL executable unavailable')
    executable = Path(selected).resolve(strict=True)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError('OpenSSL must be an executable regular file')
    return executable


def preflight(executable, env):
    version = subprocess.run([str(executable), 'version'], env=env,
                             check=True, capture_output=True, timeout=15)
    version = version.stdout.decode().strip()
    if not version.startswith('OpenSSL '):
        raise ValueError('unexpected OpenSSL version response')
    print(f'Independent oracle: {version}', flush=True)
    # FIPS 197 examples independently constrain both directions for all widths.
    plain = bytes.fromhex('00112233445566778899aabbccddeeff')
    for bits, ciphertext in VECTORS.items():
        cipher = bytes.fromhex(ciphertext)
        key = bytes(range(bits // 8)).hex()
        for inverse, source, expected in ((False, plain, cipher), (True, cipher, plain)):
            result = subprocess.run(
                [str(executable), 'enc', f'-aes-{bits}-ecb', '-nopad', '-nosalt',
                 '-K', key, '-d' if inverse else '-e'],
                input=source, env=env, check=True, capture_output=True, timeout=15)
            if result.stdout != expected:
                raise ValueError(f'OpenSSL AES-{bits} known-answer mismatch; inverse={inverse}')


def run(suite):
    if suite not in ('128', 'wide'):
        raise ValueError('unknown differential suite')
    env = dict(os.environ)
    executable = select(env)
    before = digest(executable)
    print(f'Independent oracle executable: {executable}', flush=True)
    print(f'Independent oracle SHA-256: {before}', flush=True)
    env.update(BRYNJA_OPENSSL=str(executable), OPENSSL_CONF='/dev/null', RUSTUP_AUTO_INSTALL='0')
    preflight(executable, env)
    target = 'aes128_differential' if suite == '128' else 'aes_wide_differential'
    subprocess.run(
        ['cargo', '+1.99.1', 'test', '--locked', '--offline', '-p', 'brynja-crypto',
         '--no-default-features', '--features', 'hazmat-aes-block', '--test', target,
         '--', '--ignored', '--nocapture'],
        cwd=ROOT, env=env, check=True, timeout=540)
    if digest(executable) != before:
        raise ValueError('OpenSSL executable changed during differential test')
    print(SUCCESS, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('suite', choices=('128', 'wide'))
    run(parser.parse_args().suite)
