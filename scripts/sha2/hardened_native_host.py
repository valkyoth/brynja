"""Bounded native-host preflight; never infer CPU support from a build flag."""
import os
import platform
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
FLAGS = '-Zsanitizer=address -C target-feature=+sha,+sse2'
MARKER = 'HARDENED_KERNEL_EXECUTION: X86Sha256; blocks=512'


def clean_environment():
    env = dict(os.environ)
    for key, value in env.items():
        if value and (key in {'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS',
                              'RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
                              'CARGO_BUILD_TARGET', 'CARGO_BUILD_RUSTFLAGS',
                              'CARGO_ENCODED_RUSTDOCFLAGS'} or
                      key.startswith(('CARGO_TARGET_', 'CARGO_PROFILE_', 'ASAN_', 'LSAN_'))):
            raise ValueError('native evidence rejects build override: ' + key)
    return env


def x86_cpuinfo(text):
    rows = [line.split(':', 1)[1].split() for line in text.splitlines()
            if line.split(':', 1)[0].strip() == 'flags' and ':' in line]
    if not rows or any(not {'sha_ni', 'sse2'} <= set(row) for row in rows):
        raise ValueError('every reported x86 CPU must support SHA-NI and SSE2')
    identities = sorted({line.split(':', 1)[1].strip() for line in text.splitlines()
                         if line.startswith('model name') and ':' in line})
    if not identities:
        raise ValueError('missing CPU model identity')
    return '; '.join(identities)


def x86_host():
    if (platform.system(), platform.machine()) != ('Linux', 'x86_64'):
        raise ValueError('hardened x86 ASan requires a native Linux x86_64 SHA-NI runner')
    with Path('/proc/cpuinfo').open() as stream:
        text = stream.read(4 * 1024 * 1024 + 1)
    if len(text) > 4 * 1024 * 1024:
        raise ValueError('CPU identity exceeds bound')
    return x86_cpuinfo(text)


def asan_command():
    return ['cargo', '+nightly-2026-09-11', 'test', '--locked', '--offline',
            '-p', 'brynja-hash-sha2', '-p', 'brynja-crypto-cpu', '--all-features',
            '--lib', 'hardened_execution', '--target', 'x86_64-unknown-linux-gnu',
            '--', '--nocapture', '--test-threads=1']


def execute(command, env, timeout=900):
    # Local trusted tests: spool output to disk and bound its in-memory readback.
    import tempfile
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=output,
                                stderr=subprocess.STDOUT, timeout=timeout)
        output.seek(0)
        text = output.read(4 * 1024 * 1024 + 1)
    if len(text) > 4 * 1024 * 1024:
        raise ValueError('native command output exceeds bound')
    text = text.decode('utf-8')
    if result.returncode:
        raise ValueError('native command failed:\n' + text)
    return text


def validate_asan(text):
    if MARKER not in text.splitlines() or 'test result: ok.' not in text:
        raise ValueError('ASan did not execute the hardened x86 kernel')
