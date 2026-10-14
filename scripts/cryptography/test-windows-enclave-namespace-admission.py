#!/usr/bin/env python3
"""Native exclusive-link, bounded-collision and entropy-failure regressions."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'crates/brynja-crypto-cpu-std/src/windows_enclave/native/namespace.rs'
FIXTURE = ROOT / 'assurance/windows-enclave-probe/namespace_admission.rs'
MAIN = '''#![allow(dead_code)]
#[derive(Debug)] enum Error { Image, Bounds, Platform }
mod sys {
    #[link(name="kernel32")]
    unsafe extern "system" { fn CloseHandle(handle: *mut core::ffi::c_void) -> i32; }
    pub fn close(handle: *mut core::ffi::c_void) { assert_ne!(unsafe { CloseHandle(handle) }, 0); }
}
mod namespace;
fn main() { namespace::probe(); }
'''


def fixture(source):
    call = 'unsafe { BCryptGenRandom(core::ptr::null_mut(), nonce.as_mut_ptr(), 16, 2) }'
    if source.count(call) != 1:
        raise ValueError('entropy injection anchor changed')
    return source.replace(call, 'entropy(core::ptr::null_mut(), nonce.as_mut_ptr(), 16, 2)') + FIXTURE.read_text()


def run():
    if os.name != 'nt':
        raise RuntimeError('native Windows required; no skipped pass')
    source = fixture(SOURCE.read_text())
    cases = [('normal', source, ('retry', 'exhausted', 'entropy-failure'))]
    for label, before, after, mode in (
        ('nonexclusive', 'flags: 0x60,', 'flags: 0x40,', 'retry'),
        ('no-retry', 'for _ in 0..4 {', 'for _ in 0..1 {', 'retry'),
        ('unbounded-budget', 'for _ in 0..4 {', 'for _ in 0..5 {', 'exhausted'),
        ('ignore-entropy', ', 16, 2) != 0 {', ', 16, 2) == 0 {', 'entropy-failure'),
    ):
        if source.count(before) != 1:
            raise ValueError('mutant anchor changed: ' + label)
        cases.append((label, source.replace(before, after), (mode,)))
    with tempfile.TemporaryDirectory(prefix='brynja-namespace-admission-') as directory:
        root = Path(directory)
        (root / 'main.rs').write_text(MAIN)
        for level in ('0', '2'):
            for label, content, modes in cases:
                (root / 'namespace.rs').write_text(content)
                exe = root / f'{label}-{level}.exe'
                subprocess.run(['rustc', '+1.98.1', '--edition=2024', '-Dwarnings',
                                '-C', 'opt-level=' + level, str(root / 'main.rs'), '-o', str(exe)],
                               check=True, timeout=90, stdout=sys.stdout, stderr=sys.stderr)
                for mode in modes:
                    result = subprocess.run([str(exe), mode], capture_output=True, text=True, timeout=30)
                    expected = 0 if label == 'normal' else 101
                    if result.returncode != expected or (expected and 'panicked at' not in result.stderr):
                        raise AssertionError(f'{label} O{level} {mode}\n{result.stdout}{result.stderr}')
                    reasons = {'nonexclusive': 'sibling open check failed',
                               'no-retry': 'collision retry did not create fresh alias',
                               'unbounded-budget': 'collision attempts not bounded',
                               'ignore-entropy': 'entropy failure did not reject before creating alias'}
                    if expected and reasons[label] not in result.stderr:
                        raise AssertionError('mutant failed for unrelated reason: ' + result.stderr)
                    if not expected and f'NAMESPACE_ADMISSION: {mode}: PASS' not in result.stdout:
                        raise AssertionError('missing completion marker')
                    print(f'Namespace admission: O{level} {label} {mode}: PASS', flush=True)
    print('Native namespace admission: both profiles; eight mutants rejected; PASS')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--isolated':
        with open(sys.argv[2], 'w', buffering=1) as log:
            sys.stdout = sys.stderr = log
            try:
                run()
            except BaseException:
                import traceback
                traceback.print_exc()
                sys.exit(1)
    else:
        from windows_enclave_namespace import isolated
        isolated(Path(__file__).resolve())
