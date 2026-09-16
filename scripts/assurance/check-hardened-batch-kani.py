#!/usr/bin/env python3
"""Prove real hardened budget controls in isolated source copies, not new models.

No production code, global harness inventory or release-gate rule is changed.
These bounded arithmetic/cancellation proofs do not qualify SIMD instructions,
zeroization, whole hash algorithms or the ParallelHash completion protocol.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
FAMILIES = {
    'sha256': ('brynja-hash-sha2', 'hardened_batch', 'hardened-batch-execution'),
    'sha512': ('brynja-hash-sha2', 'hardened_batch512', 'hardened-batch512-execution'),
    'keccak': ('brynja-hash-sha3', 'hardened_batch', 'hardened-batch-execution'),
}
PROOFS = r'''
#[cfg(kani)]
mod batch_qualification {
    use super::*;
    #[kani::proof]
    fn arbitrary_accounting_is_atomic() {
        let remaining: u64 = kani::any();
        let used: u64 = kani::any();
        let amount: u64 = kani::any();
        let cancelled: bool = kani::any();
        let mut calls = 0_u8;
        let mut callback = || { calls += 1; cancelled };
        let mut control = Control { remaining, used, cancelled: &mut callback };
        let result = control.charge(amount);
        if cancelled {
            assert_eq!(result, Err(Error::Cancelled));
        } else if remaining.checked_sub(amount).is_none() {
            assert_eq!(result, Err(Error::WorkLimit));
        } else if used.checked_add(amount).is_none() {
            assert_eq!(result, Err(Error::Invariant));
        } else {
            assert_eq!(result, Ok(()));
        }
        if result.is_ok() {
            assert_eq!(Some(control.remaining()), remaining.checked_sub(amount));
            assert_eq!(Some(control.used()), used.checked_add(amount));
        } else {
            assert_eq!((control.remaining(), control.used()), (remaining, used));
        }
        assert_eq!(calls, 1);
    }
    #[kani::proof]
    fn poll_preserves_finite_budget() {
        let maximum: u64 = kani::any();
        let cancelled: bool = kani::any();
        let mut callback = || cancelled;
        let mut control = Control::new(maximum, &mut callback);
        assert_eq!(control.poll(), if cancelled { Err(Error::Cancelled) } else { Ok(()) });
        assert_eq!(control.remaining(), maximum);
        assert_eq!(control.used(), 0);
    }
}
'''


def run(command, root, env):
    return subprocess.run(command, cwd=root, env=env, text=True, capture_output=True, timeout=600)


def require_success(result):
    if result.returncode or 'VERIFICATION:- SUCCESSFUL' not in result.stdout:
        raise ValueError('Kani proof failed or did not execute:\n' + result.stdout[-7000:] + result.stderr[-3000:])


def require_counterexample(result):
    if not result.returncode or 'VERIFICATION:- FAILED' not in result.stdout or 'assertion' not in result.stdout:
        raise ValueError('Kani mutation lacked an assertion counterexample:\n' + result.stdout[-7000:] + result.stderr[-3000:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family', choices=tuple(FAMILIES) + ('all',), default='all')
    args = parser.parse_args()
    policy = tomllib.loads((ROOT / 'assurance/policy.toml').read_text())
    toolchain = policy['toolchains']['kani']
    version = next(tool['version'] for tool in policy['tools'] if tool['id'] == 'kani')
    prefix = ['rustup', 'run', toolchain, 'cargo']
    installed = run([*prefix, 'kani', '--version'], ROOT, os.environ)
    if installed.returncode or installed.stdout.strip() != 'cargo-kani ' + version:
        raise ValueError('the repository-pinned Kani installation is required')
    selected = FAMILIES if args.family == 'all' else {args.family: FAMILIES[args.family]}
    with tempfile.TemporaryDirectory(prefix='brynja-hardened-batch-kani-') as directory:
        root = Path(directory)
        for package in ('brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu', 'brynja-hash-sha2', 'brynja-hash-sha3'):
            shutil.copytree(ROOT / 'crates' / package, root / 'crates' / package,
                            ignore=shutil.ignore_patterns('target'))
        (root / 'Cargo.toml').write_text((ROOT / 'Cargo.toml').read_text().replace(
            'default-members = ["crates/brynja"]', 'default-members = ["crates/brynja-hash-sha2"]'))
        env = dict(os.environ, CARGO_TARGET_DIR=str(root / 'target'), CARGO_NET_OFFLINE='true')
        for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET', 'RUSTUP_TOOLCHAIN'):
            env.pop(key, None)
        subprocess.run([*prefix, 'generate-lockfile', '--offline'], cwd=root, env=env, check=True, timeout=60)
        for family, (package, module, feature) in selected.items():
            path = root / 'crates' / package / 'src' / module / 'control.rs'
            original = path.read_text()
            source = original + PROOFS
            path.write_text(source)
            base = [*prefix, 'kani', '-p', package, '--no-default-features', '--features', feature]
            namespace = module + '::control::batch_qualification::'
            command = [*base, '--harness', namespace + 'arbitrary_accounting_is_atomic']
            try:
                require_success(run(command, root, env))
                require_success(run([*base, '--harness', namespace + 'poll_preserves_finite_budget'], root, env))
                for before, after in (
                    ('self.poll()?;', '// omitted cancellation'),
                    ('let used = self.used.checked_add(amount).ok_or(Error::Invariant)?;',
                     'let used = self.used.wrapping_add(amount);'),
                    ('let used = self.used.checked_add(amount).ok_or(Error::Invariant)?;',
                     'self.remaining = remaining; let used = self.used.checked_add(amount).ok_or(Error::Invariant)?;'),
                ):
                    if original.count(before) != 1:
                        raise ValueError('Kani source mutation anchor drift: ' + family)
                    path.write_text(original.replace(before, after) + PROOFS)
                    require_counterexample(run(command, root, env))
                path.write_text(source)
                require_success(run(command, root, env))
            finally:
                path.write_text(original)
            print(f'Hardened batch budget Kani: PASS; {family}; 2 proofs, 3 real-source counterexamples; '
                  f'Kani {version}; {toolchain}', flush=True)


if __name__ == '__main__':
    main()
