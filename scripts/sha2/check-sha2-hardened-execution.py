#!/usr/bin/env python3
"""Packaged hardened SHA-2 consumer; actual kernels, not evidence-only routes."""
import argparse
import importlib.util
import os
from pathlib import Path
import tempfile
import sha2_hardened_execution_policy as policy
import sha2_hardened_cleanup_mutants as cleanup

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ordinary', Path(__file__).with_name('check-sha2-execution.py'))
ordinary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ordinary)
run = ordinary.run


def negatives(consumer, env):
    path = consumer / 'src/main.rs'
    original = path.read_text()
    cases = (
        ('let mut h = api::Sha256::new(api::Execution::portable()).unwrap(); h.cancel(); h.update(b"x").unwrap();', 'E0382'),
        ('let h = api::Sha256::new(api::Execution::portable()).unwrap(); let mut d = [0;32]; h.finalize_secret(&mut d).unwrap(); h.cancel();', 'E0382'),
        ('fn send<T: Send>() {} send::<api::Sha512>();', 'E0277'),
        ('fn sync<T: Sync>() {} sync::<api::Sha512>();', 'E0277'),
        ('fn copy<T: Copy>() {} copy::<api::Sha256>();', 'E0277'),
        ('fn debug<T: std::fmt::Debug>() {} debug::<api::Sha256>();', 'E0277'),
        ('let h = api::Sha256::new(api::Execution::portable()).unwrap(); let _ = h.clone();', 'E0599'),
        ('let _: api::Execution = api::Route::Portable.into();', 'E0277'),
        ('let _ = api::Sha256::new(brynja_hash_sha2::execution::Execution::portable());', 'E0308'),
        ('let _: brynja_hash_sha2::Sha512TDigest = { let mut d = [0;1]; api::Sha512T::hash_secret(brynja_hash_sha2::Sha512TBits::new(8).unwrap(), api::Execution::portable(), b"key", &mut d).unwrap().digest };', 'E0308'),
        ('fn cloneable<T: Clone>() {} cloneable::<api::GeneralSecretOutput>();', 'E0277'),
        ('fn debug<T: std::fmt::Debug>() {} debug::<api::SecretOutput>();', 'E0277'),
    )
    try:
        for snippet, diagnostic in cases:
            path.write_text(original + '\nfn forbidden() {' + snippet + '}\n')
            result = run(['cargo', 'check', '--offline'], consumer, env, success=False)
            if f'error[{diagnostic}]' not in result.stderr:
                raise ValueError('negative failed for wrong reason: ' + result.stderr)
    finally:
        path.write_text(original)
    print('Twelve packaged ownership/classification bypasses rejected')


def mutations(consumer, roots, env, mode, extra):
    leaf = roots['brynja-hash-sha2'] / 'src/hardened_execution'
    cpu = roots['brynja-crypto-cpu'] / 'src/hardened_execution'
    cases = [
        (leaf / 'engine.rs', 'self.execution.compress(self.wide, guard.owner)?;', 'let _ = &guard.owner;'),
        (leaf / 'engine.rs', 'self.execution.compress(self.wide, &mut self.owner)?;', 'let _ = &self.owner;'),
        (leaf / 'general.rs', 'parameter.initial_words()', '[0; 8]'),
        (leaf / 'engine.rs', 'byte | (0x80 >> bits)', 'byte | (0x80 >> bits.saturating_add(1))'),
        (leaf / 'engine.rs', '.checked_add(1)', '.checked_add(0)'),
        (leaf / 'general.rs', 'self.parameter.last_byte_mask()', '0xff'),
    ]
    if mode != 'portable':
        cases += [(cpu / 'mod.rs', 'Ok(state == expected)', 'Ok(false)'),
                  (cpu / 'mod.rs', 'self.check(wide)?;', 'let _ = wide;')]
    for path, before, after in cases:
        original = path.read_text()
        if before not in original:
            raise ValueError('stale mutation: ' + before)
        try:
            path.write_text(original.replace(before, after))
            for profile in ([], ['--release']):
                command = ['cargo', 'run', '--offline', *profile, *extra, '--', mode]
                result = run(command, consumer, env, success=False)
                if 'acceptance failed:' not in result.stderr:
                    raise ValueError('mutant failed without runtime rejection: ' + result.stderr)
        finally:
            path.write_text(original)
    print(f'{len(cases) * 2} compiled hardened algorithm/lifecycle regressions rejected')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native-x86', action='store_true')
    parser.add_argument('--qemu', action='store_true')
    parser.add_argument('--policy-only', action='store_true')
    parser.add_argument('--write-review', action='store_true')
    args = parser.parse_args()
    policy.validate(write=args.write_review)
    if args.policy_only or args.write_review:
        return
    with tempfile.TemporaryDirectory(prefix='brynja-hardened-package-') as directory:
        destination = Path(directory)
        env = dict(os.environ, CARGO_TARGET_DIR=str(destination / 'target'))
        for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
            env.pop(name, None)
        consumer, roots = ordinary.package(destination, env, 'sha2-hardened-execution')
        for profile in ([], ['--release']):
            for mode in ('portable', 'prefer'):
                result = run(['cargo', 'run', '--offline', *profile, '--', mode], consumer, env)
                if 'named=240; general=4590' not in result.stdout:
                    raise ValueError('incomplete hardened acceptance')
        run(['cargo', 'clippy', '--offline', '--all-targets', '--', '-D', 'warnings',
             '-A', 'clippy::chunks_exact_to_as_chunks'], consumer, env)
        negatives(consumer, env)
        mutations(consumer, roots, env, 'portable', [])
        cleanup.exercise(roots, env, run)
        if args.native_x86:
            env['RUSTFLAGS'] = '-C target-feature=+sha,+sse2'
            result = run(['cargo', 'run', '--offline', '--release', '--', 'static', 'narrow'], consumer, env)
            print(result.stdout, end='')
            cleanup.kernel_faults(consumer, roots, env, run, [], ['static', 'narrow'])
        if args.qemu:
            env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER'] = 'qemu-aarch64 -cpu max'
            env['RUSTFLAGS'] = '-C linker=rust-lld -C target-feature=+neon,+sha2,+sha3'
            extra = ['--target', 'aarch64-unknown-linux-musl']
            result = run(['cargo', 'run', '--offline', '--release', *extra, '--', 'static'], consumer, env)
            print(result.stdout, end='')
            cleanup.kernel_faults(consumer, roots, env, run, extra, ['static'])
            env['RUSTFLAGS'] = '-C linker=rust-lld'
            result = run(['cargo', 'run', '--offline', '--release', *extra, '--', 'hosted'], consumer, env)
            print(result.stdout, end='')
    print('Complete packaged hardened SHA-2 execution: PASS')


if __name__ == '__main__':
    main()
