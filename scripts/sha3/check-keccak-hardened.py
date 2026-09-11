#!/usr/bin/env python3
"""Packaged hardened Keccak APIs, including compiled negative ownership tests."""
import argparse
import importlib.util
import os
from pathlib import Path
import platform
import shutil
import tempfile
import keccak_hardened_policy as policy

ROOT = policy.ROOT
spec = importlib.util.spec_from_file_location('ordinary', Path(__file__).with_name('check-sha3-execution.py'))
ordinary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ordinary)
original_run = ordinary.run


def pinned_run(args, cwd, env, success=True):
    # Native artifacts report this exact compiler, including packaging and all
    # generated consumers. RUSTUP_TOOLCHAIN must not silently change the run.
    if args and args[0] == 'cargo' and not args[1].startswith('+'):
        args = ['cargo', '+1.98.1', *args[1:]]
    return original_run(args, cwd, env, success)


ordinary.run = pinned_run


def environment(destination):
    env = dict(os.environ, CARGO_TARGET_DIR=str(destination / 'target'))
    for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
        env.pop(name, None)
    return env


def package(destination, env):
    _, roots = ordinary.package(destination, env)
    consumer = destination / 'hardened-consumer'
    (consumer / 'src').mkdir(parents=True)
    (consumer / 'tests').mkdir()
    manifest = '[workspace]\n[package]\nname="hardened-keccak-consumer"\nversion="0.0.0"\nedition="2024"\n'
    manifest += '[features]\ndefault=["hardened-execution"]\nhardened-execution=[]\n[dependencies]\n'
    for name in ('brynja-crypto-cpu', 'brynja-hash-sha3'):
        manifest += f'{name}={{path="{roots[name].as_posix()}",default-features=false,features=["hardened-execution","runtime-execution"]}}\n'
    manifest += f'brynja-crypto-cpu-std={{path="{roots["brynja-crypto-cpu-std"].as_posix()}",features=["runtime-execution"]}}\n'
    manifest += '[patch.crates-io]\n' + '\n'.join(
        f'{name}={{path="{root.as_posix()}"}}' for name, root in roots.items()) + '\n'
    (consumer / 'Cargo.toml').write_text(manifest)
    (consumer / 'src/lib.rs').write_text('pub use brynja_hash_sha3::hardened_execution as api;\n')
    shutil.copyfile(roots['brynja-hash-sha3'] / 'tests/hardened_execution.rs', consumer / 'tests/api.rs')
    return consumer, roots


def negatives(consumer, env):
    path = consumer / 'src/lib.rs'
    original = path.read_text()
    cases = []
    for name in ('Sha3_224', 'Sha3_256', 'Sha3_384', 'Sha3_512', 'Shake128', 'Shake256',
                 'Cshake128', 'Cshake256', 'Reader', 'KeccakSession'):
        for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
            cases.append((f'fn check<T:{bound}>(){{}} check::<api::{name}>();', 'E0277'))
    cases += [
        ('struct Forged; impl api::HardenedState for Forged {}', 'E0277'),
        ('fn use_again(h:api::Sha3_256) { let mut d=[0;32]; let _=h.finalize_secret(&mut d); let _=h.report(); }', 'E0382'),
        ('fn use_again(h:api::Shake128) { let _=h.finalize_xof(); let _=h.report(); }', 'E0382'),
        ('fn public(x:api::HardenedSha3SecretOutput) { let _: &[u8] = x; }', 'E0308'),
    ]
    try:
        for code, diagnostic in cases:
            path.write_text(original + '\nfn forbidden() {' + code + '}\n')
            result = ordinary.run(['cargo', 'check', '--offline'], consumer, env, success=False)
            policy.require(f'error[{diagnostic}]' in result.stderr, 'negative diagnostic: ' + result.stderr)
    finally:
        path.write_text(original)
    print(f'Hardened Keccak packaged ownership rejects {len(cases)} bypasses')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--write-review', action='store_true')
    parser.add_argument('--policy-only', action='store_true')
    parser.add_argument('--native-x86', action='store_true')
    parser.add_argument('--native-arm', action='store_true')
    parser.add_argument('--qemu', action='store_true')
    args = parser.parse_args()
    policy.validate(write=args.write_review)
    if args.write_review or args.policy_only:
        return
    with tempfile.TemporaryDirectory(prefix='brynja-keccak-consumer-') as temporary:
        destination = Path(temporary)
        env = environment(destination)
        consumer, roots = package(destination, env)
        guide = (ROOT / 'docs/hardened-keccak-execution.md').read_text()
        example = guide.split('```rust\n', 1)[1].split('```', 1)[0]
        (consumer / 'examples').mkdir()
        (consumer / 'examples/guide.rs').write_text(example)
        ordinary.run(['cargo', 'check', '--offline', '--examples'], consumer, env)
        negatives(consumer, env)
        # Default builds check API ownership without executing unavailable CPUs.
        ordinary.run(['cargo', 'test', '--offline'], consumer, env)
        if args.native_arm or args.qemu:
            if args.native_arm:
                policy.require(platform.machine() in ('aarch64', 'arm64'), 'native Arm host')
            if args.qemu:
                env['RUSTFLAGS'] = '-C linker=rust-lld'
                env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER'] = 'qemu-aarch64 -cpu max'
            target = ['--target', 'aarch64-unknown-linux-musl'] if args.qemu else []
            hosted(consumer, env, target)
        if args.native_x86 or args.native_arm or args.qemu:
            if args.qemu:
                env['RUSTFLAGS'] = '-C linker=rust-lld -C target-feature=+neon,+sha2,+sha3'
                env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER'] = 'qemu-aarch64 -cpu max'
                target = ['--target', 'aarch64-unknown-linux-musl']
            elif args.native_arm:
                env['RUSTFLAGS'] = '-C target-feature=+neon,+sha2,+sha3'
                target = []
            else:
                # Host support must be established before executing a globally
                # specialized binary. This option is an explicit native campaign.
                policy.require('avx2' in Path('/proc/cpuinfo').read_text().split(), 'native AVX2 host')
                env['RUSTFLAGS'] = '-C target-feature=+avx2'
                target = []
            for profile in ([], ['--release']):
                result = ordinary.run(['cargo', 'test', '--offline', *profile, *target,
                                       '--test', 'api', '--', '--nocapture'], consumer, env)
                policy.require('4 passed; 0 failed' in result.stdout, 'complete packaged execution')
            print('Hardened Keccak packaged accelerated byte/bit/lifecycle tests: PASS')
    print('Packaged hardened Keccak public API: PASS')


def hosted(consumer, env, target):
    path = consumer / 'tests/api.rs'
    original = path.read_text()
    first = original.index('fn authority()')
    end = original.index('\n#[test]', first)
    helper = '''fn authority() -> Result<Option<Authority>, String> {
    Ok(Some(Authority::new(Kernel::ArmKeccak,
        brynja_crypto_cpu_std::execution::Mode::Require).map_err(error)?))
}
fn session(owner: &Authority) -> Result<cpu::KeccakSession<'_>, String> {
    cpu::KeccakSession::from_runtime(owner.session().map_err(error)?
        .ok_or_else(|| "required hosted authority missing".to_string())?).map_err(error)
}
'''
    updated = (original[:first] + helper + original[end:]).replace(
        'use brynja_crypto_cpu::static_execution::{Authority, Kernel};',
        'use brynja_crypto_cpu_std::execution::{Authority, Kernel};')
    policy.require(updated != original and updated.count('fn authority()') == 1, 'exact hosted fixture')
    try:
        path.write_text(updated)
        result = ordinary.run(['cargo', 'test', '--offline', '--release', *target,
                               '--test', 'api'], consumer, env)
        policy.require('4 passed; 0 failed' in result.stdout, 'complete hosted execution')
    finally:
        path.write_text(original)
    print('Hardened Keccak hosted Arm execution: PASS; kernel=ArmKeccak')


if __name__ == '__main__':
    main()
