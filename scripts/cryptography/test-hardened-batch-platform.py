#!/usr/bin/env python3
"""Compiled x86 batch deployment-contract regressions; no release-gate changes.

Tests extracted packages, never edits production sources. Generic checks cannot
enter SIMD. --lane additionally executes specialized builds after the existing
native-host check. This does not simulate migration or qualify another platform.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/sha3'))
import keccak_batch_native as native


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


packages = load('platform_packages', ROOT / 'scripts/sha3/check-sha3-execution.py')
checks = load('platform_checks', Path(__file__).with_name('check-hardened-batch-package.py'))
FAMILIES = ('sha256', 'sha512', 'keccak')
MODULES = tuple(family + suffix for family in FAMILIES for suffix in ('_batch', '_hardened_batch'))


def source():
    text = '''#![forbid(unsafe_code)]
#[inline(never)]
pub fn feature_probe() -> bool {
    std::is_x86_feature_detected!("avx") && std::is_x86_feature_detected!("avx2")
}
'''
    for module in MODULES:
        text += '''
#[test]
fn MODULE_contract() {
    use brynja_crypto_cpu::MODULE as cpu;
    use brynja_crypto_cpu_std::MODULE as hosted;
    let enabled = cfg!(all(target_feature = "avx", target_feature = "avx2"));
    assert_eq!(cpu::Kernel::Avx2.compiled(), enabled);
    assert!(!cpu::Kernel::Neon.compiled());
    assert!(matches!(cpu::Authority::for_compiled_target(cpu::Kernel::Neon),
                     Err(cpu::Error::WrongArchitecture)));
    let authority = cpu::Authority::for_compiled_target(cpu::Kernel::Avx2);
    if enabled {
        assert!(authority.is_ok()); // Includes the real startup KAT.
    } else {
        assert!(matches!(authority, Err(cpu::Error::MissingFeatures)));
    }
    let portable = hosted::Authority::new(hosted::Mode::Portable).unwrap();
    assert_eq!(portable.kernel().unwrap(), None);
    let prefer = hosted::Authority::new(hosted::Mode::Prefer).unwrap();
    assert_eq!(prefer.kernel().unwrap(), enabled.then_some(cpu::Kernel::Avx2));
    let required = hosted::Authority::new(hosted::Mode::Require);
    if enabled {
        let required = required.unwrap();
        assert_eq!(required.kernel().unwrap(), Some(cpu::Kernel::Avx2));
        required.quarantine();
        assert!(required.kernel().is_err());
        assert!(required.executor(1).is_err());
    } else {
        assert!(matches!(required, Err(hosted::Error::Unavailable)));
    }
}
'''.replace('MODULE', module)
    return text


def run(command, cwd, env):
    return checks.run(command, cwd, env)


def passed(result):
    checks.require_success(result)
    if 'test result: ok. 6 passed; 0 failed; 0 ignored;' not in result.stdout:
        raise ValueError('six exact contract tests did not execute')


def rejected(result):
    if result.returncode == 0 or 'test result: FAILED. 5 passed; 1 failed;' not in result.stdout:
        raise ValueError('contract mutation survived or failed to execute:\n' + result.stderr[-3000:])


def mutate(path, before, after):
    original = path.read_text()
    if original.count(before) != 1:
        raise ValueError('non-unique platform mutation: ' + str(path))
    path.write_text(original.replace(before, after))
    return original


def regressions(roots, consumer, command, env):
    count = 0
    for family in FAMILIES:
        module = family + '_hardened_batch'
        path = roots['brynja-crypto-cpu'] / 'src' / module / 'mod.rs'
        # Replace only the post-admission call with a sentinel. Baseline rejects
        # first; removing the guard must reach the sentinel, never instructions
        # on an unqualified machine. The real constructor is tested separately.
        original = mutate(path, 'Self::create(kernel, Kernel::compiled)', 'Err(Error::Invariant)')
        try:
            passed(run(command, consumer, env))
            instrumented = mutate(path, 'if !kernel.compiled() {', 'if false {')
            try:
                rejected(run(command, consumer, env))
                count += 1
            finally:
                path.write_text(instrumented)
            passed(run(command, consumer, env))
        finally:
            path.write_text(original)
        path = roots['brynja-crypto-cpu-std'] / 'src' / module / 'platform.rs'
        original = mutate(path, 'if Kernel::Avx2.compiled() {', 'if true {')
        try:
            # A forged current-feature observation must not become hosted
            # authority in a generic build. CPU static admission still rejects.
            rejected(run(command, consumer, env))
            count += 1
        finally:
            path.write_text(original)
        passed(run(command, consumer, env))
    return count


def unsafe_imports(roots, consumer, cargo, env):
    path = consumer / 'src/lib.rs'
    original = path.read_text()
    command = [*cargo, 'check', '--locked', '--offline', '--lib', '--message-format=json']
    count = 0
    try:
        for family in FAMILIES:
            module = family + '_hardened_batch'
            prefix = f'#![forbid(unsafe_code)]\nuse brynja_crypto_cpu::{module}::{{Authority, Kernel, Error}};\n'
            path.write_text(prefix + 'pub fn probe() -> unsafe fn(Kernel, fn(Kernel) -> bool) -> Result<Authority, Error> { Authority::from_platform }')
            checks.require_success(run(command, consumer, env))
            path.write_text(prefix + 'pub fn probe() { let _ = Authority::from_platform(Kernel::Avx2, |_| true); }')
            checks.require_rejection(run(command, consumer, env), 'E0133')
            platform = roots['brynja-crypto-cpu'] / 'src' / module / 'platform.rs'
            saved = mutate(platform, 'pub unsafe fn from_platform(', 'pub fn from_platform(')
            try:
                # The otherwise-identical negative now compiles: the unsafe
                # boundary, not an unrelated error, made the original fail.
                checks.require_success(run(command, consumer, env))
                count += 1
            finally:
                platform.write_text(saved)
            checks.require_rejection(run(command, consumer, env), 'E0133')
    finally:
        path.write_text(original)
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=('1.90.0', '1.98.1'), default='1.98.1')
    parser.add_argument('--lane', choices=('amd-x86_64', 'intel-x86_64'))
    args = parser.parse_args()
    env = native.environment()
    env['RUSTUP_TOOLCHAIN'] = args.toolchain
    for key in tuple(env):
        if key.startswith('BRYNJA_') or key in ('RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER'):
            env.pop(key)
    version = run(['rustc', '+' + args.toolchain, '-vV'], ROOT, env)
    checks.require_success(version)
    if 'host: x86_64-unknown-linux-gnu' not in version.stdout:
        raise ValueError('this x86 regression driver requires the Linux x86_64 host toolchain')
    if args.lane:
        native.host(args.lane)  # Before executing any AVX-specialized binary.
    cargo = ['cargo', '+' + args.toolchain]
    with tempfile.TemporaryDirectory(prefix='brynja-batch-platform-') as directory:
        root = Path(directory)
        env['CARGO_TARGET_DIR'] = str(root / 'target')
        env['RUSTFLAGS'] = '-C target-cpu=x86-64 -C target-feature=-avx,-avx2'
        _, roots = packages.package(root, env)
        consumer = root / 'contract'
        (consumer / 'src').mkdir(parents=True)
        features = [name.replace('_', '-') for name in MODULES]
        manifest = '[package]\nname="batch-platform-contract"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\n'
        for name in ('brynja-crypto-cpu', 'brynja-crypto-cpu-std'):
            manifest += f'{name} = {{ path={json.dumps(str(roots[name]))}, default-features=false, features={json.dumps(features)} }}\n'
        manifest += '[patch.crates-io]\n' + ''.join(
            f'{name} = {{ path={json.dumps(str(path))} }}\n' for name, path in roots.items())
        (consumer / 'Cargo.toml').write_text(manifest)
        (consumer / 'src/lib.rs').write_text(source())
        checks.require_success(run([*cargo, 'generate-lockfile', '--offline'], consumer, env))
        command = [*cargo, 'test', '--locked', '--offline', '--lib', '--release']
        passed(run(command, consumer, env))
        mutations = regressions(roots, consumer, command, env)
        imports = unsafe_imports(roots, consumer, cargo, env)
        passed(run(command, consumer, env))
        print(f'Batch platform generic contracts: PASS; tests=6; admission mutants={mutations}; unsafe imports={imports}', flush=True)
        for features in ('+avx,-avx2', '+avx,+avx2'):
            env['RUSTFLAGS'] = '-C target-cpu=x86-64 -C target-feature=' + features
            if args.lane:
                passed(run(command, consumer, env))
                print(f'Batch platform native contracts: PASS; tests=6; features={features}; {args.lane}', flush=True)
        # Compile, but do not execute on an unknown CPU: the suggested detector
        # itself folds to true in a globally AVX2-enabled build on both endpoints.
        checks.require_success(run([*cargo, 'rustc', '--locked', '--offline', '--release', '--lib',
                                    '--', '--emit=llvm-ir'], consumer, env))
        paths = list((root / 'target/release/deps').glob('batch_platform_contract-*.ll'))
        if len(paths) != 1:
            raise ValueError('ambiguous feature probe IR')
        functions = re.findall(r'^define [^\n]*feature_probe[^\n]*\{(.*?)^}', paths[0].read_text(), re.M | re.S)
        if len(functions) != 1 or not re.search(r'^\s*ret i1 true\s*$', functions[0], re.M) or ' call ' in functions[0]:
            raise ValueError('global target-feature detector did not fold to true')
        print(f'Global AVX2 std detector constant-folding: confirmed; {args.toolchain}', flush=True)


if __name__ == '__main__':
    main()
