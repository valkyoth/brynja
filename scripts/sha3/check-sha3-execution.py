#!/usr/bin/env python3
"""Packaged opt-in SHA-3/SHAKE routes and compiled transaction regressions."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
REVIEW = ROOT / 'scripts/sha3/sha3-execution-reviewed.toml'
PACKAGES = ('brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu',
            'brynja-hash-sha2', 'brynja-hash-sha3', 'brynja-crypto-cpu-std')


def run(args, cwd, env, success=True):
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=600)
    if (result.returncode == 0) != success:
        raise RuntimeError(f'{args}\n{result.stdout}\n{result.stderr}')
    return result


def validate():
    source = ROOT / 'crates/brynja-hash-sha3/src/execution'
    for path in source.glob('*.rs'):
        text = path.read_text()
        code = '\n'.join(line.split('//')[0] for line in text.splitlines())
        if len(text.splitlines()) > 500 or any(token in code for token in
                ('unsafe', 'std::', 'alloc::', 'Vec<', 'Box<', 'static mut', '.unwrap(', '.expect(')):
            raise ValueError(f'ordinary execution boundary regression: {path}')
    for name, digest in tomllib.loads(REVIEW.read_text())['files'].items():
        actual = hashlib.sha256((ROOT / name).read_bytes().replace(b'\r\n', b'\n')).hexdigest()
        if digest != actual:
            raise ValueError(f'SHA-3 execution source changed; review {name}')
    gate = (ROOT / 'scripts/checks.sh').read_text().replace('\\\n', ' ')
    for command in ('python3 scripts/sha3/check-sha3-execution.py',
                    'cargo clippy --locked --offline --manifest-path assurance/sha3-execution/Cargo.toml'):
        if command not in gate:
            raise ValueError('SHA-3 execution gate missing: ' + command)


def package(destination, env):
    workspace = destination / 'workspace'
    workspace.mkdir()
    shutil.copyfile(ROOT / 'rust-toolchain.toml', destination / 'rust-toolchain.toml')
    manifest = (ROOT / 'Cargo.toml').read_text().replace(
        'default-members = ["crates/brynja"]', 'default-members = ["crates/brynja-hash-sha3"]')
    (workspace / 'Cargo.toml').write_text(manifest)
    for name in PACKAGES:
        shutil.copytree(ROOT / 'crates' / name, workspace / 'crates' / name,
                        ignore=shutil.ignore_patterns('target'))
    run(['cargo', 'package', '--workspace', '--offline', '--allow-dirty', '--no-verify'], workspace, env)
    roots = {}
    for name in PACKAGES:
        version = tomllib.loads((workspace / 'crates' / name / 'Cargo.toml').read_text())['package']['version']
        archive = Path(env['CARGO_TARGET_DIR']) / 'package' / f'{name}-{version}.crate'
        with tarfile.open(archive) as bundle:
            bundle.extractall(destination / 'packages', filter='data')
        roots[name] = destination / 'packages' / f'{name}-{version}'
    consumer = destination / 'consumer'
    shutil.copytree(ROOT / 'assurance/sha3-execution', consumer, ignore=shutil.ignore_patterns('target'))
    manifest = (consumer / 'Cargo.toml').read_text()
    for name, root in roots.items():
        manifest = manifest.replace(f'../../crates/{name}"', root.as_posix() + '"')
    manifest += '\n[patch.crates-io]\n' + '\n'.join(
        f'{name} = {{ path = "{root.as_posix()}" }}' for name, root in roots.items()) + '\n'
    (consumer / 'Cargo.toml').write_text(manifest)
    main = consumer / 'src/main.rs'
    main.write_text(main.read_text().replace('../../../crates/brynja-hash-sha3', roots['brynja-hash-sha3'].as_posix()))
    return consumer, roots


def classification_regressions(consumer, env):
    main = consumer / 'src/main.rs'
    original = main.read_text()
    setup = ('let mut h = api::NAME::new(api::Execution::portable()).unwrap(); '
             'let bits = brynja_hash_sha3::Fips202BitString::new(b"x", 8).unwrap(); '
             'let mut output = [0; 1]; let mut scratch = [0; 1]; '
             'let dest = brynja_hash_sha3::Fips202Output::new(&mut output, 8).unwrap(); ')
    cases = []
    for name in ('Sha3_224', 'Sha3_256', 'Sha3_384', 'Sha3_512', 'Shake128', 'Shake256'):
        calls = [('h.update(INPUT)', 'b"x"', 'api::Public::new(b"x")')]
        if name.startswith('Sha3_'):
            calls += [('api::NAME::hash(api::Execution::portable(), INPUT)', 'b"x"', 'api::Public::new(b"x")'),
                      ('h.finalize_bits(INPUT)', 'bits', 'api::PublicBits::new(bits)'),
                      ('api::NAME::hash_bits(api::Execution::portable(), INPUT)', 'bits', 'api::PublicBits::new(bits)')]
        else:
            calls += [('api::NAME::hash_with_scratch(api::Execution::portable(), INPUT, &mut output, &mut scratch)', 'b"x"', 'api::Public::new(b"x")'),
                      ('h.finalize_bits_xof(INPUT)', 'bits', 'api::PublicBits::new(bits)'),
                      ('api::NAME::hash_bits_with_scratch(api::Execution::portable(), INPUT, dest, &mut scratch)', 'bits', 'api::PublicBits::new(bits)')]
        for call, raw, classified in calls:
            cases.append((setup.replace('NAME', name), call.replace('NAME', name), raw, classified))
    try:
        for prelude, call, raw, classified in cases:
            for value, accepted in ((raw, False), (classified, True)):
                main.write_text(original + '\nfn classification() {' + prelude +
                                'let _ = ' + call.replace('INPUT', value) + ';}\n')
                result = run(['cargo', 'check', '--offline'], consumer, env, accepted)
                if not accepted and 'error[E0308]' not in result.stderr:
                    raise ValueError('classification negative failed for wrong reason: ' + result.stderr)
        for snippet, diagnostic in (
            ('let _: api::Public = (&b"x"[..]).into();', 'E0277'),
            ('let _: api::PublicBits = brynja_hash_sha3::Fips202BitString::new(b"x", 8).unwrap().into();', 'E0277'),
            ('let _ = api::Public(b"x");', 'E0603'),
            ('let _ = api::PublicBits(brynja_hash_sha3::Fips202BitString::new(b"x", 8).unwrap());', 'E0603'),
        ):
            main.write_text(original + '\nfn forbidden() {' + snippet + '}\n')
            result = run(['cargo', 'check', '--offline'], consumer, env, False)
            if f'error[{diagnostic}]' not in result.stderr:
                raise ValueError('marker boundary failed for wrong reason: ' + result.stderr)
    finally:
        main.write_text(original)
    print('24 raw-input rejections with 24 explicit-marker controls and four marker bypass rejections: PASS')


def boundary_regressions(consumer, roots, env):
    leaf = roots['brynja-hash-sha3']
    path = leaf / 'src/execution/engine.rs'
    original = path.read_text()
    for before, after, test in (
        ('bits.div_ceil(8)', '(bits / 8)', 'bit_preflight_includes_each_partial_backing_byte'),
        ('Self::check_bytes(self.output_bytes, output.len() as u128)?;', '',
         'partial_execution_matches_preflight_without_mutating_on_overflow'),
    ):
        if before not in original:
            raise ValueError('missing boundary mutation site')
        try:
            path.write_text(original.replace(before, after))
            for profile in ([], ['--release']):
                result = run(['cargo', 'test', '--offline', '-p', 'brynja-hash-sha3',
                              '--lib', *profile, test], consumer, env, False)
                if 'test result: FAILED' not in result.stdout:
                    raise ValueError('boundary mutant did not execute: ' + result.stderr)
        finally:
            path.write_text(original)
    print('Four compiled bit-preflight/output-admission regressions: PASS')


def regressions(consumer, roots, env):
    main = consumer / 'src/main.rs'
    original = main.read_text()
    for snippet, diagnostic in (
        ('let mut h = api::Shake128::new(api::Execution::portable()).unwrap(); let _ = h.finalize_xof(); h.update(api::Public::new(b"x")).unwrap();', 'E0382'),
        ('fn send<T: Send>() {} send::<api::Shake128Reader>();', 'E0277'),
        ('fn sync<T: Sync>() {} sync::<api::Sha3_256>();', 'E0277'),
        ('let h = api::Sha3_256::new(api::Execution::portable()).unwrap(); let _ = h.clone();', 'E0599'),
        ('let _ = brynja_hash_sha3::HardenedShake128::new(api::Execution::portable());', 'E0061'),
        ('let _: api::Execution = api::Route::Portable.into();', 'E0277'),
    ):
        try:
            main.write_text(original + '\nfn forbidden() {' + snippet + '}\n')
            result = run(['cargo', 'check', '--offline'], consumer, env, False)
            if f'error[{diagnostic}]' not in result.stderr:
                raise ValueError('negative failed for wrong reason: ' + result.stderr)
        finally:
            main.write_text(original)
    leaf = roots['brynja-hash-sha3'] / 'src/execution'
    for filename, before, after in (
        ('route.rs', 'crate::keccak::permute(state)', '{ let _ = state; }'),
        ('fixed.rs', 'input.0, 0x06, 3', 'input.0, 0x1f, 5'),
        ('xof.rs', 'input.0, 0x1f, 5', 'input.0, 0x06, 3'),
        ('engine.rs', 'output.copy_from_slice(scratch);', 'let _ = output;'),
        ('engine.rs', '*self = candidate;', 'let _ = candidate;'),
        ('engine.rs', 'count.checked_add(1)', 'count.checked_add(0)'),
        ('engine.rs', '*last &= u8::MAX >> 8_u8.saturating_sub(valid);', 'let _ = last;'),
    ):
        path = leaf / filename
        original = path.read_text()
        if before not in original:
            raise ValueError('missing mutation site: ' + filename)
        try:
            path.write_text(original.replace(before, after))
            for profile in ([], ['--release']):
                result = run(['cargo', 'run', '--offline', *profile, '--', 'portable'], consumer, env, False)
                if 'acceptance failed:' not in result.stderr:
                    raise ValueError('mutation failed to execute: ' + result.stderr)
        finally:
            path.write_text(original)
    print('Six packaged ownership negatives and fourteen compiled output/padding/work mutations: PASS')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--policy-only', action='store_true')
    args = parser.parse_args()
    validate()
    if args.policy_only:
        return
    with tempfile.TemporaryDirectory(prefix='brynja-sha3-execution-') as temporary:
        destination = Path(temporary)
        env = dict(os.environ, CARGO_TARGET_DIR=str(destination / 'target'))
        consumer, roots = package(destination, env)
        for mode in ('portable', 'prefer'):
            result = run(['cargo', 'run', '--offline', '--', mode], consumer, env)
            print(result.stdout, end='')
        classification_regressions(consumer, env)
        boundary_regressions(consumer, roots, env)
        regressions(consumer, roots, env)


if __name__ == '__main__':
    main()
