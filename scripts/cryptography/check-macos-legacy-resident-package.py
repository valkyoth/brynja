#!/usr/bin/env python3
"""Native extracted-package legacy resident acceptance; no release qualification."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib
import macos_legacy_resident_oracle as oracle

ROOT = Path(__file__).resolve().parents[2]
PACKAGES = ('brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu', 'brynja-crypto-cpu-std',
            'brynja-hash-sha2', 'brynja-hash-sha3', 'brynja-mac-kmac', 'brynja-hash-tuple',
            'brynja-legacy-sha1', 'brynja-legacy-sha1-std', 'brynja-legacy-md5', 'brynja-legacy-md5-std')
FEATURE = 'macos-resident-acceleration'
spec = importlib.util.spec_from_file_location('resident_package',
    Path(__file__).with_name('check-macos-resident-package.py'))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
run = shared.run


def extract(archive, destination, prefix):
    total, seen = 0, set()
    with tarfile.open(archive) as bundle:
        for member in bundle:
            path = Path(member.name)
            total += member.size
            if (path.is_absolute() or '..' in path.parts or not path.parts
                    or path.parts[0] != prefix or not member.isfile()
                    or member.name in seen or total > 16 * 1024 * 1024):
                raise ValueError('unexpected legacy package archive member')
            seen.add(member.name)
            stream = bundle.extractfile(member)
            if stream is None:
                raise ValueError('missing package contents')
            out = destination / path
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(stream.read())


def validate_graph(metadata, consumer, roots):
    expected = {'resident-legacy-consumer', 'brynja-core', 'brynja-hash-core',
                'brynja-legacy-sha1', 'brynja-legacy-sha1-std', 'brynja-legacy-md5', 'brynja-legacy-md5-std'}
    if {p['name'] for p in metadata['packages']} != expected:
        raise ValueError('resident legacy resolved dependency closure changed')
    for package in metadata['packages']:
        parent = consumer if package['name'] == 'resident-legacy-consumer' else roots[package['name']]
        if package['source'] is not None or Path(package['manifest_path']).resolve() != (parent/'Cargo.toml').resolve():
            raise ValueError('dependency escaped extracted packages')


def mutations(cargo, hosted, env, family):
    prefix = 'macos_resident::'
    cases = [
        ('resource/darwin.rs', 'let _ = brynja_core::clear_owned_region(bytes);',
         'core::hint::black_box(&mut *bytes);',
         'resource::darwin::tests::worker_placement_join_and_whole_payload_clear'),
        ('resource/darwin.rs', 'unsafe { mlock(data.as_ptr().cast(), layout.payload) }', '0',
         'resource::darwin::tests::worker_placement_join_and_whole_payload_clear'),
        ('mod.rs', 'if !self.complete {', 'if self.complete {',
         'tests::native::bounded_cancellation_and_post_write_unwind_clear_and_reuse'),
        ('worker.rs', 'state.update(part)', 'state.update(&[])',
         'tests::native::bit_padding_and_chunk_boundaries_match_portable'),
        ('worker.rs', 'finalize_bits_secret(last, staged)',
         'finalize_bits_secret(BitString::new(&[], 0).map_err(|_| Error::InvalidBits)?, staged)',
         'tests::native::bit_padding_and_chunk_boundaries_match_portable'),
    ]
    if family == 'sha1':
        cases.append(('compiled.rs', 'Ok(()) | Err(Error::Cancelled | Error::InvalidBits)',
            'Ok(()) | Err(Error::Cancelled | Error::InvalidBits | Error::Quarantined)',
            'compiled::tests::native::failures_clear_protected_output_and_classify_executor_reuse'))
    else:
        cases += [
            ('batch/mod.rs', 'if !self.keep {', 'if self.keep {',
             'batch::tests::native::work_rejection_cancellation_revocation_and_unwind_clear_all_slots'),
            ('batch/mod.rs', 'if reusable(&result) {', 'if true {',
             'batch::tests::native::work_rejection_cancellation_revocation_and_unwind_clear_all_slots'),
        ]
    for name, before, after, test in cases:
        path = hosted / 'src/macos_resident' / name
        original = path.read_text()
        if original.count(before) != 1:
            raise ValueError('legacy mutation anchor changed: ' + name)
        command = [*cargo, 'test', '--locked', '--offline', '--release', '--no-default-features',
                   '--features', FEATURE, '--lib', prefix + test, '--', '--exact']
        if 'test result: ok. 1 passed;' not in run(command, hosted, env):
            raise ValueError('mutation baseline not executed')
        try:
            path.write_text(original.replace(before, after))
            result = subprocess.run(command, cwd=hosted, env=env, text=True, capture_output=True, timeout=600)
            if not result.returncode or 'test result: FAILED. 0 passed; 1 failed;' not in result.stdout:
                raise ValueError('mutant survived or did not compile: ' + name + '\n' + result.stderr[-4000:])
        finally:
            path.write_text(original)
        if 'test result: ok. 1 passed;' not in run(command, hosted, env):
            raise ValueError('restored baseline failed')
    print(f'Resident {family} compiled mutations rejected: {len(cases)}', flush=True)


def execute(toolchain, destination):
    cargo = ['cargo', '+' + toolchain]
    identity = subprocess.check_output(['rustc', '+' + toolchain, '-vV'], text=True)
    if 'host: aarch64-apple-darwin' not in identity.splitlines():
        raise ValueError('requires native Apple Silicon macOS')
    if subprocess.check_output(['/usr/sbin/sysctl', '-n', 'hw.optional.arm.FEAT_SHA1'], text=True).strip() != '1':
        raise ValueError('native SHA1 capability missing')
    print(identity, flush=True)
    env = dict(os.environ, RUSTUP_TOOLCHAIN=toolchain, CARGO_TARGET_DIR=str(destination/'target'))
    for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET', 'CARGO_BUILD_BUILD_DIR'):
        env.pop(name, None)
    env['RUSTFLAGS'] = '-C target-feature=+neon,+sha2'
    command = [*cargo, 'package', '--locked', '--offline', '--allow-dirty', '--no-verify']
    for name in PACKAGES:
        command += ['-p', name]
    run(command, ROOT, env)
    roots = {}
    for name in PACKAGES:
        version = tomllib.loads((ROOT/'crates'/name/'Cargo.toml').read_text())['package']['version']
        prefix = f'{name}-{version}'
        extract(destination/'target/package'/f'{prefix}.crate', destination/'packages', prefix)
        roots[name] = destination/'packages'/prefix
    patches = '\n'.join(f'{name} = {{ path = {json.dumps(str(path))} }}' for name, path in roots.items())
    consumer = destination/'consumer'
    (consumer/'src').mkdir(parents=True)
    manifest = ('[package]\nname="resident-legacy-consumer"\nversion="0.0.0"\nedition="2024"\n[workspace]\n'
                '[features]\ndefault=["macos-resident"]\nmacos-resident=[]\n[dependencies]\n')
    for family in ('sha1', 'md5'):
        manifest += f'brynja-legacy-{family} = {{version="=0.1.0",default-features=false}}\n'
        manifest += f'brynja-legacy-{family}-std = {{version="=0.1.0",default-features=false,features=["{FEATURE}"]}}\n'
    (consumer/'Cargo.toml').write_text(manifest + '[patch.crates-io]\n' + patches + '\n')
    oracle.write_consumer(consumer)
    # Execute the feature-gated README examples in this focused downstream
    # consumer, not by broadening the shared README fixture/gate feature graph.
    for family in ('sha1', 'md5'):
        (consumer/f'{family}.md').write_text((roots[f'brynja-legacy-{family}-std']/'README.md').read_text())
    (consumer/'src/lib.rs').write_text(
        '#[doc = include_str!("../sha1.md")] pub struct Sha1Readme;\n'
        '#[doc = include_str!("../md5.md")] pub struct Md5Readme;\n')
    run([*cargo, 'generate-lockfile', '--offline'], consumer, env)
    metadata = json.loads(run([*cargo, 'metadata', '--locked', '--offline', '--format-version', '1'], consumer, env))
    validate_graph(metadata, consumer, roots)
    docs = run([*cargo, 'test', '--locked', '--offline', '--doc'], consumer, env)
    if 'test result: ok. 7 passed; 0 failed; 0 ignored;' not in docs:
        raise ValueError('packaged README examples did not execute: ' + docs)
    print(docs, flush=True)
    for profile, panic in (([], 'unwind'), (['--release'], 'unwind'), (['--release'], 'abort')):
        output = run([*cargo, 'run', '--locked', '--offline', *profile], consumer,
                     dict(env, RUSTFLAGS=env['RUSTFLAGS'] + ' -C panic=' + panic))
        if 'RESIDENT_LEGACY_ORACLE: 507 scalar/Arm SHA1/MD5 comparisons; 712 NEON lanes' not in output.splitlines():
            raise ValueError('legacy oracle did not execute')
        print(f'Packaged {profile or ["debug"]}; panic={panic}: {output.strip()}', flush=True)
    for family, negatives, marker in (
            ('sha1', 19, 'MACOS_RESIDENT_SHA1_COMPILED: Aarch64Sha1; differential=336'),
            ('md5', 24, 'MACOS_RESIDENT_MD5_BATCH: Aarch64Neon; differential=512')):
        hosted = roots[f'brynja-legacy-{family}-std']
        manifest = hosted/'Cargo.toml'
        manifest.write_text(manifest.read_text() + '\n[workspace]\n[patch.crates-io]\n' + patches + '\n')
        run([*cargo, 'generate-lockfile', '--offline'], hosted, env)
        for target, count in (('--lib', 18), ('--doc', negatives)):
            output = run([*cargo, 'test', '--locked', '--offline', '--no-default-features',
                          '--features', FEATURE, target, 'macos_resident', '--', '--nocapture'], hosted, env)
            if f'test result: ok. {count} passed; 0 failed; 0 ignored;' not in output:
                raise ValueError('legacy packaged test population changed: ' + output)
            if target == '--lib' and marker not in output.splitlines():
                raise ValueError('legacy packaged accelerated route missing')
            print(output, flush=True)
        mutations(cargo, hosted, env, family)
    print('Packaged macOS legacy resident acceptance: PASS; development scope only', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', default='1.99.1')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='brynja-macos-legacy-resident-') as directory:
        execute(args.toolchain, Path(directory))
