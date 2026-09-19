#!/usr/bin/env python3
"""Exercise the real SHA-1 consumer against packaged, not workspace, sources."""
import argparse
import os
import importlib.util
import random
import subprocess
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLOSURE = {'brynja-core': '0.9.0', 'brynja-hash-core': '0.1.0', 'brynja-legacy-sha1': '0.1.0'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cpu', action='store_true')
    parser.add_argument('--execution', action='store_true')
    parser.add_argument('--hardened', action='store_true')
    args = parser.parse_args()
    closure = dict(CLOSURE)
    if args.cpu or args.execution or args.hardened: closure['brynja-legacy-sha1-std'] = '0.1.0'
    with tempfile.TemporaryDirectory(prefix='brynja-sha1-package-') as temporary:
        root = Path(temporary)
        environment = dict(os.environ, CARGO_TARGET_DIR=str(root / 'target'))
        command = ['cargo', 'package', '--locked', '--offline', '--allow-dirty', '--no-verify']
        for package in closure: command.extend(['-p', package])
        subprocess.run(command, cwd=ROOT, env=environment, check=True, timeout=180)
        for package, version in closure.items():
            prefix = f'{package}-{version}'
            archive = root / 'target/package' / (prefix + '.crate')
            total = 0
            with tarfile.open(archive) as handle:
                for member in handle:
                    path = Path(member.name)
                    total += member.size
                    if (path.is_absolute() or '..' in path.parts or not path.parts
                            or path.parts[0] != prefix or not member.isfile()
                            or total > 16 * 1024 * 1024):
                        raise ValueError('unexpected package archive entry')
                    destination = root / 'unpacked' / path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    stream = handle.extractfile(member)
                    if stream is None: raise ValueError('missing archive contents')
                    destination.write_bytes(stream.read())
        consumer = root / 'consumer'
        (consumer / 'src').mkdir(parents=True)
        manifest = '[package]\nname="sha1-packaged-consumer"\nversion="0.0.0"\nedition="2024"\n[workspace]\n'
        features = ', features=["execution"]' if args.execution else ', features=["cpu"]' if args.cpu else ''
        if args.hardened: features = ', features=["execution","hardened-execution"]'
        manifest += '[dependencies]\nbrynja-legacy-sha1 = { version="=0.1.0", default-features=false'+features+' }\n'
        if args.hardened:
            manifest += 'brynja-legacy-sha1-std = { version="=0.1.0", default-features=false, features=["runtime-hardened-execution"] }\n'
            manifest += '[features]\nhardened-execution=[]\nruntime-hardened-execution=[]\n'
        elif args.execution:
            manifest += 'brynja-legacy-sha1-std = { version="=0.1.0", features=["runtime-execution"] }\n'
            manifest += '[features]\nexecution=[]\n'
        elif args.cpu: manifest += 'brynja-legacy-sha1-std = "=0.1.0"\n'
        manifest += '[patch.crates-io]\n'
        for package, version in closure.items():
            manifest += f'{package} = {{ path="../unpacked/{package}-{version}" }}\n'
        (consumer / 'Cargo.toml').write_text(manifest)
        source = 'assurance/sha1-cpu-public-api/src/packaged.rs' if args.cpu else 'assurance/sha1-public-api/src/lib.rs'
        (consumer / 'src/lib.rs').write_bytes((ROOT / source).read_bytes())
        if args.hardened:
            import hardened_package
            hardened_package.prepare(ROOT, consumer)
        (consumer / 'tests/vectors').mkdir(parents=True, exist_ok=True)
        for name in ('api.rs', 'vectors/nist.txt'):
            (consumer / 'tests' / name).write_bytes((ROOT / 'crates/brynja-legacy-sha1/tests' / name).read_bytes())
        if args.execution:
            tests = consumer / 'tests'
            (tests / 'vectors').mkdir(parents=True, exist_ok=True)
            for name in ('execution.rs', 'vectors/nist.txt'):
                (tests / name).write_bytes((ROOT / 'crates/brynja-legacy-sha1/tests' / name).read_bytes())
            (tests / 'hosted.rs').write_bytes((ROOT / 'crates/brynja-legacy-sha1-std/tests/execution.rs').read_bytes())
            manifest = (consumer / 'Cargo.toml').read_text().replace('execution=[]', 'execution=[]\nruntime-execution=[]')
            (consumer / 'Cargo.toml').write_text(manifest)
            write_oracle(tests / 'oracle.rs')
        subprocess.run(['cargo', 'generate-lockfile', '--offline'], cwd=consumer, env=environment, check=True, timeout=60)
        subprocess.run(['cargo', 'test', '--locked', '--offline', '--all-features'], cwd=consumer, env=environment, check=True, timeout=180)
        scoped_checks(consumer, root, environment)
        if args.execution:
            ownership_negatives(consumer, environment)
            compiled_regressions(consumer, root, environment)
        if args.hardened:
            hardened_package.negatives(consumer, environment)
            hardened_package.mutants(consumer, root, environment)
    print(f'SHA-1 packaged closure and external consumer: PASS; cpu={args.cpu}; execution={args.execution}; hardened={args.hardened}; no upload')


def scoped_checks(consumer, root, environment):
    source = consumer / 'src/lib.rs'
    original = source.read_text()
    api = 'brynja_legacy_sha1::hardened_in_place::'
    negatives = [(f'fn bound<T:{bound}>() {{}} fn check() {{ bound::<{api}{owner}>(); }}', 'E0277')
                 for owner in ('Sha1Workspace', "Sha1<'static>")
                 for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug')]
    negatives += [(f'fn check(s: &{api}Sha1) {{ let _ = s.{method}(1); }}', 'E0599')
                  for method in ('check_additional_bits', 'check_additional_bytes')]
    negatives += [(f'fn check(s: {api}Sha1, out: &mut [u8]) {{ let _ = s.finalize_public(out); }}', 'E0061')]
    try:
        for text, code in negatives:
            source.write_text(text)
            result = subprocess.run(['cargo', 'check', '--locked', '--offline', '--all-features'],
                cwd=consumer, env=environment, capture_output=True, text=True, timeout=90)
            if result.returncode == 0 or f'error[{code}]' not in result.stderr:
                raise ValueError('scoped SHA-1 negative absent or wrong error: ' + result.stderr[-2000:])
    finally:
        source.write_text(original)
    # Test the actual unpacked dependency, with the consumer's exact path patches.
    command = ['cargo', 'test', '--locked', '--offline', '-p', 'brynja-legacy-sha1', '--lib', 'scoped_sha1']
    path = root / 'unpacked/brynja-legacy-sha1-0.1.0/src/hardened_in_place.rs'
    original = path.read_text()
    cases = (
        ('if !self.keep {', 'if false {'),
        ('self.owner.wipe();\n        // Public IV', 'core::hint::black_box(&mut self.owner);\n        // Public IV'),
        ('fn drop(&mut self) {\n        self.owner.wipe();', 'fn drop(&mut self) {\n        core::hint::black_box(&mut self.owner);'),
        ('self.owner.chaining_state.copy_from_slice(&[', 'self.owner.chaining_state.copy_from_slice(&[1 ^'),
        ('let result = engine::update(cleanup.owner, input);', 'let result = engine::update(cleanup.owner, &[]);'),
        ('self.active = false;', 'self.active = true;'),
        ('output::failed(destination, Sha1Error::OutputLength)', 'Sha1Error::OutputLength'),
        ('destination.copy_from_slice(&self.owner.output_staging);', 'core::hint::black_box(destination);'),
        ('self.stage(tail)?;\n        initialization', 'initialization'),
    )
    for profile in ([], ['--release']):
        subprocess.run(command + profile, cwd=consumer, env=environment, check=True, capture_output=True, timeout=180)
        for before, after in cases:
            if before not in original: raise ValueError('stale scoped mutation: ' + before)
            try:
                path.write_text(original.replace(before, after))
                result = subprocess.run(command + profile, cwd=consumer, env=environment,
                    capture_output=True, text=True, timeout=180)
                if result.returncode == 0 or 'test result: FAILED' not in result.stdout:
                    raise ValueError('scoped mutant survived or failed compilation: ' + before + '\n' + result.stdout[-1800:] + result.stderr[-2000:])
            finally:
                path.write_text(original)
    print(f'Scoped SHA-1 packaged negatives: {len(negatives)}; compiled regressions: {2 * len(cases)} rejected')


def write_oracle(destination):
    spec = importlib.util.spec_from_file_location('sha1_oracle', ROOT / 'scripts/sha1/check-sha1-differential.py')
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    rng = random.Random(0x2441)
    rows = []
    for bits in sorted(set(range(1040)) | {rng.randrange(65537) for _ in range(96)}):
        data = bytearray(rng.randbytes((bits + 7) // 8))
        if bits % 8: data[-1] &= (255 << (8 - bits % 8)) & 255
        expected = bytes.fromhex(oracle.oracle(data, bits))
        valid = (bits - 1) % 8 + 1 if bits else 0
        rows.append(f'(&{list(data)}, {valid}, {list(expected)})')
    source = '''use brynja_legacy_sha1::{BitString, execution::{Executor, Mode, PublicData, Error}};
#[test]
fn independent_all_boundary_bit_oracle() -> Result<(), Error> {
 let cases: &[(&[u8],u8,[u8;20])] = &[CASES];
 let hosted = brynja_legacy_sha1_std::execution::select(Mode::Prefer);
 assert!(hosted.is_ok());
 let mut owners = vec![Executor::portable(), Executor::for_compiled_target(Mode::Prefer)?];
 if let Ok(hosted) = hosted { owners.push(hosted); }
 for owner in owners {
  for (bytes, valid, expected) in cases {
   let bits = BitString::new(bytes,*valid).map_err(|_| Error::MessageTooLong)?;
   assert_eq!(owner.hash_bits(bits,PublicData::acknowledge())?,*expected);
  }
 }
 Ok(())
}
'''
    destination.write_text(source.replace('CASES', ',\n'.join(rows)))
    print(f'Independent operational SHA-1 corpus: {len(rows)} bit-message cases')


def ownership_negatives(consumer, environment):
    path = consumer / 'src/lib.rs'
    before = path.read_text()
    cases = []
    for owner in ('Authority', 'Executor', "Stream<'static>"):
        for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
            cases.append((f'fn check<T: {bound}>() {{}}\nfn use_it() {{ check::<brynja_legacy_sha1::execution::{owner}>(); }}', 'E0277'))
    cases.extend([
        ('fn check() { let _ = brynja_legacy_sha1::execution::Authority::from_platform(brynja_legacy_sha1::Sha1Backend::X86Sha, |_| true); }', 'E0133'),
        ('fn check(o: &brynja_legacy_sha1::execution::Authority) { let _ = o.session(); }', 'E0624'),
        ('fn check(o: &brynja_legacy_sha1::execution::Executor) { let _ = o.hash(b"abc"); }', 'E0061'),
        ('fn check(o: brynja_legacy_sha1::execution::Report) { let _ = brynja_legacy_sha1::execution::Executor::with_authority(o); }', 'E0308'),
    ])
    try:
        for source, code in cases:
            path.write_text(source)
            result = subprocess.run(['cargo', 'check', '--locked', '--offline', '--all-features'],
                cwd=consumer, env=environment, text=True, capture_output=True, timeout=90)
            if result.returncode == 0 or f'error[{code}]' not in result.stderr:
                raise ValueError('ownership rejection was absent or failed for the wrong reason: '+result.stderr[-2000:])
    finally:
        path.write_text(before)
    print(f'Packaged operational SHA-1 ownership/classification negatives: {len(cases)} rejected')


def compiled_regressions(consumer, root, environment):
    path = root / 'unpacked/brynja-legacy-sha1-0.1.0/src/execution.rs'
    before = path.read_text()
    mutants = [
        before.replace('self.revoked.set(true);', 'self.revoked.set(false);'),
        before.replace('pub fn finalize(mut self) -> Result<[u8; 20], Error> {\n        self.executor.ready()?;',
                       'pub fn finalize(mut self) -> Result<[u8; 20], Error> {'),
    ]
    try:
        for source in mutants:
            if source == before:
                raise ValueError('stale compiled operational regression')
            path.write_text(source)
            for profile in ([], ['--release']):
                result = subprocess.run(['cargo', 'test', '--locked', '--offline', '--all-features',
                    '--test', 'execution', *profile, 'revocation_empty_updates_capacity_and_finalization_fail_closed'],
                    cwd=consumer, env=environment, text=True, capture_output=True, timeout=90)
                if result.returncode == 0 or 'test result: FAILED' not in result.stdout:
                    raise ValueError('operational mutant survived or did not compile: '+result.stderr[-2000:])
    finally:
        path.write_text(before)
    print('Operational SHA-1 compiled revocation/finalization regressions: 4 rejected')


if __name__ == '__main__': main()
