#!/usr/bin/env python3
"""Exercise the real MD5 consumer against packaged, not workspace, sources."""
import argparse
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLOSURE = {'brynja-core': '0.9.0', 'brynja-hash-core': '0.1.0', 'brynja-legacy-md5': '0.1.0'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cpu', action='store_true')
    parser.add_argument('--execution', action='store_true')
    parser.add_argument('--hardened', action='store_true')
    args = parser.parse_args()
    closure = dict(CLOSURE)
    if args.cpu or args.execution or args.hardened: closure['brynja-legacy-md5-std'] = '0.1.0'
    with tempfile.TemporaryDirectory(prefix='brynja-md5-package-') as temporary:
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
        manifest = '[package]\nname="md5-packaged-consumer"\nversion="0.0.0"\nedition="2024"\n[workspace]\n'
        features = ', features=["cpu"]' if args.cpu else ''
        if args.execution: features = ', features=["execution"]'
        if args.hardened: features = ', features=["hardened-execution","execution"]'
        manifest += '[dependencies]\nbrynja-legacy-md5 = { version="=0.1.0", default-features=false'+features+' }\n'
        if args.cpu: manifest += 'brynja-legacy-md5-std = "=0.1.0"\n'
        if args.execution:
            manifest += 'brynja-legacy-md5-std = {version="=0.1.0", default-features=false, features=["runtime-execution"]}\n'
            manifest += '[features]\ndefault=["execution","runtime-execution"]\nexecution=[]\nruntime-execution=[]\n'
        if args.hardened:
            manifest += 'brynja-legacy-md5-std = {version="=0.1.0", default-features=false, features=["runtime-hardened-execution"]}\n'
            manifest += '[features]\ndefault=["hardened-execution","runtime-hardened-execution"]\nhardened-execution=[]\nruntime-hardened-execution=[]\n'
        manifest += '[patch.crates-io]\n'
        for package, version in closure.items():
            manifest += f'{package} = {{ path="../unpacked/{package}-{version}" }}\n'
        (consumer / 'Cargo.toml').write_text(manifest)
        source = 'assurance/md5-cpu-public-api/src/packaged.rs' if args.cpu else 'assurance/md5-public-api/src/lib.rs'
        (consumer / 'src/lib.rs').write_bytes((ROOT / source).read_bytes())
        if args.execution:
            import execution_package
            execution_package.prepare(consumer, root)
        if args.hardened:
            import md5_hardened_package
            md5_hardened_package.prepare(consumer, root)
        (consumer / 'tests/vectors').mkdir(parents=True, exist_ok=True)
        for name in ('api.rs', 'vectors/rfc1321.txt'):
            (consumer / 'tests' / name).write_bytes((ROOT / 'crates/brynja-legacy-md5/tests' / name).read_bytes())
        subprocess.run(['cargo', 'generate-lockfile', '--offline'], cwd=consumer, env=environment, check=True, timeout=60)
        subprocess.run(['cargo', 'test', '--locked', '--offline'], cwd=consumer, env=environment, check=True, timeout=180)
        scoped_checks(consumer, root, environment)
        if args.execution: execution_package.check(consumer, root, environment)
        if args.hardened: md5_hardened_package.check(consumer, root, environment)
    print(f'MD5 packaged closure and external consumer: PASS; cpu={args.cpu}; no upload')


def scoped_checks(consumer, root, environment):
    source = consumer / 'src/lib.rs'
    original = source.read_text()
    api = 'brynja_legacy_md5::hardened_in_place::'
    negatives = [(f'fn bound<T:{bound}>() {{}} fn check() {{ bound::<{api}{owner}>(); }}', 'E0277')
                 for owner in ('Md5Workspace', "Md5<'static>")
                 for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug')]
    negatives += [(f'fn check(s: &{api}Md5) {{ let _ = s.{method}(1); }}', 'E0599')
                  for method in ('check_additional_bits', 'check_additional_bytes')]
    negatives += [(f'fn check(s: {api}Md5, out: &mut [u8]) {{ let _ = s.finalize_public(out); }}', 'E0061')]
    try:
        for text, code in negatives:
            source.write_text(text)
            result = subprocess.run(['cargo', 'check', '--locked', '--offline', '--all-features'],
                cwd=consumer, env=environment, capture_output=True, text=True, timeout=90)
            if result.returncode == 0 or f'error[{code}]' not in result.stderr:
                raise ValueError('scoped MD5 negative absent or wrong error: ' + result.stderr[-2000:])
    finally:
        source.write_text(original)
    # Test the actual unpacked dependency, with the consumer's exact path patches.
    command = ['cargo', 'test', '--locked', '--offline', '-p', 'brynja-legacy-md5', '--lib', 'scoped_md5']
    path = root / 'unpacked/brynja-legacy-md5-0.1.0/src/hardened_in_place.rs'
    original = path.read_text()
    cases = (
        ('if !self.keep {', 'if false {'),
        ('self.owner.wipe();\n        // Public IV', 'core::hint::black_box(&mut self.owner);\n        // Public IV'),
        ('fn drop(&mut self) {\n        self.owner.wipe();', 'fn drop(&mut self) {\n        core::hint::black_box(&mut self.owner);'),
        ('self.owner.chaining_state.copy_from_slice(&[', 'self.owner.chaining_state.copy_from_slice(&[1 ^'),
        ('let result = engine::update(cleanup.owner, input);', 'let result = engine::update(cleanup.owner, &[]);'),
        ('self.active = false;', 'self.active = true;'),
        ('output::failed(destination, Md5Error::OutputLength)', 'Md5Error::OutputLength'),
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
    print(f'Scoped MD5 packaged negatives: {len(negatives)}; compiled regressions: {2 * len(cases)} rejected')


if __name__ == '__main__': main()
