#!/usr/bin/env python3
"""Semantic (rehash-resistant) and compiled cleanup regressions."""
import argparse
import importlib.util
from pathlib import Path
import tempfile
import shutil
import keccak_hardened_policy as policy

spec = importlib.util.spec_from_file_location('acceptance', Path(__file__).with_name('check-keccak-hardened.py'))
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


def semantic():
    cases = [(path, f'clear_owned_region(&mut self.{field})', 'Ok::<(), ()>(())')
             for path, fields in policy.REGIONS.items() for field in fields]
    cases += [
        (policy.CPU + '/src/hardened_execution/keccak.rs', 'if !correct {', 'if false {'),
        (policy.CPU + '/src/hardened_execution/keccak.rs', 'self.check()?;', 'let _ = self;'),
        (policy.ENGINE, 'self.failed = true;', 'self.failed = false;'),
        (policy.HASH + '/src/hardened/accelerated/mod.rs', ': sealed::State', ''),
        (policy.HASH + '/src/hardened/accelerated/reader.rs', 'clear_owned_region(self.0)', 'Ok::<(), ()>(())'),
        (policy.HASH + '/Cargo.toml', 'default = []', 'default = ["hardened-execution"]'),
    ]
    with tempfile.TemporaryDirectory(prefix='brynja-keccak-policy-') as temporary:
        root = Path(temporary)
        for package in (policy.CPU, policy.HASH):
            shutil.copytree(policy.ROOT / package, root / package, ignore=shutil.ignore_patterns('target'))
        policy.semantic(root)
        for name, before, after in cases:
            path = root / name
            original = path.read_text()
            policy.require(before in original, 'stale mutation')
            try:
                path.write_text(original.replace(before, after))
                try:
                    policy.semantic(root)
                except ValueError:
                    continue
                raise AssertionError('semantic mutant escaped: ' + before)
            finally:
                path.write_text(original)
    print(f'Hardened Keccak semantic policy rejects {len(cases)} regressions')


def compiled():
    with tempfile.TemporaryDirectory(prefix='brynja-keccak-mutants-') as temporary:
        destination = Path(temporary)
        env = acceptance.environment(destination)
        _, roots = acceptance.package(destination, env)
        patches = '\n[patch.crates-io]\n' + '\n'.join(
            f'{name}={{path="{root.as_posix()}"}}' for name, root in roots.items()) + '\n'
        for root in roots.values():
            manifest = root / 'Cargo.toml'
            manifest.write_text(manifest.read_text() + patches)
        cases = []
        for source, fields in policy.REGIONS.items():
            package, relative = source.split('/src/', 1)
            root = roots[Path(package).name]
            owner = 'KeccakScratch' if package == policy.CPU else 'Memory'
            path = root / 'src' / relative
            original = path.read_text()
            marker = f'impl Drop for {owner} {{\n    fn drop(&mut self) {{\n        self.wipe();'
            policy.require(original.count(marker) == 1, 'exact live Drop observer')
            observations = '\n'.join(f'assert!(self.{field}.iter().all(|b| *b == 0), "live Drop region {field}");' for field in fields)
            fill = '\n'.join(f'value.{field}.fill(0xa5);' for field in fields)
            instrumented = original.replace(marker, marker + '\n' + observations)
            instrumented += f'\n#[test]\nfn live_drop_probe() {{ let mut value={owner}::new(); {fill} drop(value); }}\n'
            path.write_text(instrumented)
            test = 'live_drop_probe'
            command = ['cargo', 'test', '--offline', '--manifest-path', str(root / 'Cargo.toml'),
                       '--features', 'hardened-execution', '--lib', test]
            for profile in ([], ['--release']):
                acceptance.ordinary.run(command + profile, root, env)
            for field in fields:
                cases.append((root, path, field, command))
        for root, path, field, command in cases:
            original = path.read_text()
            before = f'clear_owned_region(&mut self.{field})'
            policy.require(before in original, 'stale compiled cleanup mutation')
            try:
                path.write_text(original.replace(before, 'Ok::<(), ()>(())'))
                for profile in ([], ['--release']):
                    result = acceptance.ordinary.run(command + profile, root, env, success=False)
                    policy.require('live Drop region ' + field in result.stdout, 'live destructor rejection')
            finally:
                path.write_text(original)
    print('Hardened Keccak rejects 22 compiled debug/release region-removal mutants')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--compiled', action='store_true')
    args = parser.parse_args()
    policy.validate()
    semantic()
    if args.compiled:
        compiled()


if __name__ == '__main__':
    main()
