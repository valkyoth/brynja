#!/usr/bin/env python3
"""Require the compiler inspector to reject real wrong-region/omitted-cleanup Rust."""
import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

SPEC = importlib.util.spec_from_file_location('batch_codegen_driver', Path(__file__).with_name('check-hardened-sha2-batch-codegen.py'))
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=('1.90.0', '1.98.1'), default='1.98.1')
    parser.add_argument('--target', choices=('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-musl',
                                            'aarch64-apple-darwin'), default='x86_64-unknown-linux-gnu')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='brynja-sha2-cleanup-source-') as directory:
        root = Path(directory)
        for package in ('brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu', 'brynja-hash-sha2'):
            shutil.copytree(driver.ROOT / 'crates' / package, root / 'crates' / package,
                            ignore=shutil.ignore_patterns('target'))
        manifest = (driver.ROOT / 'Cargo.toml').read_text().replace(
            'default-members = ["crates/brynja"]', 'default-members = ["crates/brynja-hash-sha2"]')
        (root / 'Cargo.toml').write_text(manifest)
        subprocess.run(['cargo', '+' + args.toolchain, 'generate-lockfile', '--offline'],
                       cwd=root, env=os.environ, check=True, timeout=60)
        target = root / 'target'
        row = driver.compile_row(root, target, args.toolchain, args.target, 'unwind')
        driver.check.check(row, 'unwind')
        count = 0
        for module in ('hardened_batch', 'hardened_batch512'):
            base = root / 'crates/brynja-hash-sha2/src' / module
            for file, before, after in (
                ('workspace.rs', 'clear_owned_region(self.states.as_flattened_mut())',
                 'clear_owned_region(self.packed.as_flattened_mut())'),
                ('workspace.rs', 'self.scalar.wipe();', '// omitted scalar wipe'),
                ('workspace.rs', 'self.wipe();', '// omitted destructor wipe'),
                ('mod.rs', 'self.workspace.wipe();', '// omitted operation cleanup'),
            ):
                path = base / file
                original = path.read_text()
                driver.check.require(original.count(before) == 1, 'unique source mutation')
                try:
                    path.write_text(original.replace(before, after))
                    # Compilation must succeed; compiler errors are not inspector rejections.
                    mutant = driver.compile_row(root, target, args.toolchain, args.target, 'unwind')
                    driver.check.reject(mutant, 'unwind')
                    count += 1
                finally:
                    path.write_text(original)
        restored = driver.compile_row(root, target, args.toolchain, args.target, 'unwind')
        driver.check.check(restored, 'unwind')
    print(f'Hardened SHA-2 batch compiler: {count} compiled source regressions rejected; '
          f'{args.toolchain}; {args.target}')


if __name__ == '__main__':
    main()
