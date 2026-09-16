#!/usr/bin/env python3
"""Require actual compiled SHA-3 cleanup regressions to fail the artifact inspector."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

SPEC = importlib.util.spec_from_file_location('sha3_batch_codegen', Path(__file__).with_name('check-hardened-sha3-batch-codegen.py'))
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)


def main():
    args = driver.arguments()
    with tempfile.TemporaryDirectory(prefix='brynja-sha3-cleanup-source-') as directory:
        root = Path(directory)
        for package in ('brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu', 'brynja-hash-sha3'):
            shutil.copytree(driver.ROOT / 'crates' / package, root / 'crates' / package,
                            ignore=shutil.ignore_patterns('target'))
        manifest = (driver.ROOT / 'Cargo.toml').read_text().replace(
            'default-members = ["crates/brynja"]', 'default-members = ["crates/brynja-hash-sha3"]')
        (root / 'Cargo.toml').write_text(manifest)
        subprocess.run(['cargo', '+' + args.toolchain, 'generate-lockfile', '--offline'],
                       cwd=root, env=os.environ, check=True, timeout=60)
        target = root / 'target'
        driver.check.check(driver.compile_row(root, target, args.toolchain, args.target, 'unwind'), 'unwind')
        base = root / 'crates/brynja-hash-sha3/src/hardened_batch'
        count = 0
        for file, before, after in (
            ('workspace.rs', 'clear_owned_region(self.states.as_flattened_mut())',
             'clear_owned_region(self.vector.as_flattened_mut())'),
            ('workspace.rs', 'clear_owned_region(self.starts.as_flattened_mut())',
             'clear_owned_region(self.written.as_flattened_mut())'),
            ('workspace.rs', 'for frame in &mut self.frames {', 'for frame in &mut self.frames[..3] {'),
            ('workspace.rs', 'self.scalar.wipe();', '// omitted scalar clear'),
            ('framing.rs', 'clear_owned_region(self.cursor.as_flattened_mut())',
             'clear_owned_region(&mut self.cursor.as_flattened_mut()[..31])'),
            ('framing.rs', 'clear_owned_region(&mut self.suffix)', 'Ok::<(), ()>(())'),
            ('framing.rs', 'fn drop(&mut self) {\n        self.wipe();', 'fn drop(&mut self) {'),
            ('workspace.rs', 'fn drop(&mut self) {\n        self.wipe();', 'fn drop(&mut self) {'),
            ('mod.rs', 'self.workspace.wipe();', '// omitted operation clear'),
        ):
            path = base / file
            original = path.read_text()
            driver.check.require(original.count(before) == 1, 'unique compiled mutation anchor')
            try:
                path.write_text(original.replace(before, after))
                # A compile error cannot substitute for an inspector rejection.
                row = driver.compile_row(root, target, args.toolchain, args.target, 'unwind')
                driver.check.reject(row, 'unwind')
                count += 1
            finally:
                path.write_text(original)
        driver.check.check(driver.compile_row(root, target, args.toolchain, args.target, 'unwind'), 'unwind')
    print(f'Hardened SHA-3 compiler: {count} compiled source regressions rejected; '
          f'{args.toolchain}; {args.target}')


if __name__ == '__main__':
    main()
