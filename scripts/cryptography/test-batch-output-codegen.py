#!/usr/bin/env python3
"""Require actual compiled output cleanup regressions to fail LLVM inspection."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

SPEC = importlib.util.spec_from_file_location('output_driver', Path(__file__).with_name('check-batch-output-codegen.py'))
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)


def main():
    args = driver.arguments()
    with tempfile.TemporaryDirectory(prefix='brynja-output-cleanup-source-') as directory:
        root = Path(directory)
        for package in ('brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu', 'brynja-hash-sha2', 'brynja-hash-sha3'):
            shutil.copytree(driver.ROOT / 'crates' / package, root / 'crates' / package,
                            ignore=shutil.ignore_patterns('target'))
        (root / 'Cargo.toml').write_text((driver.ROOT / 'Cargo.toml').read_text().replace(
            'default-members = ["crates/brynja"]', 'default-members = ["crates/brynja-hash-sha2"]'))
        subprocess.run(['cargo', '+' + args.toolchain, 'generate-lockfile', '--offline'],
                       cwd=root, env=os.environ, check=True, timeout=60)
        count = 0
        for family, (package, module, _, _) in driver.FAMILIES.items():
            target = root / 'target' / package
            def compile_and_inspect():
                llvm = driver.compile_package(root, target, package, args.toolchain, args.target, 'unwind')
                return llvm
            driver.inspect(compile_and_inspect(), family)
            path = root / 'crates' / package / 'src' / module / 'output.rs'
            original = path.read_text()
            cases = [
                ('self.destinations.iter_mut().flatten()', 'self.destinations.iter_mut().take(CAPACITY - 1).flatten()'),
                ('self.destinations.iter_mut().flatten()', 'self.destinations.iter_mut().skip(1).flatten()'),
                ('if !destination.is_empty()', 'if destination.is_empty()'),
                ('clear_owned_region(destination)', 'clear_owned_region(&mut destination[..1])'),
            ]
            if family == 'sha512':
                cases.append(('clear_owned_region(self.identities.as_flattened_mut())', 'Ok::<(), ()>(())'))
            else:
                cases.append(('clear_owned_region(&mut self.identities)', 'Ok::<(), ()>(())'))
            if family == 'keccak':
                cases.append(('clear_owned_region(self.bits.as_flattened_mut())', 'Ok::<(), ()>(())'))
            for before, after in cases:
                driver.cleanup.require(original.count(before) == 1, 'unique output mutation anchor')
                try:
                    path.write_text(original.replace(before, after))
                    llvm = compile_and_inspect()  # Compilation errors do not count as rejection.
                    try:
                        driver.inspect(llvm, family)
                    except ValueError:
                        count += 1
                    else:
                        raise AssertionError('compiled output-cleanup regression survived: ' + before)
                finally:
                    path.write_text(original)
            driver.inspect(compile_and_inspect(), family)
    print(f'Batch output compiler: PASS; {count} compiled source regressions rejected; {args.toolchain}; {args.target}')


if __name__ == '__main__':
    main()
