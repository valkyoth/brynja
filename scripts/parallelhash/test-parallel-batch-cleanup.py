#!/usr/bin/env python3
"""Compile cleanup omissions in isolated sources; require inspector rejection."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

SPEC = importlib.util.spec_from_file_location('parallel_cleanup_driver', Path(__file__).with_name('check-parallel-batch-cleanup.py'))
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)


def main():
    args = driver.arguments()
    with tempfile.TemporaryDirectory(prefix='brynja-parallel-cleanup-source-') as directory:
        root = Path(directory)
        for package in ('brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu', 'brynja-crypto-cpu-std',
                        'brynja-hash-sha2', 'brynja-hash-sha3', 'brynja-hash-parallel', 'brynja-hash-parallel-std'):
            shutil.copytree(driver.ROOT / 'crates' / package, root / 'crates' / package,
                            ignore=shutil.ignore_patterns('target'))
        (root / 'Cargo.toml').write_text((driver.ROOT / 'Cargo.toml').read_text().replace(
            'default-members = ["crates/brynja"]', 'default-members = ["crates/brynja-hash-parallel"]'))
        subprocess.run(['cargo', '+' + args.toolchain, 'generate-lockfile', '--offline'],
                       cwd=root, env=os.environ, check=True, timeout=60)
        target = root / 'target'
        count = 0
        driver.check.check(driver.compile_row(root, target, args.toolchain, args.target, 'unwind'), 'unwind')
        worker_path = root / 'crates/brynja-hash-parallel-std/src/execution/batch/worker.rs'
        original = worker_path.read_text()
        worker_target = root / 'workers'
        driver.worker.check(driver.compile_row(root, worker_target, args.toolchain, args.target, 'unwind', True), 'unwind')
        for before, after in (
            ('for slot in &mut self.0 {', 'for slot in self.0.iter_mut().skip(1) {'),
            ('for slot in &mut self.0 {', 'for slot in self.0.iter_mut().take(1) {'),
            ('clear_owned_region(slot.as_flattened_mut())', 'clear_owned_region(&mut slot.as_flattened_mut()[..255])'),
            ('self.clear();\n        #[cfg(test)]', '// omitted storage clear\n        #[cfg(test)]'),
        ):
            driver.check.require(original.count(before) == 1, 'unique worker source mutation')
            try:
                worker_path.write_text(original.replace(before, after))
                row = driver.compile_row(root, worker_target, args.toolchain, args.target, 'unwind', True)
                try:
                    driver.worker.check(row, 'unwind')
                except (ValueError, driver.worker.flow.MirCleanupFlowError):
                    count += 1
                else:
                    raise AssertionError('compiled worker cleanup regression survived')
            finally:
                worker_path.write_text(original)
        driver.worker.check(driver.compile_row(root, worker_target, args.toolchain, args.target, 'unwind', True), 'unwind')
        base = root / 'crates/brynja-hash-parallel/src/execution'
        for file, before, after in (
            ('batch.rs', 'clear_owned_region(self.values.as_flattened_mut())', 'clear_owned_region(&mut self.staging)'),
            ('batch.rs', 'self.hash.clear();', '// omitted nested hash clear'),
            ('batch.rs', 'fn drop(&mut self) {\n        self.clear();', 'fn drop(&mut self) {'),
            ('batch/transfer.rs', 'clear_owned_region(self.values.as_flattened_mut())', 'clear_owned_region(self.values[..3].as_flattened_mut())'),
            ('stream/batch.rs', 'clear_owned_region(self.workspace)', 'clear_owned_region(&mut self.workspace[..1])'),
            ('stream/batch.rs', 'clear_owned_region(&mut self.used)', 'clear_owned_region(&mut self.input_bits)'),
            ('stream/batch.rs', 'self.root.cancel();', '// omitted root cancellation'),
            ('stream/batch.rs', 'fn drop(&mut self) {\n        self.cancel();', 'fn drop(&mut self) {'),
            ('stream/batch.rs', 'if !self.complete {', 'if self.complete {'),
            ('stream/batch/output.rs', 'self.stream.cancel();', '// omitted reader cancellation'),
        ):
            path = base / file
            original = path.read_text()
            # Some buffer clears occur in flush as well; mutate the exact cancel
            # implementation for this compiler obligation, not earlier paths.
            prefix, suffix = '', original
            if file == 'stream/batch.rs' and 'clear_owned_region' in before:
                prefix, suffix = original.split('pub fn cancel(&mut self) {', 1)
                prefix += 'pub fn cancel(&mut self) {'
            driver.check.require(suffix.count(before) == 1, 'unique ParallelHash source mutation')
            try:
                path.write_text(prefix + suffix.replace(before, after))
                row = driver.compile_row(root, target, args.toolchain, args.target, 'unwind')
                driver.check.reject(row, 'unwind')
                count += 1
            finally:
                path.write_text(original)
        driver.check.check(driver.compile_row(root, target, args.toolchain, args.target, 'unwind'), 'unwind')
    print(f'ParallelHash cleanup: PASS; {count} compiled source regressions rejected; {args.toolchain}; {args.target}')


if __name__ == '__main__':
    main()
