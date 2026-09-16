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
        driver.arguments_check.check(driver.compile_row(root, worker_target, args.toolchain, args.target, 'unwind', True))
        for replacement in ('self.0.clear(); self.clear();',
                            'self.0.truncate(1); self.clear();',
                            'let _ = self.0.remove(0); self.clear();'):
            anchor = 'self.clear();\n        #[cfg(test)]'
            driver.check.require(original.count(anchor) == 1, 'unique worker argument source mutation')
            try:
                worker_path.write_text(original.replace(anchor, replacement + '\n        #[cfg(test)]'))
                row = driver.compile_row(root, worker_target, args.toolchain, args.target, 'unwind', True)
                llvm, assembly, symbol = driver.arguments_check.functions(row)
                for inspector, body in ((driver.arguments_check.llvm_check, llvm),
                                        (driver.arguments_check.assembly_check, assembly)):
                    try:
                        inspector(body, symbol)
                    except ValueError:
                        pass
                    else:
                        raise AssertionError('compiled worker argument regression survived')
                glue = driver.drop_glue.extract(row, 'unwind')
                driver.check.require(glue is not None, 'retained compiled mutant drop glue')
                llvm, assembly, symbol = glue
                for inspector, body in ((lambda body, symbol: driver.drop_glue.llvm_check(body, symbol, 'unwind'), llvm),
                                        (driver.drop_glue.assembly_check, assembly)):
                    try:
                        inspector(body, symbol)
                    except ValueError:
                        pass
                    else:
                        raise AssertionError('compiled worker drop-glue regression survived')
                count += 1
            finally:
                worker_path.write_text(original)
        driver.arguments_check.check(driver.compile_row(root, worker_target, args.toolchain, args.target, 'unwind', True))
        driver.drop_glue.check(driver.compile_row(root, worker_target, args.toolchain, args.target, 'unwind', True), 'unwind')
        driver.inline.check(driver.compile_row(root, worker_target, args.toolchain, args.target, 'unwind', True), 'unwind')
        driver.worker.check(driver.compile_row(root, worker_target, args.toolchain, args.target, 'unwind', True), 'unwind')
        driver.lifecycle.check(driver.compile_row(root, worker_target, args.toolchain, args.target, 'unwind', True), 'unwind')
        for before, after in (
            ('operation.complete = true;', 'core::mem::forget(storage);\n    operation.complete = true;'),
            ('operation.complete = true;', 'core::mem::forget(operation);'),
            ('operation.complete = true;', '// omitted successful completion'),
            ('complete: false,', 'complete: true,'),
            ('if !self.complete {', 'if self.complete {'),
        ):
            driver.check.require(original.count(before) == 1, 'unique lifecycle source mutation')
            try:
                worker_path.write_text(original.replace(before, after))
                row = driver.compile_row(root, worker_target, args.toolchain, args.target, 'unwind', True)
                try:
                    driver.lifecycle.check(row, 'unwind')
                except (ValueError, driver.worker.flow.MirCleanupFlowError):
                    count += 1
                else:
                    raise AssertionError('compiled worker lifecycle regression survived')
                if 'core::mem::forget(storage)' in after:
                    try:
                        driver.inline.check(row, 'unwind')
                    except ValueError:
                        pass
                    else:
                        raise AssertionError('compiled inlined storage omission survived')
            finally:
                worker_path.write_text(original)
        driver.lifecycle.check(driver.compile_row(root, worker_target, args.toolchain, args.target, 'unwind', True), 'unwind')
        driver.inline.check(driver.compile_row(root, worker_target, args.toolchain, args.target, 'unwind', True), 'unwind')
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
                # Loop regressions must independently fail both emitted levels;
                # removing Drop's call must fail the destructor MIR obligation.
                if before.startswith(('for ', 'clear_')):
                    inspectors = (driver.worker.check_llvm, driver.worker.check_assembly)
                else:
                    inspectors = (lambda artifacts: driver.worker.check_mir(artifacts, 'unwind'),)
                for inspector in inspectors:
                    try:
                        inspector(row)
                    except (ValueError, driver.worker.flow.MirCleanupFlowError):
                        pass
                    else:
                        raise AssertionError('compiled worker cleanup regression survived')
                count += 1
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
