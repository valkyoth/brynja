"""Compile checkpoint regressions, not malformed-IR-only negative tests."""
from pathlib import Path

from legacy_hmac_hosted_compiled_fixture import prepare


class CheckpointCompiledTests:
    def test_compiled_accelerated_checkpoint_defects(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'checkpoint-mutants'
        leaf, fixture = prepare(d, work)
        count = 0
        for target, directory in ((d.TARGETS[0], 'strict_execution'), (d.TARGETS[2], 'macos_resident')):
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True,
                              fixture / 'Cargo.toml', leaf / 'Cargo.toml')
            h.validate(emit(), target, 'unwind')
            path = leaf / 'src' / directory / 'sha1_compiled/worker.rs'
            original = path.read_text()
            begin, end = original.index('    drop('), original.index('\npub(super) fn run(')
            checkpoint = original[begin:end]
            start = checkpoint[:checkpoint.index('    super::super::worker::checkpoint(cancel)')]
            variants = [
                checkpoint.replace('drop(', 'core::mem::forget(', 1),
                checkpoint.replace('Error::Mac(brynja_legacy_hmac::Error::ExecutionFailed)', 'Error::Invariant'),
                checkpoint.replace('super::super::worker::checkpoint(cancel)', 'Ok(())'),
                checkpoint.replace('super::super::worker::checkpoint(cancel)',
                                   'super::super::worker::checkpoint(cancel).or(Ok(()))'),
                '    super::super::worker::checkpoint(cancel)?;\n' + checkpoint,
                start + checkpoint,
                checkpoint.replace('drop(', 'let retained = (', 1).replace(
                    '    super::super::worker::checkpoint(cancel)',
                    '    super::super::worker::checkpoint(cancel)?;\n    drop(retained);\n    Ok(())'),
            ]
            for mutant in variants:
                self.assertNotEqual(mutant, checkpoint)
                try:
                    path.write_text(original[:begin] + mutant + original[end:])
                    artifacts = emit()  # A compile error is NOT a successful rejection.
                    with self.subTest(target=target, mutation=count), self.assertRaises(ValueError):
                        h.validate(artifacts, target, 'unwind')
                finally:
                    path.write_text(original)
                count += 1
            marker = 'checkpoint(&owner, cancel)?;'
            offsets = [i for i in range(len(original)) if original.startswith(marker, i)]
            self.assertEqual(len(offsets), 6)
            for at in offsets:
                # Remove one of six call sites while retaining the real helper
                # and the other five: counting helper definitions cannot pass.
                for replacement in ('/* missing checkpoint */', marker.replace('?', '.ok()')):
                    try:
                        path.write_text(original[:at] + replacement + original[at + len(marker):])
                        artifacts = emit()
                        with self.subTest(target=target, site=at, replacement=replacement), self.assertRaises(ValueError):
                            h.validate(artifacts, target, 'unwind')
                    finally:
                        path.write_text(original)
                    count += 1
            h.validate(emit(), target, 'unwind')
        self.assertEqual(count, 38)
        print('Accelerated checkpoint: 38 compiled Rust defects rejected; restored baselines pass', flush=True)
