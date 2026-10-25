"""Compile real MD5 worker defects and require downstream rejection."""
from pathlib import Path

from legacy_hmac_hosted_compiled_fixture import prepare


class Md5CompiledTests:
    def test_compiled_md5_health_checkpoint_defects(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'md5-checkpoint-mutants'
        leaf, fixture = prepare(d, work)
        count = 0
        for target, directory in ((d.TARGETS[0], 'strict_execution'), (d.TARGETS[2], 'macos_resident')):
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True,
                              fixture / 'Cargo.toml', leaf / 'Cargo.toml')
            h.validate(emit(), target, 'unwind')
            path = leaf / 'src' / directory / 'md5_compiled/worker.rs'
            original = path.read_text()
            variants = []
            # Keep compilation valid; removing or ignoring each call must fail
            # qualification even when all other checkpoints remain intact.
            for marker, expected in (('healthy(&owner)?;', 2), ('checkpoint(&owner, cancel)?;', 3)):
                offsets = [i for i in range(len(original)) if original.startswith(marker, i)]
                self.assertEqual(len(offsets), expected)
                for at in offsets:
                    for replacement in ('/* missing validation */', marker.replace('?', '.ok()')):
                        variants.append(original[:at] + replacement + original[at + len(marker):])
            begin = original.index('fn checkpoint(')
            end = original.index('\nfn report(', begin)
            checkpoint = original[begin:end]
            for replacement in (
                    checkpoint.replace('healthy(owner)?;', 'let _ = healthy(owner);'),
                    checkpoint.replace('healthy(owner)?;', 'healthy(owner).map_err(|_| Error::Invariant)?;'),
                    checkpoint.replace('    healthy(owner)?;\n    cancel.check()',
                                       '    cancel.check()?;\n    healthy(owner)'),
                    checkpoint.replace('cancel.check()', 'Ok(())'),
                    checkpoint.replace('cancel.check()', 'cancel.check().or(Ok(()))')):
                variants.append(original[:begin] + replacement + original[end:])
            for mutant in variants:
                self.assertNotEqual(mutant, original)
                try:
                    path.write_text(mutant)
                    artifacts = emit()  # Compilation failure is not a passing negative test.
                    with self.subTest(target=target, mutation=count), self.assertRaises(ValueError):
                        h.validate(artifacts, target, 'unwind')
                finally:
                    path.write_text(original)
                count += 1
            h.validate(emit(), target, 'unwind')
        self.assertEqual(count, 30)
        print('MD5 checkpoints/health: 30 compiled Rust defects rejected; restored baselines pass', flush=True)
