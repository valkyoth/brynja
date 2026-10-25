"""Compile private worker defects, keeping repository production files untouched."""
from pathlib import Path
import re
from legacy_hmac_hosted_compiled_fixture import prepare


class StreamCompiledTests:
    def test_compiled_stream_input_output_and_checkpoints(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'stream-mutants'
        leaf, fixture = prepare(d, work)
        count = 0
        for target, directory in ((d.TARGETS[0], 'strict_execution'), (d.TARGETS[2], 'macos_resident')):
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True,
                              fixture / 'Cargo.toml', leaf / 'Cargo.toml')
            h.validate(emit(), target, 'unwind')
            for file in ('worker.rs', 'sha1_compiled/worker.rs'):
                path = leaf / 'src' / directory / file
                original = path.read_text()
                checkpoint = 'checkpoint(cancel)?;' if file == 'worker.rs' else 'checkpoint(&owner, cancel)?;'
                anchor = '.finalize_bits_secret(tail, staging)\n            .map_err(Error::Mac)?;\n        ' + checkpoint
                forgotten = anchor.rsplit('\n', 1)[0] + '\n        if let Err(error) = ' + checkpoint[:-2] + ' {'
                forgotten += ' core::mem::forget(secret); return Err(error); }'
                variants = [
                    original.replace('chunk.chunks(4096)', 'chunk.chunks(4095)'),
                    original.replace('.chain(core::iter::once(complete))', '.chain(core::iter::once(request.tail.bytes))'),
                    original.replace('request.tail.valid_bits == 8', 'request.tail.valid_bits == 7'),
                    original.replace('            request.tail.valid_bits\n', '            8\n'),
                    original.replace('state.update(part).map_err(Error::Mac)?;',
                                     'for _ in 0..request.tail.valid_bits { state.update(part).map_err(Error::Mac)?; }'),
                    original.replace(anchor, forgotten),
                    original.replace('        let secret = state', '        let staging_len = staging.len().saturating_sub(1);\n        let secret = state')
                            .replace('.finalize_bits_secret(tail, staging)', '.finalize_bits_secret(tail, &mut staging[..staging_len])'),
                ]
                self.assertIn(anchor, original)
                if file == 'worker.rs':
                    # Each scalar checkpoint separately, plus ignored failure.
                    offsets = [match.start() for match in re.finditer(re.escape(checkpoint), original)]
                    self.assertEqual(len(offsets), 6)
                    variants.extend(original[:at] + '/* missing checkpoint */' + original[at + len(checkpoint):]
                                    for at in offsets)
                    variants.append(original.replace(checkpoint, checkpoint.replace('?', '.ok()'), 1))
                for mutant in variants:
                    self.assertNotEqual(mutant, original)
                    try:
                        path.write_text(mutant)
                        artifacts = emit()  # Compilation failures are failures, not credited rejections.
                        with self.subTest(target=target, file=file, mutation=count), self.assertRaises(ValueError):
                            h.validate(artifacts, target, 'unwind')
                    finally:
                        path.write_text(original)
                    count += 1
                h.validate(emit(), target, 'unwind')
        self.assertEqual(count, 42)
        print('Legacy streaming workers: 42 compiled input/output/checkpoint defects rejected; restored baselines pass', flush=True)
