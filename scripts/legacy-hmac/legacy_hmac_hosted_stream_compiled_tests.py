"""Compile private worker defects, keeping repository production files untouched."""
from pathlib import Path
import re
from legacy_hmac_hosted_compiled_fixture import prepare


TAIL_CALL = 'crate::common::split_tail!(request, complete, tail, Error);'


def replace_once(source, before, after):
    if source.count(before) != 1 or before == after:
        raise ValueError('missing/ambiguous legacy stream mutation anchor: ' + before)
    return source.replace(before, after, 1)


def tail_mutations(source):
    # These conditions moved into the shared macro. Mutate that real source,
    # not the obsolete inline spelling in its four worker callers.
    return [replace_once(source, before, after) for before, after in (
        ('$request.tail.valid_bits == 8', '$request.tail.valid_bits == 7'),
        ('                $request.tail.valid_bits\n', '                8\n'))]


def worker_mutations(source, scalar):
    if source.count(TAIL_CALL) != 1:
        raise ValueError('missing/ambiguous legacy stream split_tail invocation')
    checkpoint = 'checkpoint(cancel)?;' if scalar else 'checkpoint(&owner, cancel)?;'
    anchor = '.finalize_bits_secret(tail, staging)\n            .map_err(Error::Mac)?;\n        ' + checkpoint
    forgotten = anchor.rsplit('\n', 1)[0] + '\n        if let Err(error) = ' + checkpoint[:-2] + ' {'
    forgotten += ' core::mem::forget(secret); return Err(error); }'
    variants = [replace_once(source, before, after) for before, after in (
        ('chunk.chunks(4096)', 'chunk.chunks(4095)'),
        ('.chain(core::iter::once(complete))', '.chain(core::iter::once(request.tail.bytes))'),
        ('state.update(part).map_err(Error::Mac)?;',
         'for _ in 0..request.tail.valid_bits { state.update(part).map_err(Error::Mac)?; }'),
        (anchor, forgotten))]
    shortened = replace_once(source, '        let secret = state',
                             '        let staging_len = staging.len().saturating_sub(1);\n        let secret = state')
    variants.append(replace_once(shortened, '.finalize_bits_secret(tail, staging)',
                                 '.finalize_bits_secret(tail, &mut staging[..staging_len])'))
    if scalar:
        offsets = [match.start() for match in re.finditer(re.escape(checkpoint), source)]
        if len(offsets) != 6:
            raise ValueError('legacy scalar stream checkpoint population changed')
        variants.extend(source[:at] + '/* missing checkpoint */' + source[at + len(checkpoint):]
                        for at in offsets)
        variants.append(source.replace(checkpoint, checkpoint.replace('?', '.ok()'), 1))
    return variants


class StreamCompiledTests:
    def test_compiled_stream_input_output_and_checkpoints(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'stream-mutants'
        leaf, fixture = prepare(d, work)
        common = leaf / 'src/common.rs'
        common_source = common.read_text()
        shared_variants = tail_mutations(common_source)
        # Check every current anchor before paying for compiler emission.
        for directory in ('strict_execution', 'macos_resident'):
            for file in ('worker.rs', 'sha1_compiled/worker.rs'):
                worker_mutations((leaf / 'src' / directory / file).read_text(), file == 'worker.rs')
        count = 0
        for target, directory in ((d.TARGETS[0], 'strict_execution'), (d.TARGETS[2], 'macos_resident')):
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True,
                              fixture / 'Cargo.toml', leaf / 'Cargo.toml')
            h.validate(emit(), target, 'unwind')
            for mutant in shared_variants:
                try:
                    common.write_text(mutant)
                    artifacts = emit()
                    with self.subTest(target=target, file='common.rs', mutation=count), self.assertRaises(ValueError):
                        h.validate(artifacts, target, 'unwind')
                finally:
                    common.write_text(common_source)
                count += 1
            h.validate(emit(), target, 'unwind')
            for file in ('worker.rs', 'sha1_compiled/worker.rs'):
                path = leaf / 'src' / directory / file
                original = path.read_text()
                variants = worker_mutations(original, file == 'worker.rs')
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
        # Two shared defects per target, twelve scalar and five accelerated
        # defects per platform: no duplicate shared-macro compilations.
        self.assertEqual(count, 38)
        print('Legacy streaming workers: 38 compiled shared-tail/input/output/checkpoint defects rejected; restored baselines pass', flush=True)
