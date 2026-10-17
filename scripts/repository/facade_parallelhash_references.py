"""Adapt two synthetic portable references without exporting leaf-only owners.

All accelerated tests/assertions remain. Only the public reference computation
uses curated ordinary APIs instead of hidden portable in-place helpers. These
are test bytes, not confidential material or a hardened-reference claim.
"""


def once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('facade ParallelHash reference anchor changed')
    return text.replace(before, after)


def adapt(name, text):
    if name == 'scheduled.rs':
        text = once(text, '$plan:ident, $fixed:ident', '$plan:ident, $collector:ident, $fixed:ident')
        for width in (128, 256):
            text = once(text, f'ParallelHash{width}Plan,\n    ParallelHash{width},',
                        f'ParallelHash{width}Plan,\n    ParallelHash{width}Collector,\n    ParallelHash{width},')
        text = once(text, '''                let mut portable = hash::hardened_in_place::$workspace::new();
                portable.with(&plan, b"", |mut root| {
                    for index in 0..plan.leaf_count() {
                        root.merge(leaf_worker.execute(plan.job(index)?, &mut first)?)?;
                    }
                    root.finalize_public(&mut output, Public::acknowledge())
                })??;''', '''                let mut portable = hash::$collector::new(&plan, b"")?;
                for index in 0..plan.leaf_count() {
                    let leaf = leaf_worker.execute(plan.job(index)?, &mut first)?;
                    portable.merge(&leaf)?;
                }
                portable.finalize(&mut output)?;''')
    elif name == 'xof_lifecycle.rs':
        text = once(text, '($test:ident, $workspace:ident)', '($test:ident, $workspace:ident, $reference:ident)')
        for width in (128, 256):
            text = once(text, f'    ParallelHashXof{width}Workspace\n);',
                        f'    ParallelHashXof{width}Workspace, ParallelHashXof{width}\n);')
        text = once(text, '''                                    let mut reference = hash::hardened_in_place::$workspace::new();
                                    let mut expected = [0; 32];
                                    reference.with(&mut [0; 8], b"", |mut state| {
                                        state.update(b"pending")?;
                                        state
                                            .finalize_xof()?
                                            .squeeze_public(&mut expected, Public::acknowledge())
                                    })??;''', '''                                    let mut block = [0; 8];
                                    let mut reference = hash::$reference::new(&mut block, b"")?;
                                    let mut expected = [0; 32];
                                    reference.update(b"pending")?;
                                    reference.finalize_xof()?.squeeze(&mut expected)?;''')
    if 'hardened_in_place' in text:
        raise ValueError('hidden portable reference still present')
    return text
