"""Execute compiled acceptance mutations in a disposable downstream fixture."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

import legacy_final_acceptance as policy


def run_tests():
    source = policy.ROOT / policy.FIXTURE
    batch = policy.read(policy.ROOT, policy.FIXTURE + '/src/batch.rs')
    poison = 'output = wanted.map(|lane| lane.map(|byte| !byte));'
    start = batch.index('        let report = HardenedMd5Batch::new()')
    end = batch.index('.map_err(|_| "hardened public batch failed")?;', start)
    end += len('.map_err(|_| "hardened public batch failed")?;')
    call = batch[start:end]
    if batch.count(call) != 1 or batch.count(poison) != 3:
        raise AssertionError('public-output mutation anchors changed')
    noop = batch.replace(call, '        let report = brynja_legacy_md5::Md5BatchReport::default();')
    partial = batch.replace(call, '        output[0] = wanted[0];\n'
        '        let report = brynja_legacy_md5::Md5BatchReport::default();')
    noop = noop.replace('Md5BatchError, PublicDeclassification,', 'Md5BatchError,')
    partial = partial.replace('Md5BatchError, PublicDeclassification,', 'Md5BatchError,')
    wrong_report = batch.replace(call, call.replace('let report =', 'let mut report =')
        + '\n        report.vector_blocks = 1;')
    # Reproduce the original weakness as a positive counter-control: a no-op
    # passes if only the hardened-public reset is removed. Production is never
    # edited, and these deliberately broken fixtures are not deployed.
    reused = noop.replace('        ' + poison + '\n', '', 1)
    variants = ((batch, True), (noop, False), (partial, False),
                (wrong_report, False), (reused, True))
    with tempfile.TemporaryDirectory(prefix='brynja-final-batch-') as directory:
        root = Path(directory)
        (root / 'src').mkdir()
        manifest = (source / 'Cargo.toml').read_text(encoding='utf-8')
        def absolute_dependency(match):
            return 'path = ' + json.dumps((source / match[1]).resolve().as_posix(), ensure_ascii=False)
        # Rebind dependency paths, but leave the binary's relative source path.
        manifest = re.sub(r'path = "(\.\./[^"]+)"', absolute_dependency, manifest)
        (root / 'Cargo.toml').write_text(manifest, encoding='utf-8')
        (root / 'Cargo.lock').write_bytes((source / 'Cargo.lock').read_bytes())
        # The #[path] attribute is relative to src/, unlike Cargo dependency paths.
        vectors = (source / 'src/../../legacy-hash-public-api/src/vectors.rs').resolve()
        for name in ('lib.rs', 'main.rs'):
            text = (source / 'src' / name).read_text(encoding='utf-8')
            text = text.replace('"../../legacy-hash-public-api/src/vectors.rs"',
                                json.dumps(vectors.as_posix(), ensure_ascii=False))
            (root / 'src' / name).write_text(text, encoding='utf-8')
        env = dict(os.environ, CARGO_TERM_COLOR='never', CARGO_INCREMENTAL='0')
        for profile in ([], ['--release']):
            for content, should_pass in variants:
                (root / 'src/batch.rs').write_text(content, encoding='utf-8')
                result = subprocess.run(['cargo', 'test', '--locked', '--offline',
                    '--manifest-path', str(root / 'Cargo.toml'), '--target-dir', str(root / 'target'),
                    '--no-default-features', '--lib', *profile,
                    'tests::frozen_portable_and_bounded_batch_profiles', '--', '--exact'],
                    cwd=policy.ROOT, env=env, capture_output=True, text=True, timeout=180)
                output = result.stdout + result.stderr
                if should_pass:
                    valid = result.returncode == 0 and '1 passed; 0 failed' in output
                else:
                    valid = (result.returncode != 0 and '1 failed' in output
                             and 'hardened batch differs' in output)
                if not valid:
                    raise AssertionError('compiled batch mutation or positive control failed:\n' + output[-6000:])
    print('Final batch acceptance rejects no-op, partial writes and false route reports in debug/release; positive and stale-output controls pass')
