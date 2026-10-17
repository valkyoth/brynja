"""No-compiler regressions for Keccak hosted/static consumer orchestration."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import facade_keccak_acceptance as acceptance
import facade_keccak_routes as routes
from test_facade_keccak import rejected


def check():
    text = 'use brynja_hash_sha3::batch::*; use brynja_crypto_cpu_std::keccak_batch;'
    for package, namespace in (('brynja', 'facade::crypto::sha3'), ('brynja-crypto', 'facade::sha3')):
        assert acceptance.rewrite(text, package) == f'use {namespace}::batch::*; use host::keccak_batch;'
    rejected(lambda: acceptance.rewrite(text, 'unknown'))
    rejected(lambda: acceptance.rewrite(text + ' use brynja_core::*;', 'brynja'))
    lines = ['CPU:avx2', 'ROUTE:keccak-batch:true', 'ROUTE:hardened-keccak-batch:true']
    assert acceptance.probe_result('\n'.join(lines)) == ('avx2', dict.fromkeys(acceptance.FAMILIES, True))
    for invalid in (lines[:-1], lines * 2, ['CPU:other', *lines[1:]],
                    [lines[0], lines[1], lines[1]],
                    [*lines[:2], 'ROUTE:other:true'],
                    [*lines[:2], 'ROUTE:hardened-keccak-batch:maybe']):
        rejected(lambda: acceptance.probe_result('\n'.join(invalid)))
    assert acceptance.probe_source().count('    route!(') == 2
    generated = routes.source()
    assert generated.count('Authority::new(') == 3
    assert 'Executor::portable()' not in generated
    assert 'witness.completed_vector_calls(), report.vector_calls' in generated
    for before, after in (('batch::Executor::portable()', 'changed()'),
                          ('secret::Executor::portable()', 'changed()'),
                          ('assert_eq!(report.vector_calls, 0);', 'changed();')):
        with patch.object(routes.portable, 'RUST', routes.portable.RUST.replace(before, after)):
            rejected(routes.source)
    for name, (_, marker) in acceptance.FAMILIES.items():
        suffix = ('; profiles=secret,declassified,public; cleanup=drop,declassify,staging'
                  if name.startswith('hardened') else '')
        good = SimpleNamespace(returncode=0, stdout='00;11;22;33\n' * 256,
                               stderr=f'{marker}: batches=256; vector_calls=42{suffix}\n')
        expected = good.stdout.splitlines()
        acceptance.check_result(good, expected, marker, True)
        for change in ({'returncode': 1}, {'stdout': 'partial'}, {'stderr': ''},
                       {'stderr': good.stderr * 2},
                       {'stderr': good.stderr.replace('batches=256', 'batches=255')},
                       {'stderr': good.stderr.replace('vector_calls=42', 'vector_calls=0')},
                       {'stderr': good.stderr.replace(marker, 'OTHER')},
                       {'stderr': good.stderr.rstrip() + '; changed\n'}):
            invalid = SimpleNamespace(**(vars(good) | change))
            rejected(lambda: acceptance.check_result(invalid, expected, marker, True))
        rejected(lambda: acceptance.check_result(good, expected, marker, False))
        if suffix:
            invalid = SimpleNamespace(**(vars(good) | {'stderr': good.stderr.replace(',staging', '')}))
            rejected(lambda: acceptance.check_result(invalid, expected, marker, True))
    good = SimpleNamespace(returncode=1, stdout='', stderr='Error: "authority: Unavailable"\n')
    acceptance.check_unavailable(good)
    for change in ({'returncode': 0}, {'returncode': 101}, {'returncode': -9},
                   {'stdout': 'partial'}, {'stderr': 'error[E0308]'},
                   {'stderr': 'Error: "executor: Unavailable"'},
                   {'stderr': good.stderr + 'panicked at'}):
        invalid = SimpleNamespace(**(vars(good) | change))
        rejected(lambda: acceptance.check_unavailable(invalid))
    # Every compiled mutation restores the extracted source after build failure,
    # unrelated runtime rejection or survival. Never write production files.
    with TemporaryDirectory(prefix='facade-keccak-routes-') as directory:
        root = Path(directory)
        for mutation in acceptance.MUTANTS:
            relative, before, after, _ = mutation
            path = root / 'src' / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            for failure in ('build', 'runtime', 'survived'):
                path.write_text(before)

                def run(command, *args, **kwargs):
                    assert path.read_text() == after
                    if failure == 'build':
                        raise ValueError('synthetic compiler failure')
                    if '--no-run' in command:
                        return None
                    return SimpleNamespace(returncode=0 if failure == 'survived' else 101,
                                           stdout='', stderr='unrelated failure')

                with patch.object(acceptance, 'MUTANTS', (mutation,)):
                    rejected(lambda: acceptance.mutants(SimpleNamespace(run=run), root,
                                                        {'brynja-hash-sha3': root}, [], {}))
                assert path.read_text() == before
    print('Facade Keccak route harness rejects import/source/probe/output/counter/exit drift; '
          'all six mutants restore extracted sources across three failure paths')
