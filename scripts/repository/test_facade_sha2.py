"""Non-compiling regressions for facade SHA-2 oracle/route orchestration."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import facade_sha2_acceptance as batches


def rejects(action):
    try:
        action()
    except ValueError:
        return
    raise AssertionError('accepted SHA-2 facade harness regression')


def check():
    text = 'use brynja_hash_sha2::batch::*; use brynja_crypto_cpu_std::sha256_batch;'
    for facade, namespace in (('brynja', 'facade::crypto::sha2'), ('brynja-crypto', 'facade::sha2')):
        assert batches.fixture_source(text, facade) == (
            f'use {namespace}::batch::*; use host::sha256_batch;')
    rejects(lambda: batches.fixture_source(text, 'other'))
    rejects(lambda: batches.fixture_source(text + '\nuse brynja_core::Secret;', 'brynja'))
    lines = ['CPU:avx2'] + [f'ROUTE:{name}:false' for name in batches.FAMILIES]
    assert batches.probe_result('\n'.join(lines)) == ('avx2', dict.fromkeys(batches.FAMILIES, False))
    for changed in (lines[:-1], lines + [lines[-1]], ['CPU:arbitrary'] + lines[1:],
                    lines[:-1] + [lines[1]], [lines[0], lines[1].replace('false', 'maybe'), *lines[2:]],
                    [lines[0], 'ROUTE:wrong:true', *lines[2:]]):
        rejects(lambda: batches.probe_result('\n'.join(changed)))
    marker = 'SHA256_BATCH_ACCEPTANCE'
    good = SimpleNamespace(returncode=0, stdout='aa\nbb\n',
                           stderr=marker + ': batches=2; vector_calls=3\n')
    batches.check_result(good, ['aa', 'bb'], marker, True)
    variants = (
        {'returncode': 1}, {'stdout': 'aa\n'}, {'stdout': 'aa\ncc\n'},
        {'stderr': ''}, {'stderr': good.stderr * 2},
        {'stderr': good.stderr.replace('batches=2', 'batches=1')},
        {'stderr': good.stderr.replace('vector_calls=3', 'vector_calls=0')},
        {'stderr': good.stderr.replace(marker, 'HARDENED_SHA256_BATCH')},
        {'stderr': good.stderr.rstrip() + '; ignored\n'},
    )
    for change in variants:
        bad = SimpleNamespace(**(vars(good) | change))
        rejects(lambda: batches.check_result(bad, ['aa', 'bb'], marker, True))
    rejects(lambda: batches.check_result(good, ['aa', 'bb'], marker, False))
    suffix = '; profiles=secret,declassified,public; cleanup=drop,declassify'
    hard = SimpleNamespace(returncode=0, stdout=good.stdout,
                           stderr=good.stderr.replace(marker, 'HARDENED_SHA256_BATCH').rstrip() + suffix + '\n')
    batches.check_result(hard, ['aa', 'bb'], 'HARDENED_SHA256_BATCH', True)
    hard.stderr = hard.stderr.replace('; cleanup=drop,declassify', '')
    rejects(lambda: batches.check_result(hard, ['aa', 'bb'], 'HARDENED_SHA256_BATCH', True))
    for reason, validator in (('Unavailable', batches.check_unavailable), ('Invariant', batches.check_invariant)):
        valid = SimpleNamespace(returncode=1, stdout='', stderr=f'Error: "{reason}"\n')
        validator(valid)
        for change in ({'returncode': 0}, {'returncode': 101}, {'stdout': 'partial output'},
                       {'stderr': 'error[E0432]: compilation failed'},
                       {'stderr': 'thread panicked at'}, {'returncode': -9}):
            invalid = SimpleNamespace(**(vars(valid) | change))
            rejects(lambda: validator(invalid))
    # Both ordinary and accelerated mutation helpers restore extracted sources
    # even if compilation fails. The real repository is never modified here.
    with TemporaryDirectory(prefix='facade-sha2-harness-') as directory:
        root = Path(directory)
        (root / 'src/batch').mkdir(parents=True)
        originals = {
            'mod.rs': '*output = staged;',
            'engine.rs': 'session\n                    .compress(PublicData::new(&mut packed), PublicData::new(&blocks))'
                         '\n                    .map_err(Error::Backend)?;',
        }
        for filename, original in originals.items():
            (root / 'src/batch' / filename).write_text(original)

        def fail(*args, **kwargs):
            raise ValueError('synthetic compilation failure')

        api = SimpleNamespace(run=fail)
        data = {'sha256_batch_acceptance.py': ('request\n' * 384, ['expected'] * 384)}
        for helper in (batches.mutations, batches.native_mutations):
            rejects(lambda: helper(api, root, {'brynja-hash-sha2': root}, [], {}, data))
            for filename, original in originals.items():
                assert (root / 'src/batch' / filename).read_text() == original
    print('Facade SHA-2 harness rejects import/route/oracle/counter/cleanup/exit regressions '
          'and restores extracted sources after compiler failure')
