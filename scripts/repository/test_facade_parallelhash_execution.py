"""Non-compiling regressions for scheduled/streaming ParallelHash acceptance."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import facade_parallelhash_execution as acceptance
from test_facade_keccak import rejected


def check():
    for name in ('scheduled.rs', 'xof_lifecycle.rs'):
        source = (acceptance.ROOT / 'crates/brynja-hash-parallel/tests/scoped_accelerated' / name).read_text()
        rewritten = acceptance.references.adapt(name, source)
        assert 'hardened_in_place' not in rewritten and 'assert_eq!(output, expected)' in rewritten
        assert rewritten.count('#[test]') == source.count('#[test]')
        rejected(lambda: acceptance.references.adapt(name, source + source))
        rejected(lambda: acceptance.references.adapt(name, source.replace('hardened_in_place', 'missing')))
    rejected(lambda: acceptance.references.adapt('other.rs', 'hash::hardened_in_place::Example'))
    source = ('use brynja_hash_parallel::execution; use brynja_hash_parallel_std::execution; '
              'use brynja_crypto_cpu::static_execution; use brynja_crypto_cpu_std::execution; '
              'use brynja_hash_sha3::hardened_execution;')
    for package, namespace in (('brynja', 'facade::crypto'), ('brynja-crypto', 'facade')):
        text = acceptance.rewrite(source, package)
        for item in ('parallelhash::execution', 'cpu::static_execution', 'sha3::hardened_execution'):
            assert namespace + '::' + item in text
        assert 'threads::execution' in text and 'host::execution' in text
        test = '#![cfg(feature = "hardened-execution")]\n' + source + '\n#[cfg(feature = "runtime-execution")]\nfn x() {}'
        text = acceptance.test_source(test, package)
        assert text.startswith('#![forbid(unsafe_code)]') and '#[cfg' not in text
        assert 'fn x() {}' in text
    rejected(lambda: acceptance.rewrite(source, 'unknown'))
    rejected(lambda: acceptance.rewrite(source + ' use brynja_core::*;', 'brynja'))
    generic = ('avx2', 'X86Keccak', 'MissingTargetFeatures', 'MissingMigrationGuarantee')
    for mode in acceptance.MODES:
        required = mode in acceptance.SCOPED or mode in ('required', 'stream-required', 'threads-required')
        assert bool(acceptance.unavailable(mode, generic)) == required
        assert acceptance.unavailable(mode, ('arm-keccak', 'ArmKeccak', 'ready', 'ready')) is None
        if mode in acceptance.SCOPED:
            assert acceptance.unavailable(mode, ('avx2', 'X86Keccak', 'ready', 'MissingMigrationGuarantee')) is None
        answers = ['ab'] * 256
        good = SimpleNamespace(returncode=0, stdout='ab\n' * 256,
            stderr=f'PARALLELHASH_EXECUTION: cases=256; mode={mode}; scoped={256 if mode in acceptance.SCOPED else 0}\n')
        acceptance.check_result(good, answers, mode)
        rejected(lambda: acceptance.check_result(good, answers[:-1], mode))
        for changes in ({'returncode': 1}, {'stdout': 'partial'}, {'stderr': ''},
                        {'stderr': good.stderr * 2}, {'stderr': good.stderr.replace('cases=256', 'cases=0')},
                        {'stderr': good.stderr.replace(f'mode={mode}', 'mode=other')},
                        {'stderr': good.stderr.replace('scoped=', 'omitted=')}):
            bad = SimpleNamespace(**(vars(good) | changes))
            rejected(lambda: acceptance.check_result(bad, answers, mode))
    rejected(lambda: acceptance.unavailable('unknown', generic))
    for line in (1, 2):
        error = SimpleNamespace(returncode=1, stdout='', stderr='Error: Custom { kind: InvalidData, error: ' +
                                json.dumps(f'line {line}: execution route mismatch') + ' }\n')
        acceptance.check_execution_error(error, 'execution route mismatch', line)
        for changes in ({'returncode': 0}, {'returncode': 101}, {'returncode': -9},
                        {'stdout': 'partial'}, {'stderr': 'error[E0308]'},
                        {'stderr': error.stderr.replace('InvalidData', 'Other')},
                        {'stderr': error.stderr.replace(f'line {line}', 'line 3')}):
            bad = SimpleNamespace(**(vars(error) | changes))
            rejected(lambda: acceptance.check_execution_error(bad, 'execution route mismatch', line))
    restoration()
    print('Facade ParallelHash execution rejects import/guard/route/population/error drift and restores every mutant')


def restoration():
    with TemporaryDirectory(prefix='facade-parallel-execution-harness-') as directory:
        root = Path(directory)
        base = root / 'src/execution'
        base.mkdir(parents=True)
        for attribute in ('ALGORITHM_MUTANTS', 'CLEANUP_MUTANTS'):
            for mutant in getattr(acceptance, attribute):
                filename, before, *_ = mutant
                path = base / filename
                for failure in ('build', 'runtime', 'survived'):
                    path.write_text(before)

                    def run(command, *args, **kwargs):
                        assert path.read_text() != before
                        if failure == 'build':
                            raise ValueError('synthetic build failure')
                        if 'build' in command or '--no-run' in command:
                            return None
                        if failure == 'runtime':
                            raise ValueError('synthetic runtime failure')
                        return SimpleNamespace(returncode=0, stdout='answer\n', stderr='')

                    patches = {'ALGORITHM_MUTANTS': (), 'CLEANUP_MUTANTS': (), attribute: (mutant,)}
                    with patch.multiple(acceptance, **patches):
                        rejected(lambda: acceptance.mutants(SimpleNamespace(run=run), root,
                            {'brynja-hash-parallel': root}, [], {'CARGO_TARGET_DIR': str(root)},
                            (['request'], ['answer'], [0])))
                    assert path.read_text() == before
        path = base / 'backend.rs'
        before = 'Mode::Prefer(Some(s)) | Mode::Require(Some(s)) => Some(s),'
        for failure in ('build', 'runtime', 'survived'):
            path.write_text(before)

            def run(command, *args, **kwargs):
                assert path.read_text() != before
                if failure == 'build':
                    raise ValueError('synthetic build failure')
                if 'build' in command:
                    return None
                return SimpleNamespace(returncode=0 if failure == 'survived' else 101,
                                       stdout='', stderr='unrelated failure')

            rejected(lambda: acceptance.fallback_mutant(SimpleNamespace(run=run), root,
                {'brynja-hash-parallel': root}, [], {'CARGO_TARGET_DIR': str(root)},
                (['request'], ['answer'], [0])))
            assert path.read_text() == before


def graph_checks(api, document):
    names = {'brynja-crypto-cpu': [], 'brynja-crypto-cpu-std': ['runtime-execution'],
             'brynja-hash-parallel': ['runtime-execution'],
             'brynja-hash-parallel-std': ['runtime-execution'],
             'brynja-hash-sha3': ['hardened-execution']}
    api.graph(document(names), acceptance.FEATURES, hosted=True, threaded=True)
    for flags in ({}, {'hosted': True}, {'threaded': True}):
        rejected(lambda: api.graph(document(names), acceptance.FEATURES, **flags))
    for key in ('brynja-hash-parallel', 'brynja-hash-parallel-std', 'brynja-hash-sha3'):
        changed = names | {key: []}
        rejected(lambda: api.graph(document(changed), acceptance.FEATURES, hosted=True, threaded=True))
    changed = names | {'brynja-hash-parallel-std': ['runtime-batch-execution']}
    rejected(lambda: api.graph(document(changed), acceptance.FEATURES, hosted=True, threaded=True))
    print('Facade runtime-threaded graph rejects seven missing opt-in/feature regressions')
