"""No-compiler regressions for ordinary facade sponge acceptance."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import facade_sha3_execution as acceptance
from test_facade_keccak import rejected


def check():
    for package, prefix in (('brynja', 'facade::crypto'), ('brynja-crypto', 'facade')):
        text = acceptance.rewrite('use brynja_hash_sha3::execution; use brynja_crypto_cpu::static_execution; use brynja_crypto_cpu_std::sponge;', package)
        assert prefix + '::sha3::execution' in text and prefix + '::cpu::static_execution' in text
        assert 'host::sponge' in text
    rejected(lambda: acceptance.rewrite('', 'unknown'))
    rejected(lambda: acceptance.rewrite('use brynja_core::*;', 'brynja'))
    main = (acceptance.ROOT / 'assurance/sha3-execution/src/main.rs').read_text()
    relocated = acceptance.fixture_main(main)
    assert '../../../crates/' not in relocated and relocated.startswith('#![forbid(unsafe_code)]')
    for changed in ('', main + main, main.replace('execution_cases/mod.rs', 'renamed.rs')):
        rejected(lambda: acceptance.fixture_main(changed))
    scenarios = (
        ('avx2', 'X86Keccak', 'MissingTargetFeatures', 'MissingMigrationGuarantee'),
        ('avx2', 'X86Keccak', 'ready', 'MissingMigrationGuarantee'),
        ('arm-keccak', 'ArmKeccak', 'ready', 'ready'),
        ('none', 'ArmKeccak', 'MissingTargetFeatures', 'MissingFeaturesOrOsState'),
    )
    for selected in scenarios:
        for mode in acceptance.MODES:
            route, error = acceptance.expected(mode, selected)
            unavailable = (mode == 'static' and selected[2] != 'ready') or (mode == 'hosted' and selected[3] != 'ready')
            assert bool(error) == unavailable and bool(route) != unavailable
    assert acceptance.expected('static', scenarios[0])[1] == 'acceptance failed: SHA-3 execution failure: Backend(MissingTargetFeatures)'
    assert acceptance.expected('hosted', scenarios[0])[1] == 'acceptance failed: hosted selection: Hosted(Unavailable(MissingMigrationGuarantee))'
    assert acceptance.expected('prefer', scenarios[0])[0] == ('Portable', 'PortableFallback(MissingMigrationGuarantee)')
    assert acceptance.expected('hosted', scenarios[2])[0] == ('Runtime(ArmKeccak)', 'Accelerated')
    rejected(lambda: acceptance.expected('unknown', scenarios[0]))
    for selected, host in (('Portable', 'PortableRequested'), ('Static(X86Keccak)', 'PortableRequested'),
                           ('Runtime(ArmKeccak)', 'Accelerated')):
        output = (f'SHA-3/SHAKE ordinary execution: PASS; cases=1084; route={selected}\n'
                  f'cSHAKE ordinary execution: PASS; cases=628; route={selected}\n'
                  f'hosted selection: {host}\npublic-only; independently verified: NO; FIPS validated: NO\n')
        good = SimpleNamespace(returncode=0, stdout=output, stderr='')
        acceptance.check_result(good, (selected, host))
        for changes in ({'returncode': 1}, {'stderr': 'unexpected'}, {'stdout': ''},
                        {'stdout': output + output}, {'stdout': output.replace('1084', '1083')},
                        {'stdout': output.replace('628', '0')}, {'stdout': output.replace('route=', 'omitted=')},
                        {'stdout': output.replace('NO', 'YES')}, {'stdout': output.replace('hosted selection:', 'missing:')}):
            bad = SimpleNamespace(**(vars(good) | changes))
            rejected(lambda: acceptance.check_result(bad, (selected, host)))
    error = 'acceptance failed: cSHAKE execution mismatch'
    good = SimpleNamespace(returncode=1, stdout='', stderr=error + '\n')
    acceptance.check_error(good, error)
    for changes in ({'returncode': 0}, {'returncode': 101}, {'returncode': -9},
                    {'stdout': 'partial'}, {'stderr': 'error[E0308]'}, {'stderr': 'panicked at something'}):
        rejected(lambda: acceptance.check_error(SimpleNamespace(**(vars(good) | changes)), error))
    cases = acceptance.negatives.classification()
    assert len(cases) == 48 and len(set(cases)) == 48
    assert len(acceptance.negatives.OWNERS) == len(set(acceptance.negatives.OWNERS)) == 14
    for setup, call, raw, wrapped in cases:
        assert 'INPUT' in call and raw != wrapped and 'Public' in wrapped
    restoration()
    print('Ordinary facade SHA-3 rejects import/path/population/route/error drift and restores eleven compiled mutants')


def restoration():
    with TemporaryDirectory(prefix='facade-sha3-harness-') as directory:
        root = Path(directory)
        base = root / 'src/execution'
        base.mkdir(parents=True)
        for mutant in acceptance.MUTANTS:
            name, before, _, count, _ = mutant
            path = base / name
            original = (before + '\n') * count
            for failure in ('build', 'runtime', 'survived'):
                path.write_text(original)

                def run(command, *args, **kwargs):
                    assert path.read_text() != original
                    if failure == 'build':
                        raise ValueError('synthetic compiler failure')
                    if 'build' in command:
                        return None
                    return SimpleNamespace(returncode=0 if failure == 'survived' else 101,
                                           stdout='', stderr='unrelated runtime failure')

                with patch.object(acceptance, 'MUTANTS', (mutant,)):
                    rejected(lambda: acceptance.mutants(SimpleNamespace(run=run), root,
                        {'brynja-hash-sha3': root}, [], {'CARGO_TARGET_DIR': str(root)}))
                assert path.read_text() == original
        path = base / 'route.rs'
        for replacements in acceptance.NATIVE_MUTANTS:
            original = '\n'.join(before for before, _ in replacements)
            for failure in ('build', 'runtime', 'survived'):
                path.write_text(original)

                def run(command, *args, **kwargs):
                    assert path.read_text() != original
                    if failure == 'build':
                        raise ValueError('synthetic native build failure')
                    if 'build' in command:
                        return None
                    return SimpleNamespace(returncode=0 if failure == 'survived' else 101,
                                           stdout='', stderr='unrelated native failure')

                with patch.object(acceptance, 'NATIVE_MUTANTS', (replacements,)):
                    rejected(lambda: acceptance.native_mutants(SimpleNamespace(run=run), root,
                        {'brynja-hash-sha3': root}, [], {'CARGO_TARGET_DIR': str(root)},
                        ('avx2', 'X86Keccak', 'ready', 'MissingMigrationGuarantee')))
                assert path.read_text() == original
        lib = root / 'src/lib.rs'
        lib.write_text('original consumer')

        def source(*args):
            lib.write_text('temporary probe')

        def fail(*args, **kwargs):
            raise ValueError('synthetic failed compilation')

        rejected(lambda: acceptance.negatives.execute(SimpleNamespace(source=source, run=fail,
            require=acceptance.require), root, 'brynja', [], {}))
        assert lib.read_text() == 'original consumer'
