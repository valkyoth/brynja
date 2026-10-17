"""No-compiler regressions for hardened SHA-3 consumer orchestration."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import facade_hardened_sha3 as acceptance
import facade_hardened_sha3_regressions as probes
from test_facade_keccak import rejected


def check():
    original = (acceptance.ROOT / 'crates/brynja-hash-sha3/tests/hardened_execution.rs').read_text()
    adapted = acceptance.sources.owned(original)
    assert adapted.count('#[test]') == 5
    assert 'Ok(None)' not in adapted and 'let compiled =' not in adapted
    assert 'FACADE_SHA3_MODE' in adapted and 'Mode::Require' in adapted
    for bad in ('', original + original, original.replace('fn authority()', 'fn other()'),
                original.replace('#[test]', '', 1)):
        try:
            acceptance.sources.owned(bad)
        except ValueError:
            pass
        else:
            raise AssertionError('changed integration inventory accepted')
    for name, count in acceptance.TESTS.items():
        for ready in (False, True):
            marker = acceptance.MARKERS.get(name, '') if ready else ''
            stdout = f'test result: ok. {count if ready else 1} passed; 0 failed; 0 ignored;\n' + marker + '\n'
            good = SimpleNamespace(returncode=0, stdout=stdout, stderr='')
            acceptance.check_result(good, name, ready)
            for change in ({'returncode': 101}, {'returncode': -9}, {'stdout': ''},
                           {'stdout': stdout + stdout}, {'stdout': stdout.replace('0 failed', '1 failed')},
                           {'stdout': stdout.replace('0 ignored', '1 ignored')}):
                rejected(lambda: acceptance.check_result(SimpleNamespace(**(vars(good) | change)), name, ready))
            if name in acceptance.MARKERS:
                changed = stdout.replace(marker, '') if ready else stdout + acceptance.MARKERS[name] + '\n'
                rejected(lambda: acceptance.check_result(SimpleNamespace(returncode=0, stdout=changed), name, ready))
    orchestration()
    restoration()
    print('Hardened SHA-3 facade rejects skip-as-pass, source/route/population drift and surviving mutants; mutation/probe sources restore')


def orchestration():
    for static, hosted in (('MissingTargetFeatures', 'MissingMigrationGuarantee'), ('ready', 'ready')):
        seen = []

        def run(command, consumer, env):
            name = command[command.index('--test')+1]
            seen.append((command, env))
            ready = env['FACADE_SHA3_EXPECT'] == 'ready'
            if '--no-run' in command:
                return None
            assert ('required_admission' in command) != ready
            assert ('--exact' in command) != ready
            count = acceptance.TESTS[name] if ready else 1
            marker = acceptance.MARKERS.get(name, '') if ready else ''
            return SimpleNamespace(returncode=0, stdout=f'test result: ok. {count} passed; 0 failed; 0 ignored;\n{marker}\n')

        acceptance.campaign(SimpleNamespace(run=run), Path('/consumer'), ['cargo'], {},
                            ('avx2', 'X86Keccak', static, hosted))
        assert len(seen) == 24
        assert {env['FACADE_SHA3_MODE'] for _, env in seen} == {'static', 'hosted'}
        assert {env['FACADE_SHA3_EXPECT'] for _, env in seen} == ({'ready'} if static == 'ready'
            else {'MissingTargetFeatures', 'Unavailable(MissingMigrationGuarantee)'})


def restoration():
    with TemporaryDirectory(prefix='facade-hardened-sha3-') as directory:
        root = Path(directory)
        roots = {'brynja-hash-sha3': root}
        for mutant in probes.MUTANTS:
            filename, before, _, count, _, _ = mutant
            path = root / 'src/hardened/accelerated' / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            original = ('\n' + before) * count
            for failure in ('compiler', 'runtime', 'survived'):
                path.write_text(original)

                def run(command, *args, **kwargs):
                    assert path.read_text() != original
                    if failure == 'compiler':
                        raise ValueError('synthetic compiler failure')
                    if '--no-run' in command:
                        return None
                    return SimpleNamespace(returncode=0 if failure == 'survived' else 101,
                                           stdout='unrelated runtime failure', stderr='')

                with patch.object(probes, 'MUTANTS', (mutant,)):
                    rejected(lambda: probes.mutants(SimpleNamespace(run=run), root, roots, [], {}))
                assert path.read_text() == original
        path = root / 'src/lib.rs'
        path.write_text('original')

        def source(*args):
            path.write_text('probe')

        def fail(*args):
            raise ValueError('synthetic compiler failure')

        rejected(lambda: probes.negatives(SimpleNamespace(source=source, run=fail), root, 'brynja', [], {}))
        assert path.read_text() == 'original'
