"""No-compiler regressions for production KMAC packaged acceptance."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import facade_kmac_acceptance as acceptance
from test_facade_keccak import rejected


def check():
    sources = acceptance.sources
    fixture = acceptance.ROOT / 'assurance/kmac-execution'
    for name, replacements in sources.COUNTS.items():
        original = (fixture / 'src' / name).read_text()
        adapted = sources.production(name, original)
        assert 'conformance' not in adapted
        for before in replacements:
            rejected(lambda: sources.production(name, original.replace(before, 'missing')))
            rejected(lambda: sources.production(name, original + before))
        rejected(lambda: sources.production(name, original + '\nconformance::execution'))
    rejected(lambda: sources.production('other.rs', ''))
    original = (acceptance.ROOT / 'crates/brynja-mac-kmac/tests/execution.rs').read_text()
    adapted = sources.execution_tests(original)
    assert adapted.count('#[test]') == 7 and 'conformance' not in adapted
    for bad in ('', original + original, original.replace('fn separate_test_owners', 'fn renamed_test_owners')):
        rejected(lambda: sources.execution_tests(bad))
    original = (fixture / 'tests/scoped/xof.rs').read_text()
    adapted = sources.scoped_tests('scoped/xof.rs', original)
    assert '.with(&[1]' in adapted and 'conformance' not in adapted
    for bad in ('', original + original, original.replace('Ok(Err(KmacError::KeyTooShort))', 'Ok(Ok(()))')):
        rejected(lambda: sources.scoped_tests('scoped/xof.rs', bad))
    for package, namespace in (('brynja', 'facade::crypto'), ('brynja-crypto', 'facade')):
        text = sources.rewrite('use brynja_mac_kmac::execution; use brynja_crypto_cpu::static_execution; use brynja_crypto_cpu_std::execution;', package)
        assert namespace + '::kmac::execution' in text and namespace + '::cpu::static_execution' in text and 'host::execution' in text
    rejected(lambda: sources.rewrite('use brynja_core::*;', 'brynja'))
    rejected(lambda: sources.rewrite('', 'unknown'))
    rows = [(name, bytes(32), 256, b'', 0, b'', 0, 256, bytes(32))
            for name in acceptance.oracle.NAMES for _ in range(67)]
    request, answers = acceptance.oracle.render(rows)
    assert len(request.splitlines()) == len(answers) == 268
    for bad in (rows[:-1], rows + [rows[0]], [('unknown', *rows[0][1:])] + rows[1:],
                [('kmac256', *rows[0][1:])] + rows[1:],
                [('kmac128', b'', 0, b'', 0, b'', 0, 256, bytes(32))] + rows[1:],
                [(*rows[0][:-2], 1, b'\x01')] + rows[1:],
                [(*rows[0][:-1], b'')] + rows[1:]):
        rejected(lambda: acceptance.oracle.render(bad))
    assert len(acceptance.oracle.invalid()) == 17
    for mode in ('portable', 'prefer-portable', 'static', 'prefer', 'hosted'):
        route = 'KMAC_EXECUTION_ROUTE: ' + acceptance.shared.route(mode, 'X86Keccak') + '\n'
        good = SimpleNamespace(returncode=0, stdout='\n'.join(answers) + '\n', stderr=route)
        acceptance.check_result(good, answers, mode, 'X86Keccak')
        for changed in ({'returncode': 1}, {'stdout': ''}, {'stdout': good.stdout + good.stdout},
                        {'stderr': ''}, {'stderr': route + route}, {'stderr': route.replace('Healthy', 'Quarantined') if 'Healthy' in route else 'KMAC_EXECUTION_ROUTE: static'}):
            rejected(lambda: acceptance.check_result(SimpleNamespace(**(vars(good) | changed)), answers, mode, 'X86Keccak'))
        rejected(lambda: acceptance.check_result(good, answers[:-1], mode, 'X86Keccak'))
        error = 'line 2: noncanonical bit string'
        bad = SimpleNamespace(returncode=1, stdout='', stderr=route +
            'Error: Custom { kind: InvalidData, error: ' + json.dumps(error) + ' }\n')
        acceptance.check_failure(bad, mode, 'X86Keccak', 'InvalidData', error)
        for changed in ({'returncode': 0}, {'returncode': 101}, {'returncode': -9},
                        {'stdout': 'partial'}, {'stderr': 'compiler error'},
                        {'stderr': bad.stderr.replace('line 2', 'line 1')}):
            rejected(lambda: acceptance.check_failure(SimpleNamespace(**(vars(bad) | changed)), mode, 'X86Keccak', 'InvalidData', error))
    restoration()
    print('KMAC facade rejects source/conformance/corpus/route/population/error drift; compiled mutation and ownership sources restore on failures')


def restoration():
    probes = acceptance.probes
    with TemporaryDirectory(prefix='facade-kmac-harness-') as directory:
        root = Path(directory)
        base = root / 'src/execution'
        base.mkdir(parents=True)
        roots = {'brynja-mac-kmac': root}
        for mutant in probes.ALGORITHM:
            filename, before, _ = mutant
            path = base / filename
            for failure in ('build', 'runtime', 'survived'):
                path.write_text(before)

                def run(command, *args, **kwargs):
                    assert path.read_text() != before
                    if failure == 'build' or (failure == 'runtime' and 'build' not in command):
                        raise ValueError('synthetic compiler/runtime failure')
                    if 'build' in command:
                        return None
                    return SimpleNamespace(returncode=0, stdout='\n'.join(['expected'] * 268) + '\n', stderr='KMAC_EXECUTION_ROUTE: Portable\n')

                with patch.object(probes, 'ALGORITHM', (mutant,)):
                    rejected(lambda: probes.algorithm_mutants(SimpleNamespace(run=run, require=acceptance.require), root, roots,
                        [], {'CARGO_TARGET_DIR': str(root)}, ('request', ['expected'] * 268), 'X86Keccak',
                        acceptance.check_result, acceptance.check_failure))
                assert path.read_text() == before
        for helper, filename, before, extra in (
            (probes.cleanup_mutant, 'output.rs', 'let _ = clear_owned_region(self.0);', ()),
            (probes.cleanup_mutant, '../hardened_in_place/accelerated.rs', 'let _ = brynja_core::clear_owned_region(self.0);', (True,)),
            (probes.fallback_mutant, 'backend.rs',
             'Mode::Prefer(Some(session)) | Mode::Require(Some(session)) => Some(session),',
             (('', []), 'X86Keccak', acceptance.check_result, acceptance.check_failure)),
        ):
            path = base / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            for failure in ('build', 'runtime', 'survived'):
                path.write_text(before)

                def run(command, *args, **kwargs):
                    assert path.read_text() != before
                    if failure == 'build':
                        raise ValueError('synthetic compiler failure')
                    if 'build' in command or '--no-run' in command:
                        return None
                    return SimpleNamespace(returncode=0 if failure == 'survived' else 101,
                                           stdout='', stderr='unrelated error')

                rejected(lambda: helper(SimpleNamespace(run=run, require=acceptance.require), root, roots, [],
                    {'CARGO_TARGET_DIR': str(root)}, *extra))
                assert path.read_text() == before
        path = root / 'src/lib.rs'
        path.write_text('original')

        def source(*args):
            path.write_text('probe')

        def fail(*args, **kwargs):
            raise ValueError('synthetic check failure')

        rejected(lambda: probes.negatives(SimpleNamespace(source=source, run=fail), root, 'brynja', [], {}))
        assert path.read_text() == 'original'
