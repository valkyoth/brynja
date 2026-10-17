"""No-compiler fail-closed regressions for TupleHash facade acceptance."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import facade_tuplehash_acceptance as acceptance
import facade_tuplehash_probes as probes
from test_facade_keccak import rejected


def check():
    names = ('tuple128', 'tuple256', 'tuplexof128', 'tuplexof256')
    cases = [(name, b'', 0, [], 1, b'\x01') for name in names for _ in range(67)]
    requests, expected = acceptance.render(cases)
    assert len(requests.splitlines()) == len(expected) == 268
    for changed in (cases[:-1], cases + [cases[0]],
                    [('unknown', *cases[0][1:])] + cases[1:],
                    [('tuple256', *cases[0][1:])] + cases[1:],
                    [(*cases[0][:-1], b'')] + cases[1:],
                    [(*cases[0][:-1], b'\x81')] + cases[1:]):
        rejected(lambda: acceptance.render(changed))
    text = 'use brynja_hash_tuple::execution; use brynja_crypto_cpu::static_execution; use brynja_crypto_cpu_std::execution as host;'
    for package, namespace in (('brynja', 'facade::crypto'), ('brynja-crypto', 'facade')):
        rewritten = acceptance.rewrite(text, package)
        assert f'{namespace}::tuplehash::execution' in rewritten
        assert f'{namespace}::cpu::static_execution' in rewritten
        assert 'use host::execution as host;' in rewritten
    rejected(lambda: acceptance.rewrite(text, 'other'))
    rejected(lambda: acceptance.rewrite(text + ' use brynja_core::*;', 'brynja'))
    lines = ['CPU:avx2', 'KERNEL:X86Keccak', 'STATIC:ready', 'HOSTED:MissingMigrationGuarantee']
    assert acceptance.probe_result('\n'.join(lines)) == ('avx2', 'X86Keccak', 'ready', 'MissingMigrationGuarantee')
    for index, replacements in enumerate((('CPU:other', 'CPU:arm-keccak'),
                                          ('KERNEL:Other', 'KERNEL:ArmKeccak'),
                                          ('STATIC:Quarantined', 'STATIC:missing'),
                                          ('HOSTED:Kernel(Quarantined)', 'HOSTED:missing'))):
        for replacement in replacements:
            invalid = list(lines)
            invalid[index] = replacement
            rejected(lambda: acceptance.probe_result('\n'.join(invalid)))
    for invalid in (lines[:-1], lines + [lines[-1]], list(reversed(lines))):
        rejected(lambda: acceptance.probe_result('\n'.join(invalid)))
    for mode in ('portable', 'prefer-portable', 'static', 'prefer', 'hosted'):
        route = acceptance.route(mode, 'X86Keccak')
        good = SimpleNamespace(returncode=0, stdout='\n'.join(expected) + '\n',
                               stderr='TUPLEHASH_EXECUTION_ROUTE: ' + route + '\n')
        acceptance.check_result(good, expected, mode, 'X86Keccak')
        if mode in ('static', 'prefer'):
            invalid = SimpleNamespace(**(vars(good) | {'stderr': good.stderr.replace('generation: 2', 'generation: 1')}))
            rejected(lambda: acceptance.check_result(invalid, expected, mode, 'X86Keccak'))
        rejected(lambda: acceptance.check_result(good, expected[:-1], mode, 'X86Keccak'))
        for change in ({'returncode': 1}, {'stdout': 'partial'}, {'stderr': ''},
                       {'stderr': good.stderr * 2}, {'stderr': good.stderr + 'ignored\n'},
                       {'stderr': good.stderr.replace(route, 'Quarantined')}):
            bad = SimpleNamespace(**(vars(good) | change))
            rejected(lambda: acceptance.check_result(bad, expected, mode, 'X86Keccak'))
        error = 'line 2: noncanonical bit string'
        bad_input = SimpleNamespace(returncode=1, stdout='', stderr=good.stderr +
            'Error: Custom { kind: InvalidData, error: ' + json.dumps(error) + ' }\n')
        acceptance.check_failure(bad_input, mode, 'X86Keccak', 'InvalidData', error)
        for change in ({'returncode': 0}, {'returncode': 101}, {'returncode': -9},
                       {'stdout': 'partial'}, {'stderr': 'error[E0432]'},
                       {'stderr': bad_input.stderr.replace('line 2', 'line 1')}):
            invalid = SimpleNamespace(**(vars(bad_input) | change))
            rejected(lambda: acceptance.check_failure(invalid, mode, 'X86Keccak', 'InvalidData', error))
    for hosted, reason in ((False, 'MissingTargetFeatures'), (True, 'MissingMigrationGuarantee')):
        error = f'Unavailable({reason})' if hosted else reason
        valid = SimpleNamespace(returncode=1, stdout='', stderr=
            'Error: Custom { kind: Other, error: "execution selection: ' + error + '" }\n')
        acceptance.check_unavailable(valid, reason, hosted)
        for change in ({'returncode': 0}, {'returncode': 101}, {'stdout': 'partial'},
                       {'stderr': 'panicked at'}, {'stderr': valid.stderr.replace(reason, 'Quarantined')}):
            invalid = SimpleNamespace(**(vars(valid) | change))
            rejected(lambda: acceptance.check_unavailable(invalid, reason, hosted))
    message = {'reason': 'compiler-message', 'message': {'level': 'error', 'code': {'code': 'E0277'}}}
    valid = SimpleNamespace(returncode=101, stdout=json.dumps(message))
    assert probes.diagnostic(valid, 'E0277')
    assert not probes.diagnostic(valid, 'E0499')
    for change in ({'returncode': 0}, {'returncode': -9}, {'stdout': ''},
                   {'stdout': json.dumps(message).replace('error', 'warning')}):
        assert not probes.diagnostic(SimpleNamespace(**(vars(valid) | change)), 'E0277')
    restoration()
    print('Facade TupleHash harness rejects corpus/import/admission/route/output/error/diagnostic drift; '
          'mutation and negative-probe sources restore after failures')


def restoration():
    with TemporaryDirectory(prefix='facade-tuplehash-harness-') as directory:
        root = Path(directory)
        leaf = root / 'src/execution'
        leaf.mkdir(parents=True)

        def fail(*args, **kwargs):
            raise ValueError('synthetic compilation failure')

        roots = {'brynja-hash-tuple': root}
        for mutant in acceptance.ALGORITHM_MUTANTS:
            relative, before, _ = mutant
            path = leaf / relative
            for failure in ('build', 'runtime', 'survived'):
                path.write_text(before)

                def run(command, *args, **kwargs):
                    assert path.read_text() != before
                    if failure == 'build' or (failure == 'runtime' and 'build' not in command):
                        raise ValueError('synthetic compilation/runtime failure')
                    if 'build' in command:
                        return None
                    return SimpleNamespace(returncode=0, stdout='expected\n', stderr='')

                with patch.object(acceptance, 'ALGORITHM_MUTANTS', (mutant,)):
                    rejected(lambda: acceptance.algorithm_mutants(SimpleNamespace(run=run), root, roots,
                        [], {'CARGO_TARGET_DIR': str(root)}, ('request', ['expected']), 'X86Keccak'))
                assert path.read_text() == before
        for helper, filename, before, extra in (
            (acceptance.cleanup_mutant, 'output.rs', 'let _ = clear_owned_region(self.0);', ()),
            (acceptance.fallback_mutant, 'backend.rs',
             'Mode::Prefer(Some(session)) | Mode::Require(Some(session)) => Some(session),', (('', []), 'X86Keccak')),
        ):
            path = leaf / filename
            for failure in ('build', 'runtime', 'survived'):
                path.write_text(before)

                def run(command, *args, **kwargs):
                    assert path.read_text() != before
                    if failure == 'build':
                        raise ValueError('synthetic compiler failure')
                    if 'build' in command or '--no-run' in command:
                        return None
                    return SimpleNamespace(returncode=0 if failure == 'survived' else 101,
                                           stdout='', stderr='unrelated failure')

                rejected(lambda: helper(SimpleNamespace(run=run), root, roots, [],
                    {'CARGO_TARGET_DIR': str(root)}, *extra))
                assert path.read_text() == before
        path = root / 'src/lib.rs'
        path.write_text('original source')

        def source(*args):
            path.write_text('changed probe')

        rejected(lambda: probes.negatives(SimpleNamespace(source=source, run=fail), root, 'brynja', [], {}))
        assert path.read_text() == 'original source'
