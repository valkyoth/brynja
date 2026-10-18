"""Focused non-compiling regressions for the v0.24.53 retest guards."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import kmac_production_mutants
import kmac_admission_mutants


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rejects(call):
    try:
        call()
    except (ValueError, RuntimeError):
        return
    raise AssertionError('retest guard accepted a regression')


def check():
    gate = load('check-kmac-conformance-enabled')
    root = Path(__file__).resolve().parents[2]
    source = (root / 'assurance/kmac-conformance-rejected/src/enabled.rs').read_text()
    probes = [line.strip() for line in source.splitlines() if line.strip().startswith('let _ = ')]
    records = [json.dumps({'reason': 'compiler-message', 'message': {'level': 'error',
        'code': {'code': 'E0599'}, 'spans': [{'is_primary': True, 'text': [{'text': line}]}]}})
        for line in probes]
    output = '\n'.join(records)
    gate.validate(output, source)
    inventory = gate.kmac_conformance_inventory
    inventory.validate(root, gate.probes())
    source_root = root / 'crates/brynja-mac-kmac/src'
    read = lambda name: (source_root / name).read_text()
    for prefix in inventory.FAMILIES:
        for leaf in ('fixed.rs', 'xof.rs'):
            name = prefix + leaf
            original = read(name)
            anchor = 'conformance_api! { $profile;'
            assert anchor in original
            changed = original.replace(anchor, anchor + '\npub fn future_conformance() {}', 1)
            actual = inventory.inventory(lambda n: changed if n == name else read(n))
            assert actual != set(gate.probes())
            # Leaking any public conformance method outside the guard fails even
            # if someone adds the missing name to the hand-maintained probes.
            changed = original.replace(anchor, 'not_conformance_api! { $profile;', 1)
            rejects(lambda: inventory.inventory(lambda n: changed if n == name else read(n)))
    original = read('fixed.rs')
    changed = original + '\nimpl Kmac128 { pub fn outside_conformance() {} }\n'
    rejects(lambda: inventory.inventory(lambda n: changed if n == 'fixed.rs' else read(n)))
    changed = original.replace('production, Kmac128,', 'production, Kmac512,', 1)
    assert inventory.inventory(lambda n: changed if n == 'fixed.rs' else read(n)) != set(gate.probes())
    changed = original + '\n/* pub fn fake_conformance() {} */\n'
    assert inventory.inventory(lambda n: changed if n == 'fixed.rs' else read(n)) == set(gate.probes())
    positive = (root / 'assurance/kmac-conformance-rejected/src/positive.rs').read_text()
    gate.validate_positive(positive)
    assert len(gate.probes()) == 98
    assert positive.count('fn control_') == len(gate.probes())
    for bad in ('', positive.replace('fn control_0()', 'fn removed()'),
                positive.replace('::finalize_secret_bits_conformance', '::absent_method'),
                positive.replace('|_| ()', 'untyped_callback')):
        rejects(lambda: gate.validate_positive(bad))
    # Each owner family needs executable policy mutations, not just tokens.
    mutations = kmac_admission_mutants.cases(True)
    assert len(mutations) == 19
    assert {name for name, *_ in mutations} == {
        'fixed.rs', 'xof.rs', 'execution/fixed.rs', 'execution/xof.rs',
        'hardened_in_place/fixed.rs', 'hardened_in_place/xof.rs',
        'hardened_in_place/accelerated/fixed.rs', 'hardened_in_place/accelerated/xof.rs'}
    for success, code, status, summary in (
        (True, 0, 'ok', 'ok. 1 passed; 0 failed; 0 ignored;'),
        (False, 101, 'FAILED', 'FAILED. 0 passed; 1 failed; 0 ignored;'),
    ):
        output = f'test portable_policy ... {status}\ntest result: {summary}'
        result = SimpleNamespace(returncode=code, stdout=output)
        assert kmac_admission_mutants.verdict(result, 'portable_policy', success)
        for bad_code, bad_output in ((0 if code else 101, output), (code, ''),
                (code, output.replace('portable_policy', 'unrelated_test')),
                (code, output.replace('0 ignored;', '1 ignored;'))):
            bad = SimpleNamespace(returncode=bad_code, stdout=bad_output)
            assert not kmac_admission_mutants.verdict(bad, 'portable_policy', success)
    output = '\n'.join(records)
    for bad in ('', '\n'.join(records[:-1]), output.replace('E0599', 'E0433'),
                output.replace('"is_primary": true', '"is_primary": false'),
                output.replace(probes[0], probes[1])):
        rejects(lambda: gate.validate(bad, source))
    rejects(lambda: gate.validate(output, source.replace(probes[0], '')))
    oracle = load('check-kmac-differential')
    shared = oracle.cases()
    assert len(shared) == 256
    assert {name: sum(c[0] == name for c in shared) for name in
            ('kmac128', 'kmac256', 'kmacxof128', 'kmacxof256')} == {
                'kmac128': 64, 'kmac256': 64, 'kmacxof128': 64, 'kmacxof256': 64}
    cases = shared + oracle.production_byte_cases()
    selected = oracle.production_cases(cases)
    assert len(selected) == 59
    expected = '\n'.join('KMAC_PRODUCTION_ORACLE: ' + c[0] for c in selected)
    oracle.production_population(expected, cases)
    for bad in ('', expected.rsplit('\n', 1)[0], expected + '\n' + expected,
                expected.replace('kmac128', 'kmac256')):
        rejects(lambda: oracle.production_population(bad, cases))
    for identity in ('kmac128', 'kmac256', 'kmacxof128', 'kmacxof256'):
        for bits in (256, 512):
            reduced = [c for c in cases if not (c[0] == identity and c[7] == bits)]
            markers = '\n'.join('KMAC_PRODUCTION_ORACLE: ' + c[0]
                                for c in oracle.production_cases(reduced))
            rejects(lambda: oracle.production_population(markers, reduced))
    # In particular, leaking either verifier must remove an expected E0599.
    for method in ('verify_conformance', 'verify_bits_conformance'):
        reduced = [r for r, probe in zip(records, probes) if not probe.endswith('::' + method + ';')]
        assert len(reduced) < len(records)
        rejects(lambda: gate.validate('\n'.join(reduced), source))
    for code, output, error, valid in (
        (0, 'ff\n', '', True), (1, '', 'oracle mismatch', True),
        (0, 'aa\n', '', False), (0, '', '', False), (0, 'garbage\n', '', False),
        (101, '', 'compiler error', False), (-9, '', 'mismatch', False),
        (1, '', 'unrelated runtime error', False),
    ):
        result = SimpleNamespace(returncode=code, stdout=output, stderr=error)
        assert kmac_production_mutants.rejected(result, ['aa']) == valid
    print('Retest guards reject six diagnostic, two verifier-leak and twelve production-population regressions')
    print('Production mutant verdict accepts wrong bytes/runtime mismatches; rejects six false failures')
    print('Positive counterpart inventory and exact admission populations reject twelve false-pass cases')
    print('Source-derived conformance inventory rejects new methods, missing guards and changed owners across eight macro families')
