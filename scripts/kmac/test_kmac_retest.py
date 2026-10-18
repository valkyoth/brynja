"""Focused non-compiling regressions for the v0.24.53 retest guards."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import kmac_production_mutants


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
    for bad in ('', '\n'.join(records[:-1]), output.replace('E0599', 'E0433'),
                output.replace('"is_primary": true', '"is_primary": false'),
                output.replace(probes[0], probes[1])):
        rejects(lambda: gate.validate(bad, source))
    rejects(lambda: gate.validate(output, source.replace(probes[0], '')))
    oracle = load('check-kmac-differential')
    cases = oracle.cases()
    selected = oracle.production_cases(cases)
    assert len(selected) == 43
    expected = '\n'.join('KMAC_PRODUCTION_ORACLE: ' + c[0] for c in selected)
    oracle.production_population(expected, cases)
    for bad in ('', expected.rsplit('\n', 1)[0], expected + '\n' + expected,
                expected.replace('kmac128', 'kmac256')):
        rejects(lambda: oracle.production_population(bad, cases))
    for code, output, error, valid in (
        (0, 'ff\n', '', True), (1, '', 'oracle mismatch', True),
        (0, 'aa\n', '', False), (0, '', '', False), (0, 'garbage\n', '', False),
        (101, '', 'compiler error', False), (-9, '', 'mismatch', False),
        (1, '', 'unrelated runtime error', False),
    ):
        result = SimpleNamespace(returncode=code, stdout=output, stderr=error)
        assert kmac_production_mutants.rejected(result, ['aa']) == valid
    print('Retest guards reject six diagnostic and four production-population regressions')
    print('Production mutant verdict accepts wrong bytes/runtime mismatches; rejects six false failures')
