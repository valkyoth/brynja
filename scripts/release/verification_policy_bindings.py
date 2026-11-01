"""Source-policy assessments with explicit original inventories, not a gate.

These legacy checkers inspect source text and their own reviewed pins. Their
report/workflow inputs belong only to these rows, not to runtime or proof rows.
The exporter reads this maintained data; status scans never import checkers.
"""
import json
from pathlib import Path
from verification_assessment_bindings import ENV
from verification_miri_bindings import REJECT

DATA = Path(__file__).with_name('verification_policy_inputs.json')
MARKERS = {
    'sha2': ('sha256',
        ['complete portable six-algorithm SHA-2 source policy: PASS'],
        ['portable SHA-2 policy validates every fixture baseline and rejects unsafe, native, allocation, identity, bit-domain, arithmetic, padding, dynamic-analysis, SHA-2/HMAC ownership, package, test, size, and hash regressions']),
    'sha3': ('sha3',
        ['complete portable six-function FIPS 202 source policy: PASS'],
        ['portable SHA-3 policy rejects seventy-one boundary, permutation, padding, SP 800-185, cSHAKE, bit-domain, XOF, allocation, timeout, identity, dynamic-analysis, size, and hash regressions']),
    'kmac': ('kmac',
        ['complete KMAC128/KMAC256/KMACXOF128/KMACXOF256 source policy: PASS'],
        ['KMAC codegen accepts exact owners alongside Setup names and rejects 18 lookup/cleanup regressions',
         'KMAC policy rejects ownership, lifecycle, borrowed-comparison, feature, algorithm, test, and dependency regressions']),
    'tuplehash': ('tuplehash',
        ['complete TupleHash128/256 and TupleHashXOF128/256 source policy: PASS'],
        ['TupleHash policy rejects forty-two encoding, lifecycle, cleanup, API, proof, dynamic-analysis, code-generation, test, and dependency regressions',
         'Scoped TupleHash policy rejects 110 semantic regressions']),
    'parallelhash': ('parallelhash',
        ['complete ParallelHash128/256 and ParallelHashXOF128/256 source policy: PASS'],
        ['ParallelHash Miri matrix modules reject five production-import regressions',
         'ParallelHash buffering matrix rejects production import and disconnected helper',
         'ParallelHash policy rejects thirty-six domain, encoding, lifecycle, cleanup, scheduling, evidence, test, and dependency regressions',
         'Borrowed ParallelHash framing/leaf policy rejects 227 semantic regressions',
         'Scoped thread handoff rejects 91 semantic regressions']),
}


def definitions():
    result = {('python3', f'scripts/{family}/{mode}-{stem}.py'): (family, lines)
            for family, (stem, check, test) in MARKERS.items()
            for mode, lines in [('check', check), ('test', test)]}
    for family, count, title in [('kmac', 98, 'KMAC'), ('tuplehash', 148, 'TupleHash')]:
        result[('python3', f'scripts/{family}/test-{family}-execution-policy.py')] = (
            family + '-execution', [f'{title} execution policy rejects {count} semantic regressions'])
    result[('python3', 'scripts/sha3/test-sha3-hardened.py')] = ('sha3-hardened', [
        'hardened FIPS 202 policy rejects thirty-four cleanup, lifecycle, source-transition, metadata-ownership, capability, API, temporary, unsafe, failure, unwind, dynamic-analysis, and codegen regressions'])
    return result


def build(rows):
    known = definitions()
    scripts = {argv[1] for argv in known}
    declared = json.loads(DATA.read_text())
    groups = {'source-policy-python': {'tools': [{'program': 'python3'}]}}
    checks = []
    for row in rows:
        argv = tuple(row['command'])
        if row['phase'] != 'repository' or len(argv) < 2 or argv[0] != 'python3' or argv[1] not in scripts:
            continue
        if argv not in known or row.get('environment') or row.get('stdin'):
            raise ValueError('unreviewed source-policy selector: ' + row['id'])
        family, markers = known[argv]
        key = 'source-policy-' + row['id']
        groups[key] = {'paths': [argv[1], *declared[family]['paths']]}
        if family == 'kmac' and '/test-' in argv[1]:
            # Only extracted lookup snippets on synthetic artifacts, no compiler.
            groups[key]['tools'] = [{'program': p} for p in ('bash', 'grep', 'awk', 'head', 'cut')]
        checks.append(dict(component=row['families'][0], id=row['id'], name=row['label'], category='repository',
            command=list(argv), cwd='.', inputs=['source-policy-python', key], environment=ENV, reject_environment=REJECT,
            success={'contains': markers, 'unique_lines': markers}, timeout_seconds=300, log_bytes=16777216,
            establishes='Existing source-policy and checker mutation assertions only; not execution of cryptography, '
                        'native tests, Miri or proofs. This legacy policy also reads its original review pins and '
                        'gate/declaration text: their changes affect this row only, not prior runtime/proof results.'))
    return dict(schema=1, groups=groups, checks=checks)
