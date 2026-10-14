"""One explicit additive-API review, not a general production-change exemption.

Original platform records cover only their unchanged execution paths. New setup
APIs have separate Linux x86 functional checks, not fresh Apple/Arm qualification.
"""
from pathlib import Path
import subprocess

import native_review_io as io
import native_review_scope as scope

REVIEW = 'security/native-reuse/v0.24.50-setup-review.json'
REVIEW_SHA256 = '8e8b480698d66dce1e869b6c496af8da73419ab841bef286e39383e64ab0c7c7'
BASE = 'b31075ee038714a6ef2a4bd304324a74e74d635c'
SOURCE = 'e4db2751d43dbf1130b5717a00bb8b050caadce5'
FAMILIES = {
    'keccak-hardened': 'sha3-execution',
    'kmac-execution': 'kmac-execution',
    'tuplehash-execution': 'tuplehash-execution',
    'parallelhash-execution': 'parallelhash-differential',
}
PACKAGES = ['-p', 'brynja-hash-sha3', '-p', 'brynja-mac-kmac']
COMMANDS = [
    ['cargo', '+1.98.1', 'test', '--locked', '--offline', *PACKAGES,
     '--all-features', '--lib', 'setup'],
    ['cargo', '+1.98.1', 'test', '--locked', '--offline', '--release', *PACKAGES,
     '--all-features', '--lib', 'setup'],
    ['cargo', '+1.98.1', 'test', '--locked', '--offline', *PACKAGES,
     '--no-default-features', '--lib', 'setup'],
    ['cargo', '+1.98.1', 'test', '--locked', '--offline', *PACKAGES,
     '--all-features', '--doc', 'setup'],
]
TESTS = (
    'fragmented_domains_match_contiguous_at_all_bit_offsets',
    'completion_checks_shape_not_just_phase',
    'errors_and_unwind_clear_and_cannot_reopen_setup',
    'in_place_completion_erases_source_on_success_and_error',
    'streamed_setup_matches_all_four_contiguous_identities',
    'rejected_incomplete_excess_and_wrong_phase_are_terminal',
    'exact_completion_and_unwind_clear_source',
)


def feature_graph(root, family, graph):
    packages = [p for p in graph['packages'] if p['name'] == 'brynja-crypto-cpu-std']
    if family == 'parallelhash-execution':
        io.require(not packages, 'unexpected hosted dependency in parallel fixture')
        return
    io.require(len(packages) == 1, 'ambiguous hosted dependency')
    package = packages[0]
    io.require(Path(package['manifest_path']).resolve() ==
               (root / 'crates/brynja-crypto-cpu-std/Cargo.toml').resolve(),
               'unexpected hosted dependency origin')
    nodes = [n for n in graph['resolve']['nodes'] if n['id'] == package['id']]
    io.require(len(nodes) == 1 and 'strict-sha2' not in nodes[0]['features'],
               'Windows module reachable in captured fixture')


def inactive(root, family):
    result = subprocess.run(['cargo', '+1.98.1', 'metadata', '--locked', '--offline',
                             '--format-version', '1', '--manifest-path',
                             'assurance/' + FAMILIES[family] + '/Cargo.toml'],
                            cwd=root, check=True, stdout=subprocess.PIPE, timeout=60)
    io.require(len(result.stdout) <= io.LIMIT, 'setup feature graph exceeds bound')
    feature_graph(root, family, io.document(result.stdout))


def changes(root, base, source, closure):
    old, new = io.tree(root, base), io.tree(root, source)
    result = {}
    for name in sorted(set(old) | set(new)):
        if not scope.selected(name, closure) or old.get(name) == new.get(name):
            continue
        io.require(name in new, 'reviewed input removal: ' + name)
        if name == 'Cargo.lock':
            io.require(scope.lock(root, base) == scope.lock(root, source),
                       'reviewed dependency graph changed')
            continue
        result[name] = {
            'before': io.sha(io.historical(root, base, name)) if name in old else None,
            'after': io.sha(io.historical(root, source, name)),
        }
    return result


def check_log(index, raw):
    output = raw.decode()
    io.require(output and '0 failed' in output and 'test result: FAILED' not in output,
               'failed or empty setup test output')
    if index < 3:
        io.require(all(any(line.startswith('test ') and line.endswith('::' + name + ' ... ok')
                           for line in output.splitlines()) for name in TESTS),
                   'incomplete setup test population')
    else:
        io.require(output.count('test result: ok. 10 passed; 0 failed; 0 ignored;') == 2 and
                   sum('Setup (line ' in line and line.endswith(' - compile fail ... ok')
                       for line in output.splitlines()) == 20, 'setup ownership test population')


def checks(root, doc, head):
    io.require(len(doc['checks']) == len(COMMANDS), 'complete setup checks required')
    io.require('host: x86_64-unknown-linux-gnu' in doc['compiler'].splitlines() and
               'release: 1.98.1' in doc['compiler'].splitlines(), 'setup check compiler/host')
    for index, (row, command) in enumerate(zip(doc['checks'], COMMANDS)):
        name = f'security/native-reuse/v0.24.50-setup-{index:02d}.log'
        io.require(set(row) == {'command', 'exit_code', 'log', 'sha256'} and
                   row['command'] == command and type(row['exit_code']) is int and
                   row['exit_code'] == 0 and row['log'] == name, 'setup check identity/result')
        raw = io.committed(root, name, head)
        io.require(io.sha(raw) == row['sha256'], 'setup check log hash')
        check_log(index, raw)


def validate(root, family, original, adapter, current, captured, head):
    from native_review_carry_forward import check_protected, check_closure
    io.require(family in FAMILIES and original['reviewed_commit'] == BASE,
               'setup supplement family/base')
    raw = io.committed(root, REVIEW, head)
    io.require(io.sha(raw) == REVIEW_SHA256, 'setup supplement requires exact accepted review')
    doc = io.document(raw)
    io.require(set(doc) == {'schema', 'base_commit', 'source_commit', 'disposition',
                           'families', 'changes', 'compiler', 'checks'} and
               type(doc['schema']) is int and doc['schema'] == 1 and
               doc['base_commit'] == BASE and doc['source_commit'] == SOURCE and
               doc['disposition'] == 'accepted-unchanged-paths-with-separate-setup-tests' and
               doc['families'] == FAMILIES, 'setup supplement schema/scope')
    io.git(root, 'merge-base', '--is-ancestor', BASE, SOURCE)
    io.git(root, 'merge-base', '--is-ancestor', SOURCE, head)
    # Revalidate the original test-only decision; do not broaden it retroactively.
    check_protected(root, original, BASE)
    previous = {name: adapter.digest(name, io.historical(root, BASE, name))
                for name in current if name in io.names(root, BASE)}
    check_closure(root, original, previous, captured, adapter.digest)
    expected = changes(root, BASE, SOURCE, current)
    approved = {name: row for name, row in doc['changes'].items()
                if scope.selected(name, current)}
    io.require(expected == approved, 'setup supplement source delta differs')
    scope.unchanged(root, SOURCE, head, current)
    for name, digest in current.items():
        io.require(adapter.digest(name, io.historical(root, SOURCE, name)) == digest,
                   'setup supplement current input changed: ' + name)
    inactive(root, family)
    checks(root, doc, head)
