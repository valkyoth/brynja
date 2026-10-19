"""Narrow TupleHash/ParallelHash carry-forward: facade fixture version only.

Artifacts remain untouched and retain their capture commit. No native code,
capture command, compiler, result, or executable policy changes are exempted.
"""
from pathlib import Path
import sys
import tomllib
import argparse
import native_review_io as io
import native_review_scope as scope

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/tuplehash'))
import tuplehash_execution_native as evidence
sys.path.insert(0, str(ROOT / 'scripts/parallelhash'))
import parallelhash_execution_native as parallel_evidence

REVIEW = 'scripts/tuplehash/tuplehash_reviewed_hashes.py'
FIXTURE = 'assurance/tuplehash-public-api/Cargo.toml'
FACADE = 'crates/brynja/Cargo.toml'


def version_only(previous, current, old_version, new_version):
    """Require exactly one facade-version replacement and no other byte change."""
    require = evidence.require
    old = tomllib.loads(previous.decode())
    new = tomllib.loads(current.decode())
    require(old['dependencies']['brynja']['version'] == '=' + old_version and
            new['dependencies']['brynja']['version'] == '=' + new_version,
            'fixture must track the corresponding facade versions')
    before = ('version = "=' + old_version + '"').encode()
    after = ('version = "=' + new_version + '"').encode()
    require(previous.count(before) == 1 and old_version != new_version and
            previous.replace(before, after, 1) == current,
            'carry-forward only permits the fixture facade version')


def replace_pin(previous, old_fixture, new_fixture, fixture=FIXTURE, quote='"'):
    before = evidence.hashlib.sha256(old_fixture).hexdigest().encode()
    after = evidence.hashlib.sha256(new_fixture).hexdigest().encode()
    old_entry = (quote + fixture + quote + ': ' + quote).encode() + before + quote.encode()
    new_entry = (quote + fixture + quote + ': ' + quote).encode() + after + quote.encode()
    evidence.require(previous.count(old_entry) == 1,
                     'carry-forward requires exactly one fixture pin')
    return previous.replace(old_entry, new_entry, 1)


def reviewed_pin_only(previous, current, old_fixture, new_fixture, fixture=FIXTURE, quote='"'):
    evidence.require(replace_pin(previous, old_fixture, new_fixture, fixture, quote) == current,
                     'carry-forward cannot change executable review policy or other pins')


def validate(root=ROOT, family='tuplehash'):
    evidence = {'tuplehash': globals()['evidence'], 'parallelhash': parallel_evidence}[family]
    review = f'scripts/{family}/{family}_reviewed_hashes.py'
    fixture = f'assurance/{family}-public-api/Cargo.toml'
    digest = evidence.shared.source_digest if family == 'tuplehash' else evidence.digest
    shared, require = evidence.shared, evidence.require
    head = shared.git(root, 'rev-parse', 'HEAD').decode().strip()
    from native_evidence_approval import validate as approve
    approval = approve(family + '-execution', root, head)
    require(not shared.git(root, 'status', '--porcelain', '--untracked-files=all').strip(),
            'clean carry-forward checkout required')

    def historical(commit, name):
        return io.historical(root, commit, name)

    def current(name):
        raw = shared.bounded(root, name).replace(b'\r\n', b'\n')
        require(raw == historical(head, name), 'carry-forward inputs must be committed')
        return raw

    index = shared.document(current(evidence.INDEX))
    require(set(index) == {'schema', 'capture_commit', 'lanes'} and
            type(index['schema']) is int and index['schema'] == 1, 'carry-forward index schema')
    capture = index['capture_commit']
    require(isinstance(capture, str) and evidence.re.fullmatch('[a-f0-9]{40}', capture),
            'carry-forward capture commit')
    require(capture == approval['capture_commit'], 'approved capture identity')
    shared.git(root, 'merge-base', '--is-ancestor', capture, head)
    require(set(index['lanes']) == set(evidence.LANES), 'all carry-forward native lanes required')
    expected = evidence.sources(root)
    captured = {name: digest(name, historical(capture, name)) for name in expected}
    changed = {name for name in expected if expected[name] != captured[name]}
    approved = approval['validation_changes']
    require(set(approved) <= set(expected), 'approved validation input absent from capture')
    require(review in changed and changed <= set(approved) | {review},
            'carry-forward rejects any other native-input change')
    old_fixture, new_fixture = historical(capture, fixture), current(fixture)
    old_version = tomllib.loads(historical(capture, FACADE).decode())['package']['version']
    new_version = tomllib.loads(current(FACADE).decode())['package']['version']
    version_only(old_fixture, new_fixture, old_version, new_version)
    quote = '"' if family == 'tuplehash' else "'"
    intermediate = historical(capture, review)
    if review in approved:
        # The evidence snapshot may predate the separately approved validator
        # edits. Undo ONLY the proven fixture pin and authenticate the resulting
        # complete module against the externally pinned after digest below.
        intermediate = replace_pin(current(review), new_fixture, old_fixture, fixture, quote)
    # This is not candidate self-approval: every intermediate byte must match
    # the independently supplied digest, including executable logic/other pins.
    for name, pair in approved.items():
        after = intermediate if name == review else current(name)
        require(io.sha(historical(capture, name)) == pair['before'] and
                io.sha(after) == pair['after'], 'approved validation bytes changed: ' + name)
    reviewed_pin_only(intermediate, current(review), old_fixture, new_fixture, fixture, quote)
    # Raw approved pairs and the single structural pin replacement were checked
    # above. Retain additions/removals/build checks for the entire family closure.
    scope.unchanged(root, capture, head, expected,
                    reviewed_validation=set(approved) | {review})
    for lane, row in index['lanes'].items():
        require(set(row) == {'artifact', 'sha256', 'cpu', 'reviewed'} and row['reviewed'] is True,
                'carry-forward owner review required')
        name = row['artifact']
        require(isinstance(name, str) and evidence.re.fullmatch(
            f'assurance/{family}-execution-native/[a-z0-9_-]+[.]json', name),
            'carry-forward artifact path')
        raw = current(name)
        require(evidence.hashlib.sha256(raw).hexdigest() == row['sha256'], 'carry-forward artifact hash')
        record = shared.document(raw)
        evidence.record_check(record, lane, capture, captured)
        require(record['cpu'] == row['cpu'], 'carry-forward reviewed CPU identity')
    io.clean(root)
    require(shared.git(root, 'rev-parse', 'HEAD').decode().strip() == head and
            evidence.sources(root) == expected, 'checkout changed during native reuse')
    print(f'{family} native evidence: PASS via verified facade-version-only carry-forward '
          f'with {len(approved)} externally approved validation changes; '
          'original capture and raw artifacts retained; no new native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family', choices=('tuplehash', 'parallelhash'), default='tuplehash')
    validate(family=parser.parse_args().family)
