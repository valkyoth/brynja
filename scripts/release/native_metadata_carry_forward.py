"""Narrow TupleHash/ParallelHash carry-forward: facade fixture version only.

Artifacts remain untouched and retain their capture commit. No native code,
capture command, compiler, result, or executable policy changes are exempted.
"""
from pathlib import Path
import sys
import tomllib
import argparse

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


def reviewed_pin_only(previous, current, old_fixture, new_fixture, fixture=FIXTURE, quote='"'):
    before = evidence.hashlib.sha256(old_fixture).hexdigest().encode()
    after = evidence.hashlib.sha256(new_fixture).hexdigest().encode()
    old_entry = (quote + fixture + quote + ': ' + quote).encode() + before + quote.encode()
    new_entry = (quote + fixture + quote + ': ' + quote).encode() + after + quote.encode()
    evidence.require(previous.count(old_entry) == 1 and
                     previous.replace(old_entry, new_entry, 1) == current,
                     'carry-forward cannot change executable review policy or other pins')


def validate(root=ROOT, family='tuplehash'):
    evidence = {'tuplehash': globals()['evidence'], 'parallelhash': parallel_evidence}[family]
    review = f'scripts/{family}/{family}_reviewed_hashes.py'
    fixture = f'assurance/{family}-public-api/Cargo.toml'
    digest = evidence.shared.source_digest if family == 'tuplehash' else evidence.digest
    shared, require = evidence.shared, evidence.require
    head = shared.git(root, 'rev-parse', 'HEAD').decode().strip()
    require(not shared.git(root, 'status', '--porcelain', '--untracked-files=all').strip(),
            'clean carry-forward checkout required')

    def historical(commit, name):
        require(int(shared.git(root, 'cat-file', '-s', commit + ':' + name)) <= shared.LIMIT,
                'carry-forward object bound')
        return shared.git(root, 'show', commit + ':' + name).replace(b'\r\n', b'\n')

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
    shared.git(root, 'merge-base', '--is-ancestor', capture, head)
    require(set(index['lanes']) == set(evidence.LANES), 'all carry-forward native lanes required')
    expected = evidence.sources(root)
    captured = {name: digest(name, historical(capture, name)) for name in expected}
    changed = {name for name in expected if expected[name] != captured[name]}
    require(changed == {review}, 'carry-forward rejects any other native-input change')
    old_fixture, new_fixture = historical(capture, fixture), current(fixture)
    old_version = tomllib.loads(historical(capture, FACADE).decode())['package']['version']
    new_version = tomllib.loads(current(FACADE).decode())['package']['version']
    version_only(old_fixture, new_fixture, old_version, new_version)
    reviewed_pin_only(historical(capture, review), current(review), old_fixture, new_fixture,
                      fixture, '"' if family == 'tuplehash' else "'")
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
    print(f'{family} native evidence: PASS via verified facade-version-only carry-forward; '
          'original capture and raw artifacts retained')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family', choices=('tuplehash', 'parallelhash'), default='tuplehash')
    validate(family=parser.parse_args().family)
