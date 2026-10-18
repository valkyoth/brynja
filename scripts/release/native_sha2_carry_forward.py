#!/usr/bin/env python3
"""Reuse SHA-2 capture only when the added enclave module is feature-inactive.

Original artifacts are validated with their actual source/commit identities.
This does not qualify Windows or any newly reachable implementation.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

import native_review_io as io
import native_review_scope as scope

sys.path.insert(0, str(io.ROOT / 'scripts/sha2'))
import hardened_native_evidence as evidence

LIB = 'crates/brynja-crypto-cpu-std/src/lib.rs'
DIRECTORY = 'crates/brynja-crypto-cpu-std/src/windows_enclave/'
ANCHOR = b'pub mod strict_tuplehash;\n'
DECLARATION = b'#[cfg(feature = "strict-sha2")]\npub mod windows_enclave;\n'
FIXTURE = 'assurance/sha2-hardened-execution/Cargo.toml'


def inactive(root):
    result = subprocess.run(['cargo', '+1.98.1', 'metadata', '--locked', '--offline',
                             '--format-version', '1', '--manifest-path', FIXTURE],
                            cwd=root, check=True, stdout=subprocess.PIPE, timeout=60)
    io.require(len(result.stdout) <= io.LIMIT, 'SHA-2 feature graph exceeds bound')
    graph = io.document(result.stdout)
    packages = [row for row in graph['packages'] if row['name'] == 'brynja-crypto-cpu-std']
    io.require(len(packages) == 1, 'ambiguous hosted package graph')
    package = packages[0]
    io.require(Path(package['manifest_path']).resolve() ==
               (root / 'crates/brynja-crypto-cpu-std/Cargo.toml').resolve(),
               'unexpected hosted package origin')
    nodes = [row for row in graph['resolve']['nodes'] if row['id'] == package['id']]
    io.require(len(nodes) == 1 and 'strict-sha2' not in nodes[0]['features'],
               'Windows enclave module is reachable in native fixture')


def equivalent(root, capture, current, captured):
    added = set(current) - set(captured)
    io.require(added and all(name.startswith(DIRECTORY) and name.endswith('.rs') for name in added),
               'unexpected SHA-2 source addition')
    io.require(set(captured) <= set(current) and not any(n.startswith(DIRECTORY) for n in captured),
               'SHA-2 source removed or enclave already captured')
    def structural(revision):
        return {name: value for name, value in io.tree(root, revision).items()
                if scope.selected(name, current) and name not in {LIB, 'Cargo.lock'} and
                not name.startswith(DIRECTORY)}
    io.require(structural(capture) == structural(io.git(root, 'rev-parse', 'HEAD').decode().strip()),
               'SHA-2 implementation/build inventory changed')
    old = io.historical(root, capture, LIB)
    new = io.read(root, LIB)
    io.require(old.count(ANCHOR) == 1 and DECLARATION not in old and
               new == old.replace(ANCHOR, ANCHOR + DECLARATION),
               'hosted module declaration is not the exact guarded addition')
    for name, expected in captured.items():
        io.require(evidence.source_digest(name, io.historical(root, capture, name)) == expected,
                   'original SHA-2 source mismatch: ' + name)
        if name != LIB:
            io.require(current[name] == expected, 'changed SHA-2 input: ' + name)
    # Manifest, lock graph, capture commands and .cargo inputs above remain
    # exact. Also inspect the resolved feature union; never trust a path label.
    inactive(root)


def validate(root=io.ROOT):
    io.clean(root)
    head = io.git(root, 'rev-parse', 'HEAD').decode().strip()
    index = io.document(io.committed(root, evidence.INDEX, head))
    io.require(set(index) == {'schema', 'capture_commit', 'lanes'} and
               type(index['schema']) is int and index['schema'] == 1, 'SHA-2 index schema')
    capture = io.revision(index['capture_commit'])
    io.git(root, 'merge-base', '--is-ancestor', capture, head)
    io.require(set(index['lanes']) == set(evidence.LANES), 'all native SHA-2 lanes required')
    current = evidence.sources(root)
    closures = []
    for lane, row in index['lanes'].items():
        io.require(set(row) == {'artifact', 'sha256', 'cpu', 'reviewed'} and
                   row['reviewed'] is True, 'SHA-2 owner review pending')
        name = row['artifact']
        io.require(isinstance(name, str) and re.fullmatch(
            r'assurance/sha2-hardened-native/[a-z0-9_-]+[.]json', name), 'SHA-2 artifact path')
        raw = io.committed(root, name, head)
        io.require(hashlib.sha256(raw).hexdigest() == row['sha256'], 'SHA-2 artifact hash')
        record = io.document(raw)
        captured = record['sources']
        evidence.validate_record(record, lane, capture, captured)
        io.require(row['cpu'] == record['cpu'], 'SHA-2 reviewed CPU mismatch')
        closures.append(captured)
    io.require(all(value == closures[0] for value in closures), 'inconsistent SHA-2 capture closures')
    from native_unchanged import validate_inputs
    try:
        validate_inputs(root, capture, head, current, closures[0], evidence.source_digest)
        disposition = 'captured implementation/build inputs unchanged'
    except ValueError:
        equivalent(root, capture, current, closures[0])
        disposition = 'only exact feature-inactive enclave addition excluded'
    io.clean(root)
    io.require(io.git(root, 'rev-parse', 'HEAD').decode().strip() == head and
               evidence.sources(root) == current, 'SHA-2 inputs changed during validation')
    print('SHA-2 native reuse: PASS; original three-platform records retained; '
          + disposition + '. Original compiler/platform claims only. No Windows qualification.')


if __name__ == '__main__':
    try:
        validate()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
