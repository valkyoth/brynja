#!/usr/bin/env python3
"""Tag-only requirement for reviewed, fresh native hardened SHA-1 captures."""
import hashlib
import json
import re
import subprocess
from pathlib import Path
import hardened_native as native

ROOT = native.policy.ROOT
INDEX = 'security/sha1-hardened-native.json'


def bounded_json(root, relative):
    path = Path(relative)
    native.require(not path.is_absolute() and '..' not in path.parts, 'artifact must be repository-relative')
    return json.loads(native.policy.read(root, relative))


def validate_record(record, lane, expected):
    native.require(record.get('schema') == 1 and record.get('version') == '0.24.42', 'capture schema/version')
    native.require(record.get('lane') == lane and record.get('source_sha256') == expected, 'lane/source closure')
    native.require(re.fullmatch('[0-9a-f]{40}', record.get('commit', '')), 'capture commit')
    native.require(record.get('native') == 'operator-self-attested' and record.get('profile') == 'hardened-legacy-only', 'attestation/profile')
    native.require(record.get('owned_memory_regions') == 7, 'region inventory')
    for claim in ('fips_validated', 'independent_review', 'register_erasure'):
        native.require(record.get(claim) is False, 'unsupported '+claim)
    arm = native.LANES[lane] == 'arm'
    system = 'Darwin' if lane == 'apple-m2-aarch64' else 'Linux'
    target = 'aarch64-apple-darwin' if system=='Darwin' else 'aarch64-unknown-linux-gnu' if arm else 'x86_64-unknown-linux-gnu'
    native.require(record.get('system') == system and record.get('static_features') == ('+neon,+sha2' if arm else '+sse2,+sha'), 'system/features')
    compiler = record.get('compiler', '').splitlines()
    native.require('release: 1.98.1' in compiler and 'host: '+target in compiler, 'native compiler')
    native.require(isinstance(record.get('cpu'), str) and bool(record['cpu']), 'CPU identity')
    native.require(record.get('disposition') == 'pending owner review; native correctness is not migration or side-channel proof', 'capture limits')
    native.validate_results(record.get('results', {}), lane)


def validate(root=ROOT):
    index = bounded_json(root, INDEX)
    native.require(set(index) == {'schema', 'version', 'owner_review', 'captures'}, 'index fields')
    native.require(index['schema']==1 and index['version']=='0.24.42', 'index version')
    native.require(index['owner_review']=='accepted-correctness-with-residuals', 'owner review pending')
    required = {'intel-x86_64', 'aws-aarch64', 'apple-m2-aarch64'}
    native.require(required <= set(index['captures']) <= set(native.LANES), 'required native lanes missing')
    expected = native.policy.hashes(root)
    for lane, entry in index['captures'].items():
        native.require(set(entry)=={'path','sha256'}, 'artifact descriptor')
        source = native.policy.read(root, entry['path'])
        native.require(hashlib.sha256(source.encode()).hexdigest()==entry['sha256'], 'artifact checksum')
        record = bounded_json(root, entry['path'])
        validate_record(record, lane, expected)
        subprocess.run(['git','merge-base','--is-ancestor',record['commit'],'HEAD'], cwd=root, check=True, timeout=30)
    print('Hardened SHA-1 native qualification: reviewed correctness with explicit residual limits')


if __name__ == '__main__': validate()
