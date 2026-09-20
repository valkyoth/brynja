#!/usr/bin/env python3
"""Reuse actual crate assembly for development checks, never a release receipt."""
import argparse
import importlib
import json
from pathlib import Path
import sys

import check_callers as audit
import check_worker_handoffs as handoffs

# Existing instruction/erasure validators, not a second implementation of them.
CHECKS = (
    ('brynja-core', 'secret_copy', 'COPY'),
    ('brynja-core', 'secret_mask', 'MASK'),
    ('brynja-core', 'secret_xor', 'XOR'),
    ('brynja-core', 'secret_predicate', 'PREDICATE'),
    ('brynja-core', 'secret_difference', 'DIFFERENCE'),
    ('brynja-hash-core', 'secret_predicate', 'PREDICATE'),
    ('brynja-hash-sha2', 'sha256_scalar', 'SCALAR'),
    ('brynja-hash-sha2', 'sha512_scalar', 'SCALAR'),
    ('brynja-hash-sha3', 'keccak_scalar', 'SCALAR'),
    ('brynja-legacy-sha1', 'sha1_scalar', 'SCALAR'),
    ('brynja-legacy-md5', 'md5_scalar', 'SCALAR'),
)


def cases(record_path):
    # The existing checker enforces exact compiler/target/profile coverage,
    # source identity, and artifact hashes before returning any assembly.
    handoffs.require(len(CHECKS) == 11 and len({(p, v) for p, v, _ in CHECKS}) == 11,
                     'boundary inventory is missing or duplicated')
    handoffs.checked_functions(record_path, batch=True)
    record = json.loads(record_path.read_text())
    for row in record['records']:
        arm = row['target'].startswith('aarch64')
        for package, validator, marker in CHECKS:
            paths = [record_path.parent / key for key in row['artifacts']
                     if Path(key).name.startswith(package.replace('-', '_') + '-')
                     and key.endswith('.s')]
            handoffs.require(len(paths) == 1, 'missing/ambiguous actual crate assembly: ' + package)
            module = importlib.import_module('check_' + validator)
            yield package, validator, marker, arm, module.inspect, paths[0].read_text()


def inspector_sources():
    """Report the exact loaded local Python validators, separately from Rust inputs."""
    paths = {Path(__file__).resolve()}
    for module in tuple(sys.modules.values()):
        source = getattr(module, '__file__', None)
        if source:
            path = Path(source).resolve()
            if path.is_relative_to(audit.ROOT) and path.suffix == '.py':
                paths.add(path)
    return {str(path.relative_to(audit.ROOT)): audit.digest(path) for path in sorted(paths)}


def main(record_path):
    before = audit.sources()
    count = 0
    for package, name, _, arm, inspect, assembly in cases(record_path):
        inspect(assembly, arm)
        count += 1
    handoffs.require(count == 88, 'incomplete recorded boundary coverage')
    handoffs.require(before == audit.sources(), 'source changed during inspection')
    print(f'Recorded production boundaries: {count} PASS; 11 boundaries x 8 compiler/target/profile configurations')
    print('Observation record SHA-256: ' + audit.digest(record_path))
    print('Inspector source SHA-256: ' + json.dumps(inspector_sources(), sort_keys=True))
    print('Development assembly inspection only; no native run, build, release receipt or whole-call erasure claim')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record)
