#!/usr/bin/env python3
"""Compile repository fixtures against lean archives without overlaying inputs.

This bounded packaging check is not a replacement for native execution, the
existing oracle campaigns, or cleanup qualification. It proves that moving
fixtures out of downloads preserves all affected downstream test targets.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
from unittest.mock import patch

import package_contents as contents

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('lean_facade_package',
    Path(__file__).with_name('check-facade-package.py'))
api = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = api
spec.loader.exec_module(api)


def snapshot(roots):
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for root in roots.values() for path in root.rglob('*') if path.is_file()}


def execute(root, selected=None):
    env = api.clean_environment(root)
    with patch.dict(os.environ, env, clear=True), patch.object(api.packaging, 'PACKAGING_PACKAGES',
            api.archives.specifications(api.packaging)):
        roots = api.parallelhash.package_roots(api.packaging, root)
    for name in contents.MIGRATED.intersection(roots):
        contents.check(ROOT / 'crates' / name / 'Cargo.toml',
            [p.relative_to(roots[name]).as_posix() for p in roots[name].rglob('*') if p.is_file()])
    original = snapshot(roots)
    cases = (
        ('sha2', api.sha2_execution, (False,)),
        ('sha2-hardened', api.sha2_execution, (True,)),
        ('sha2-scoped', api.scoped_sha2, ()),
        ('sha3', api.sha3_execution, ()),
        ('sha3-hardened', api.hardened_sha3, ()),
        ('kmac', api.kmac, ()),
        ('tuplehash', api.tuplehash, ()),
        ('parallelhash', api.parallel_execution, ()),
    )
    for package in ('brynja', 'brynja-crypto'):
        for label, module, extra in cases:
            if selected is not None and label != selected:
                continue
            consumer = root / (package + '-' + label)
            (consumer / 'src').mkdir(parents=True)
            (consumer / 'tests').mkdir()
            module.install(api, consumer, roots, package, *extra)
            for profile in ([], ['--release']):
                api.run(['cargo', '+1.99.1', 'test', '--offline', '--no-run', *profile], consumer, env)
            print(f'Lean fixture compile: {package}/{label}; debug/release PASS (not runtime execution)', flush=True)
    contents.require(snapshot(roots) == original, 'fixture build changed extracted dependency inputs')
    count = 2 * (len(cases) if selected is None else 1)
    print(f'Repository-only fixtures: {count} consumers / {count * 2} profile builds PASS; pristine archives unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family', choices=('sha2', 'sha2-hardened', 'sha2-scoped', 'sha3',
                                             'sha3-hardened', 'kmac', 'tuplehash', 'parallelhash'))
    args = parser.parse_args()
    with api.cargo_environment.private_directory(ROOT) as directory:
        execute(Path(directory), args.family)
