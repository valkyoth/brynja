#!/usr/bin/env python3
"""Invalid tag-width rejection through real public constructors, not a crypto proof."""
import argparse
from pathlib import Path
import re
import tomllib

import legacy_hmac_verifiers as verifier

FIXTURE = 'assurance/legacy-hmac-policy/Cargo.toml'
HARNESS_NAMES = ('md5_invalid_tag_width_rejects', 'sha1_invalid_tag_width_rejects')


def policy(root=verifier.ROOT):
    manifest = tomllib.loads((root / FIXTURE).read_text())
    if (set(manifest) != {'package', 'workspace', 'dependencies', 'lints'}
            or manifest['package'] != {'name': 'brynja-legacy-hmac-policy-fixture', 'version': '0.0.0',
                                       'edition': '2024', 'rust-version': '1.90', 'publish': False}
            or manifest['workspace'] != {}
            or manifest['dependencies'] != {'brynja-legacy-hmac': {
                'path': '../../crates/brynja-legacy-hmac', 'version': '=0.1.0', 'default-features': False}}):
        raise ValueError('legacy HMAC Kani fixture must consume only the portable real crate')
    lock = tomllib.loads((root / FIXTURE).with_name('Cargo.lock').read_text())
    expected = {'brynja-core': [], 'brynja-hash-core': [],
                'brynja-legacy-sha1': ['brynja-core', 'brynja-hash-core'],
                'brynja-legacy-md5': ['brynja-core', 'brynja-hash-core'],
                'brynja-legacy-hmac': ['brynja-core', 'brynja-legacy-md5', 'brynja-legacy-sha1'],
                'brynja-legacy-hmac-policy-fixture': ['brynja-legacy-hmac']}
    rows = lock.get('package', [])
    if set(lock) != {'version', 'package'} or lock['version'] != 4 or len(rows) != len(expected):
        raise ValueError('legacy HMAC proof lock population changed')
    if {row.get('name') for row in rows} != set(expected):
        raise ValueError('legacy HMAC proof dependency identity changed')
    for row in rows:
        name = row['name']
        path = root / (FIXTURE if name.endswith('-fixture') else 'crates/' + name + '/Cargo.toml')
        version = tomllib.loads(path.read_text())['package']['version']
        if (set(row) != {'name', 'version'} | ({'dependencies'} if expected[name] else set())
                or row['version'] != version or row.get('dependencies', []) != expected[name]):
            raise ValueError('legacy HMAC proof dependency origin/version/edges changed')
    source = (root / FIXTURE).with_name('src').joinpath('lib.rs').read_text()
    names = re.findall(r'#\[kani::proof\]\s+#\[kani::unwind\(2\)\]\s+fn ([a-z0-9_]+)\(\)', source)
    if tuple(names) != HARNESS_NAMES or source.count('#[kani::proof]') != 2:
        raise ValueError('legacy HMAC public-constructor proof population changed')
    for harness, identity, maximum in zip(HARNESS_NAMES, ('Md5', 'Sha1'), (16, 20), strict=True):
        bodies = re.findall(r'fn ' + harness + r'\(\) \{([^{}]*)\}', source)
        if (len(bodies) != 1 or 'Hmac::<' + identity + '>::with_tag_length(' not in bodies[0]
                or f'kani::assume(!(10..={maximum}).contains(&width));' not in bodies[0]
                or 'Err(Error::TagLength)' not in bodies[0]):
            raise ValueError('legacy HMAC proof must constrain width and call the actual public constructor')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy-only', action='store_true')
    args = parser.parse_args()
    policy()
    if args.policy_only:
        print('Legacy HMAC Kani inventory: 2 invalid-tag-width proofs; NOT executed')
        return
    pin = verifier.tool('kani')
    with verifier.cargo_environment.private_directory(verifier.ROOT) as temporary:
        env = verifier.environment(Path(temporary))
        env['CARGO_NET_OFFLINE'] = 'true'
        cargo = ['cargo', '+' + pin['execution_toolchain'], 'kani']
        banner = verifier.run([*cargo, '--version'], env).strip()
        if banner != f'Kani Rust Verifier {pin["version"]} (cargo plugin)\nCBMC 6.11.0':
            raise ValueError('legacy HMAC Kani tool identity differs from repository pin')
        verifier.run(['cargo', '+' + pin['execution_toolchain'], 'metadata', '--locked', '--offline',
                      '--format-version', '1', '--manifest-path', FIXTURE], env)
        for harness in HARNESS_NAMES:
            output = verifier.run([*cargo, '--manifest-path', FIXTURE, '--harness', harness], env)
            print(output)
            if 'Complete - 1 successfully verified harnesses, 0 failures, 1 total.' not in output:
                raise ValueError('legacy HMAC proof execution population missing: ' + harness)
    print('Legacy HMAC invalid-tag-width Kani: PASS; 2 proofs; no cryptographic proof claim')


if __name__ == '__main__':
    main()
