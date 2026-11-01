"""Scoped Cargo fixture checks from the former repository campaign.

No execution, discovery, or blanket workspace input hashing. The remaining
script-based component assessments stay unresolved until explicitly bound.
"""
from verification_cargo_bindings import cargo_inputs, FIXTURES
from verification_miri_bindings import REJECT

FIXTURE_MODES = {
    'sha1-public-api': {'test'}, 'md5-public-api': {'test'},
    'keccak-batch': {'test', 'clippy'}, 'hmac-policy': {'test'},
    'legacy-hmac-policy': {'test'}, 'acceleration-contract': {'test', 'clippy'},
    'parallelhash-std-public-api': {'test', 'clippy'},
    'sha3-execution': {'clippy'}, 'parallelhash-differential': {'test', 'clippy'},
    'kmac-public-api': {'test', 'clippy'}, 'cshake-public-api': {'test', 'clippy'},
    'tuplehash-public-api': {'test', 'clippy'}, 'parallelhash-public-api': {'test', 'clippy'},
    'sha256-batch': {'clippy'}, 'sha512-batch': {'clippy'},
    'hmac-timing': {'clippy'}, 'sha3-public-api': {'clippy'},
    'kmac-execution': {'clippy'}, 'tuplehash-execution': {'clippy'},
}


def build(rows):
    groups, checks = {}, []
    for row in rows:
        original = row['command']
        if row['phase'] != 'repository' or original[0] != 'cargo' or '--manifest-path' not in original:
            continue
        name = original[original.index('--manifest-path') + 1].removeprefix('assurance/').removesuffix('/Cargo.toml')
        if name == 'crate-readmes':
            continue  # Whole-workspace documentation diagnostic.
        if name not in FIXTURES or original[1] not in FIXTURE_MODES.get(name, set()):
            raise ValueError('unreviewed repository Cargo fixture')
        key = 'fixture-' + row['id']
        tools = ['cargo', 'rustc', 'rustdoc'] + (['clippy-driver'] if original[1] == 'clippy' else [])
        groups[key] = {'tools': [{'program': tool, 'toolchain': '1.99.1'} for tool in tools]}
        inputs = [key] + cargo_inputs(groups, original[1:], key + '-source')
        command = [original[0], '+1.99.1', *original[1:]]
        for flag in ['--locked', '--offline']:
            if flag not in command:
                command.insert(3, flag)
        success = (dict(contains=['test result: ok.'], minimum_tests=1, allow_ignored=True)
                   if original[1] == 'test' else dict(contains=['Finished', 'target(s)']))
        checks.append(dict(component=row['families'][0], id=row['id'], name=' '.join(original[1:]),
            category='repository', command=command, cwd='.', inputs=inputs,
            environment={'RUSTUP_AUTO_INSTALL': '0', 'CARGO_NET_OFFLINE': 'true'},
            platform='linux-x86_64', reject_environment=REJECT, success=success,
            timeout_seconds=1200, log_bytes=16777216,
            establishes='Existing component fixture tests or Clippy only; ignored native tests are not qualification.'))
    return dict(schema=1, groups=groups, checks=checks)
