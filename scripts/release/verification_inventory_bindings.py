"""HMAC declaration inventory bindings, not execution of the linked campaigns.

Explicit inputs mirror the existing inventory's reads. Linked check files are
only checked for existence by that inventory; conservatively tracking their
contents affects these two rows, never the linked checks' execution records.
"""
from verification_assessment_bindings import ENV
from verification_miri_bindings import REJECT

LEAF = 'crates/brynja-mac-hmac/src/'
HOST = 'crates/brynja-crypto-cpu-std/src/'
SOURCES = [LEAF + name for name in (
    'lib.rs', 'bits.rs', 'algorithms.rs', 'scratch.rs', 'engine.rs', 'output.rs',
    'execution/mod.rs', 'execution/retained.rs')]
SOURCES += [HOST + directory + '/' + name
            for directory in ('strict_hmac', 'macos_resident/hmac')
            for name in ('mod.rs', 'compiled.rs')]
MANIFESTS = ['crates/' + name + '/Cargo.toml' for name in
             ('brynja-mac-hmac', 'brynja-crypto-cpu-std', 'brynja-strict')]
LINKS = ['scripts/hmac/' + name for name in (
    'check-hmac-hosted-cleanup.py', 'check-hmac-differential.py',
    'check-hmac-bit-differential.py', 'check-hmac-general-differential.py',
    'hmac_faults.py', 'check-hmac-package.py', 'check-hmac-protected.py',
    'check-hmac-facade.py', 'check-hmac-strict.py', 'test-hmac-verification.py',
    'check-hmac-cleanup.py', 'check-hmac-engine-cleanup.py',
    'check-hmac-execution-cleanup.py', 'check-hmac-static-cleanup.py',
    'check-hmac-hosted-native.py', 'check-hmac-launch.py',
    'check-hmac-x86-sha512.py', 'check-hmac-timing.py')]
LINKS += ['crates/brynja-mac-hmac/tests/vectors.rs',
          'crates/brynja-mac-hmac/tests/lifecycle.rs',
          'assurance/hmac-faults/adapter_tests.rs',
          'assurance/hmac-faults/execution_cases.rs']
HELPERS = ['scripts/hmac/hmac_inventory.py',
           'scripts/cryptography/rust_source_contract.py',
           'scripts/cryptography/hmac_owner_contract.py',
           'scripts/cryptography/legacy_hmac_owner_contract.py']
MARKER = 'HMAC development inventory: PASS; 14 owners/outputs, 10 profiles; qualification PENDING'


def definitions():
    return {('python3', 'scripts/hmac/' + name): mode for name, mode in (
        ('check-hmac-inventory.py', 'check'), ('test-hmac-inventory.py', 'test'))}


def build(rows):
    known = definitions()
    scripts = {argv[1] for argv in known}
    groups = {'inventory-python': {'tools': [{'program': 'python3'}]}}
    checks = []
    for row in rows:
        argv = tuple(row['command'])
        if row['phase'] != 'repository' or len(argv) < 2 or argv[0] != 'python3' or argv[1] not in scripts:
            continue
        if argv not in known or row.get('environment') or row.get('stdin'):
            raise ValueError('unreviewed inventory selector: ' + row['id'])
        mode = known[argv]
        key = 'inventory-' + row['id']
        paths = [argv[1], *SOURCES, *LINKS, *HELPERS,
                 'standards/protocol-surfaces.json', 'security/cryptographic-api-profile-policy.toml']
        groups[key] = {'paths': sorted(set(paths))}
        if mode == 'check':
            groups[key]['paths'].append('docs/hmac-development-inventory.md')
            groups[key]['toml'] = {name: ['features'] for name in MANIFESTS}
            success = {'contains': [MARKER], 'unique_lines': [MARKER]}
        else:
            # The mutation test performs literal text replacements, so its
            # manifest spelling/format is part of the fixture assumptions.
            groups[key]['paths'] += MANIFESTS
            success = {'contains': ['\nRan 11 tests in '], 'unique_lines': ['OK']}
        checks.append(dict(component=row['families'][0], id=row['id'], name=row['label'],
            category='repository', command=list(argv), cwd='.', inputs=['inventory-python', key],
            environment=dict(ENV), reject_environment=REJECT, success=success,
            timeout_seconds=300, log_bytes=16777216,
            establishes='Existing HMAC owner/profile/source-document inventory' +
                (' and eleven mutation tests.' if mode == 'test' else ' and generated-document comparison.') +
                ' No linked campaign, compiler, native backend or cryptography is executed. '
                'Inventory review text affects this row only, not prior execution/proof results.'))
    return dict(schema=1, groups=groups, checks=checks)
