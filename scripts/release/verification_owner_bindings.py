"""Existing owner-policy, compiler and legacy graph regressions.

Read declarations only when exporting. In particular, importing the API model
would evaluate its historical source inventory; do not do that in the exporter.
Policy pins affect the policy rows, never the implementation checks they name.
"""
from pathlib import Path
import tomllib
from verification_assessment_bindings import ENV
from verification_cargo_bindings import BASE, source_inputs
from verification_checker_bindings import OWNER_HELPERS
from verification_miri_bindings import REJECT

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'security/cryptographic-api-profile-policy.toml'
PROFILE_HELPERS = [*OWNER_HELPERS, *['scripts/cryptography/' + p + '.py' for p in (
    'api_profile_model', 'api_profile_render', 'legacy_hmac_owner_tests')]]
# These are precisely the recursively inventoried code trees in the composed
# owner contracts. target, __pycache__, tracker state/report are excluded by the
# runner. They are inventory inputs, not execution of the named check scripts.
OWNER_TREES = [
    'crates/brynja-mac-hmac/src', 'scripts/hmac',
    'crates/brynja-crypto-cpu-std/src/strict_hmac',
    'crates/brynja-crypto-cpu-std/src/macos_resident/hmac',
    *['assurance/hmac-' + p for p in ('cleanup', 'engine-cleanup', 'execution-cleanup', 'hosted-cleanup')],
    'crates/brynja-legacy-hmac', 'crates/brynja-legacy-hmac-std', 'scripts/legacy-hmac',
    *['assurance/legacy-hmac-' + p for p in (
        'cleanup', 'engine-cleanup', 'execution-cleanup', 'md5-cleanup', 'hosted-cleanup', 'timing', 'policy')]]
COMPILER_PACKAGES = BASE | {'brynja-sanitization', 'sanitization', 'brynja-test-support',
    'brynja-hash-sha2', 'brynja-hash-sha3', 'brynja-mac-kmac', 'brynja-hash-tuple',
    'brynja-hash-parallel', 'brynja-legacy-md5', 'brynja-legacy-sha1',
    # Cargo resolves these declared development dependencies while compiling the
    # direct owner tests. This is not a hosted HMAC qualification campaign.
    'brynja-crypto-cpu', 'brynja-crypto-cpu-std', 'brynja-mac-hmac'}
WORKSPACE_HELPERS = ['scripts/repository/' + p + '.py' for p in (
    'validate-workspace-metadata', 'parallelhash_workspace_policy', 'strict_workspace_policy',
    'macos_workspace_policy', 'facade_workspace_policy', 'legacy_hmac_workspace_policy')]
LEGACY_HELPERS = ['scripts/legacy-hmac/' + p + '.py' for p in (
    'check-legacy-hmac-package', 'legacy_hmac_acceptance', 'legacy_hmac_bits',
    'legacy_hmac_native', 'legacy_hmac_md5_native', 'legacy_hmac_md5_lanes', 'legacy_hmac_negatives')]
LEGACY_HELPERS += ['scripts/repository/facade_cargo_environment.py', 'scripts/sha2/sha2_public_api.py',
    'scripts/md5/check-md5-differential.py', 'scripts/sha1/check-sha1-differential.py']


def profile_paths():
    policy = tomllib.loads((ROOT / PROFILE).read_text())
    paths = {PROFILE, 'standards/protocol-surfaces.json', 'docs/VERSION_PLAN.md',
             'scripts/checks.sh', *PROFILE_HELPERS, *OWNER_TREES}
    paths.update(row['path'] for row in policy['reviewed-source'])

    def targets(value):
        if isinstance(value, dict):
            for child in value.values():
                targets(child)
        elif isinstance(value, list):
            for child in value:
                targets(child)
        elif isinstance(value, str):
            name = value.partition('#')[0]
            if name.startswith(('crates/', 'scripts/', 'assurance/', 'docs/')) and ' ' not in name:
                # The existing policy's symbol/evidence paths are declarations,
                # not arbitrary discovery of the whole repository.
                if name.endswith(('.rs', '.py', '.sh', '.md', '.toml', '.lock')):
                    paths.add(name)
    for key in ('cleanup', 'current-secret-owner', 'registered-secret-owner'):
        targets(policy[key])
    return sorted(paths)


def definitions():
    return {
        ('python3', 'scripts/cryptography/check-api-profiles.py'): dict(kind='profile', markers=[
            'cryptographic API register covers 135 capabilities, 8 current and 10 registered capability owners, and 71 planned secret owners']),
        ('python3', 'scripts/cryptography/test-api-profiles.py'): dict(kind='profile', markers=[
            'Split operation contracts retain public exports and reject helper review drift',
            'cryptographic API-profile policy rejects twenty-five structural regressions and twenty-three secret-output downgrades']),
        ('python3', 'scripts/hmac/test-hmac-owner-contract.py'): dict(kind='profile', count=16),
        ('python3', 'scripts/cryptography/check-secret-owner-compiler.py'): dict(kind='compiler', markers=[
            'compiler-checked secret-owner shapes and exact MIR cleanup calls pass under Rust 1.90.0 and 1.98.1']),
        ('python3', 'scripts/legacy-hmac/test-legacy-hmac-package.py'): dict(kind='metadata', count=15),
        ('python3', 'scripts/legacy-hmac/test-legacy-hmac-hosted-package.py'): dict(kind='metadata', count=8),
    }


def build(rows):
    known = definitions()
    scripts = {argv[1] for argv in known}
    groups = {'owner-python': {'tools': [{'program': 'python3'}]}}
    checks = []
    for row in rows:
        argv = tuple(row['command'])
        if row['phase'] != 'repository' or len(argv) < 2 or argv[0] != 'python3' or argv[1] not in scripts:
            continue
        if argv not in known or row.get('environment') or row.get('stdin'):
            raise ValueError('unreviewed owner selector: ' + row['id'])
        spec = known[argv]
        key = 'owner-' + row['id']
        group = groups[key] = dict(paths=[argv[1]])
        inputs = ['owner-python', key]
        env = dict(ENV)
        if spec['kind'] == 'profile':
            group['paths'] += profile_paths()
            if argv[1].endswith('/check-api-profiles.py'):
                group['paths'] += ['security/cryptographic-api-profile-register.json',
                                   'docs/cryptographic-api-profile-register.md']
            claim = ('Existing source-policy inventory and/or synthetic owner regressions only; '
                     'no compiler or linked cryptographic campaign is executed. Historical pins '
                     'and source-inventory drift affect this policy row only.')
        elif spec['kind'] == 'compiler':
            group['paths'] += OWNER_HELPERS
            group['tools'] = [{'program': p, 'toolchain': c}
                              for c in ('1.90.0', '1.98.1') for p in ('cargo', 'rustc')]
            group['toml'] = {'Cargo.toml': ['workspace.package', 'workspace.lints', 'workspace.resolver',
                                          'profile', 'patch', 'replace']}
            inputs += source_inputs(groups, key + '-source', COMPILER_PACKAGES, 'Cargo.lock')
            claim = ('Existing direct secret-owner compiler-test discovery and exact MIR cleanup checks '
                     'under Rust 1.90.0 and 1.98.1. Discovery compiles but does not execute the listed '
                     'tests; this is not Miri, native backend qualification or composed HMAC proof.')
        else:
            group['paths'] += [*WORKSPACE_HELPERS, 'package-policy.toml', 'rust-toolchain.toml']
            group['tools'] = [{'program': p, 'toolchain': '1.99.1'} for p in ('cargo', 'rustc')]
            # The original test resolves the workspace graph, not its source
            # implementations. Retain manifests, never every crate's src/tests.
            group['patterns'] = ['crates/*/Cargo.toml']
            group['toml'] = {'Cargo.toml': ['workspace', 'patch', 'replace']}
            group['locks'] = [{'path': 'Cargo.lock', 'packages': ['sanitization']}]
            env['RUSTUP_TOOLCHAIN'] = '1.99.1'
            if argv[1].endswith('/test-legacy-hmac-package.py'):
                group['paths'] += LEGACY_HELPERS
            else:
                group['paths'] += ['scripts/legacy-hmac/legacy_hmac_hosted_acceptance.py',
                    'scripts/legacy-hmac/legacy_hmac_acceptance.py',
                    'crates/brynja-legacy-hmac-std/src/strict_execution',
                    'crates/brynja-legacy-hmac-std/src/macos_resident']
            claim = ('Existing synthetic package/graph/oracle regressions and offline Cargo metadata '
                     'inspection. Hosted wrapper parity is source inspection, not native execution. '
                     'No Rust cryptography, package build or qualification campaign is executed.')
        group['paths'] = sorted(set(group['paths']))
        success = ({'contains': [f'\nRan {spec["count"]} tests in '], 'unique_lines': ['OK']}
                   if 'count' in spec else {'contains': spec['markers'], 'unique_lines': spec['markers']})
        checks.append(dict(component=row['families'][0], id=row['id'], name=row['label'], category='repository',
            command=list(argv), cwd='.', inputs=inputs, environment=env, reject_environment=REJECT,
            success=success, timeout_seconds=3600 if spec['kind'] == 'compiler' else 300,
            log_bytes=16777216, establishes=claim))
    return dict(schema=1, groups=groups, checks=checks)
