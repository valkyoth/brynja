"""Existing compiled correctness controls, not timing/native campaigns.

These two unittest drivers mix synthetic records with real portable compiler
controls. Keep their complete original selectors and label the distinction.
"""
from verification_assessment_bindings import ENV
from verification_cargo_bindings import fixture_inputs
from verification_miri_bindings import REJECT

TIMING = 'scripts/hmac/test-hmac-timing.py'
CPU = 'scripts/sha2/test-general-sha512-t-cpu.py'


def definitions():
    return {
        ('python3', TIMING): dict(fixture='hmac-timing', count=8, helpers=[
            *['scripts/hmac/' + name + '.py' for name in (
                'test-hmac-timing', 'hmac_timing', 'hmac_timing_fixture_tests',
                'check-hmac-timing', 'hmac_timing_routes', 'hmac_adapter_native',
                'hmac_faults', 'hmac_verifiers')],
            'scripts/repository/facade_cargo_environment.py'], extra=[
                'assurance/hmac-timing/Cargo.toml', 'assurance/hmac-timing/Cargo.lock',
                'assurance/hmac-faults/host_probe.rs'],
            marker='HMAC timing fixture: 12 identities; four compiled no-op/key/decision mutants rejected',
            establishes='Synthetic HMAC timing-analyser controls plus the existing compiled portable '
                        'correctness smoke test and four compiled mutants. No timing measurements, '
                        'native acceleration qualification or constant-time claim.'),
        ('python3', CPU): dict(fixture='general-sha512-t-cpu', count=5, helpers=[
            *['scripts/sha2/' + name + '.py' for name in (
                'test-general-sha512-t-cpu', 'general_sha512_t_cpu',
                'capture-general-sha512-t-native', 'general_sha512_t_policy', 'sha512_t_contract')],
            'scripts/cryptography/rust_source_contract.py'], extra=[], marker=None,
            establishes='Existing SHA-512/t compile-time feature/consumption controls and ordinary-build '
                        'candidate rejection, plus synthetic transcript/host/output-path tests. '
                        'No candidate acceleration, native capture or QEMU campaign.'),
    }


def build(rows):
    known = definitions()
    scripts = {argv[1] for argv in known}
    groups = {'control-python': {'tools': [{'program': 'python3'}]}}
    checks = []
    for row in rows:
        argv = tuple(row['command'])
        if row['phase'] != 'repository' or len(argv) < 2 or argv[0] != 'python3' or argv[1] not in scripts:
            continue
        if argv not in known or row.get('environment') or row.get('stdin'):
            raise ValueError('unreviewed correctness-control selector: ' + row['id'])
        spec = known[argv]
        key = 'control-' + row['id']
        groups[key] = dict(paths=spec['helpers'] + spec['extra'],
            tools=[{'program': p, 'toolchain': '1.99.1'} for p in ('cargo', 'rustc')],
            toml={'Cargo.toml': ['workspace.package.edition', 'workspace.package.rust-version',
                               'workspace.lints', 'workspace.resolver', 'profile.dev',
                               'profile.test', 'profile.release']})
        inputs = ['control-python', key, *fixture_inputs(groups, spec['fixture'], key + '-fixture')]
        success = {'contains': [f'\nRan {spec["count"]} tests in '], 'unique_lines': ['OK']}
        if spec['marker']:
            success['contains'].append(spec['marker'])
            success['unique_lines'].append(spec['marker'])
        checks.append(dict(component=row['families'][0], id=row['id'], name=row['label'],
            category='repository', command=list(argv), cwd='.', inputs=inputs,
            environment={**ENV, 'RUSTUP_TOOLCHAIN': '1.99.1'}, reject_environment=REJECT,
            platform='linux-x86_64', success=success, timeout_seconds=2400,
            log_bytes=16777216, establishes=spec['establishes']))
    return dict(schema=1, groups=groups, checks=checks)
