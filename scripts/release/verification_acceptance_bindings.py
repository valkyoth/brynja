"""Four existing acceptance-regression suites, not milestone rollup campaigns."""
from pathlib import Path
import tomllib
from verification_assessment_bindings import ENV
from verification_cargo_bindings import fixture_inputs
from verification_miri_bindings import REJECT

ROOT = Path(__file__).resolve().parents[2]
GATES = ['scripts/checks.sh', 'scripts/ci/check-rust-version-matrix.sh',
    'scripts/assurance/check-bare-metal.sh', '.github/workflows/ci.yml',
    'scripts/zeroization/check-zeroization-miri.sh', 'scripts/zeroization/check-zeroization-sanitizer.sh']


def reviewed(name):
    """Read an original explicit pin inventory as data, never execute its checker."""
    return [name, *tomllib.loads((ROOT / name).read_text())['files']]


def definitions():
    return {
        ('python3', 'scripts/sp800185/test-portable-acceptance.py'): dict(
            fixture='sp800185-public-api', reviews=['scripts/sp800185/portable-acceptance-hashes.toml'],
            helpers=['scripts/sp800185/portable_acceptance.py'], extra=[], markers=[
                'SP 800-185 portable policy rejects 28 closure regressions',
                'SP 800-185 live hardened output rejects 42 executable corruptions']),
        ('python3', 'scripts/sp800185/test-execution-acceptance.py'): dict(
            fixture='sp800185-final', reviews=['scripts/sp800185/execution-acceptance-hashes.toml',
                'scripts/sp800185/frozen-portable-contract.toml'],
            helpers=['scripts/sp800185/execution_acceptance.py', 'scripts/sp800185/native_capture.py',
                'scripts/assurance/assurance_process.py', 'scripts/assurance/assurance_process_tree.py'], extra=[], markers=[
                'SP 800-185 lock binding rejects stale, missing and changed-lock regressions',
                'SP 800-185 frozen, native-lane, report and four live corruption regressions: PASS']),
        ('python3', 'scripts/legacy-hash/test-legacy-acceptance.py'): dict(
            fixture='legacy-hash-public-api/current', reviews=['scripts/legacy-hash/legacy-reviewed.toml'],
            helpers=['scripts/legacy-hash/legacy_acceptance.py', 'scripts/legacy-hash/check-panic-profiles.py',
                'scripts/legacy-hash/check-legacy-package.py'], extra=GATES, markers=[
                'Panic profiles use the current lock, preserve frozen inputs and reject three execution failures',
                'Legacy acceptance rejects 12 structural corruptions, changed real-file output, and 8 unsafe archives']),
        ('python3', 'scripts/legacy-hash/test-legacy-final-acceptance.py'): dict(
            fixture='legacy-hash-final', reviews=['scripts/legacy-hash/final-reviewed.toml',
                'scripts/legacy-hash/frozen-v02420.toml', 'scripts/legacy-hash/sha1-operational-delta.toml',
                'scripts/legacy-hash/md5-operational-delta.toml'],
            helpers=['scripts/legacy-hash/legacy_final_acceptance.py', 'scripts/legacy-hash/final_batch_mutations.py'],
            extra=['scripts/legacy-hash/native-source-snapshot.toml', *[
                f'assurance/md5-observations/v0.24.22/{lane}.json'
                for lane in ('amd-x86_64', 'intel-x86_64', 'aws-aarch64', 'apple-m2-aarch64')]], markers=[
                'Strict legacy source inventory rejects 36 missing/stale/source-drift regressions',
                'Apple legacy closure rejects 110 regressions; historical snapshot/captures unchanged',
                'MD5 batch test delta rejects omission, stale pin and source drift; historical snapshot unchanged',
                'Prefixed MD5 rejects 15 delta regressions; historical captures/snapshot unchanged',
                'Legacy enclosing review rejects four missing/stale SHA-1/MD5 delta bindings',
                'Final legacy acceptance rejects 43 frozen, source, claim, route and coverage regressions',
                'Final batch acceptance rejects no-op, partial writes and false route reports in debug/release; positive and stale-output controls pass']),
    }


def build(rows):
    known = definitions()
    scripts = {argv[1] for argv in known}
    groups = {'acceptance-python': {'tools': [{'program': 'python3'}]}}
    checks = []
    for row in rows:
        argv = tuple(row['command'])
        if row['phase'] != 'repository' or len(argv) < 2 or argv[0] != 'python3' or argv[1] not in scripts:
            continue
        if argv not in known or row.get('environment') or row.get('stdin'):
            raise ValueError('unreviewed acceptance regression selector: ' + row['id'])
        spec = known[argv]
        key = 'acceptance-' + row['id']
        paths = [argv[1], *spec['helpers'], *spec['extra']]
        paths += [p for review in spec['reviews'] for p in reviewed(review)]
        if spec['fixture'] == 'legacy-hash-final':
            snapshot = tomllib.loads((ROOT / 'scripts/legacy-hash/native-source-snapshot.toml').read_text())
            paths += [p for record in snapshot.values() for p in record['files']]
        groups[key] = dict(paths=sorted(set(paths)),
            tools=[{'program': p, 'toolchain': '1.99.1'} for p in ('cargo', 'rustc')],
            toml={'Cargo.toml': ['workspace.package', 'workspace.lints', 'workspace.resolver',
                               'profile', 'patch', 'replace']})
        inputs = ['acceptance-python', key, *fixture_inputs(groups, spec['fixture'], key + '-fixture')]
        checks.append(dict(component=row['families'][0], id=row['id'], name=row['label'], category='repository',
            command=list(argv), cwd='.', inputs=inputs, environment={**ENV, 'RUSTUP_TOOLCHAIN': '1.99.1'},
            reject_environment=REJECT, platform='linux-x86_64', timeout_seconds=3600, log_bytes=16777216,
            success=dict(contains=spec['markers'], unique_lines=spec['markers']),
            establishes='Existing acceptance-policy and compiled downstream corruption regressions. '
                        'Native capture creation and panic-profile child processes are mocked where tested; '
                        'portable fixtures and mutation controls really execute when this check is requested. '
                        'Historical review files affect this row only. No fresh native evidence, independent '
                        'review, Miri, sanitizer or full milestone campaign is claimed.'))
    return dict(schema=1, groups=groups, checks=checks)
