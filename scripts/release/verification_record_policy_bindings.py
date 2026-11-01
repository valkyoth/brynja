"""Explicit record/source-policy checks, never global freshness requirements.

Some old policies compare raw manifests/locks or gate text. Track those bytes
only for these policies, not for the cryptographic executions they describe.
"""
from verification_assessment_bindings import ENV
from verification_miri_bindings import REJECT
from pathlib import Path
import tomllib


def definitions():
    result = {}
    for mode in ('check', 'test'):
        path = f'scripts/sanitization/{mode}-sanitization-admission.py'
        markers = (['sanitization 2.1.1 admission record, isolation: PASS'] if mode == 'check' else [
            'sanitization admission rejects seventeen identity, graph, error-boundary, release-history, feature, FIPS, and drift regressions',
            'Adapter release history: four accepted states and eighteen identity/publication/admission regressions passed'])
        result[('python3', path)] = dict(paths=[
            'scripts/sanitization/sanitization_admission.py', 'Cargo.toml', 'Cargo.lock', 'release-crates.toml',
            'assurance/sanitization-admission/Cargo.toml', 'assurance/sanitization-admission/Cargo.lock',
            'assurance/sanitization-admission/src/lib.rs', 'docs/sanitization-admission-review.md',
            'security/dependency-admissions/sanitization-2.1.1.toml'],
            patterns=['crates/*/Cargo.toml'], markers=markers)
    for stem, family in [('sha256', 'sha2'), ('sha512', 'sha2'), ('keccak', 'sha3')]:
        path = f'scripts/{family}/test-{stem}-batch' + ('-policy' if stem == 'keccak' else '') + '.py'
        crates = ['brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu', 'brynja-hash-sha2', 'brynja-crypto-cpu-std']
        if stem == 'keccak':
            crates.append('brynja-hash-sha3')
        paths = ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', f'docs/{stem}-batch-execution.md',
            'scripts/checks.sh', 'scripts/zeroization/check-zeroization-miri.sh',
            'scripts/zeroization/check-zeroization-sanitizer.sh', 'scripts/assurance/check-kani.sh',
            'scripts/sha2/check-sha2-execution.py', 'scripts/sha2/sha2_execution_faults.py',
            f'scripts/{family}/{stem}-batch-reviewed.json', f'assurance/{stem}-batch']
        paths += [f'crates/{crate}/{name}' for crate in crates for name in ('src', 'Cargo.toml', 'README.md')]
        if stem == 'keccak':
            paths += ['scripts/zeroization/miri_scope.py', 'scripts/sha3/check-sha3-bit-differential.py',
                'scripts/sha3/check-cshake-differential.py', 'crates/brynja-hash-sha3/tests/vectors/nist-bit-selected.txt']
            markers = ['Keccak batch policy rejects 42 hash/contract/command/default/removal/symlink/new-source regressions']
        else:
            paths += ['scripts/sha2/check-sha2-bit-differential.py',
                'crates/brynja-hash-sha2/tests/' + ('batch.rs' if stem == 'sha256' else 'batch512.rs')]
            markers = ['Nine batch hash/removal/symlink/new-source regressions rejected',
                'Eight native batch sanitizer clean/hostile-environment/failure cases passed']
            if stem == 'sha512':
                paths += ['crates/brynja-hash-sha2/tests/batch512_general',
                    'scripts/sha2/sha512_t_digest_oracle.py', 'scripts/sha2/sha512_t_iv_oracle.py']
                markers.append('11 public-data/platform-import/panic-profile documentation regressions rejected')
        result[('python3', path)] = dict(paths=paths,
            patterns=[f'scripts/{family}/*{stem}*batch*.py'], markers=markers)
    # This selector only mutates the historical claim/pin checker; the separate
    # check-final-acceptance command executes the aggregate milestone campaign.
    paths = ['assurance/hash-final-acceptance/' + p for p in ('Cargo.toml', 'Cargo.lock', 'src/lib.rs', 'src/main.rs')]
    paths += [f'assurance/{name}/src/lib.rs' for name in ('sha2-public-api', 'sha3-public-api', 'sha3-hardened-api')]
    paths += [f'scripts/{family}/check-{family}-{name}' for family in ('sha2', 'sha3')
              for name in ('public-api.py', 'hardened.py', 'bit-differential.py', 'hardened-codegen.sh')]
    paths += ['scripts/checks.sh', 'scripts/ci/check-rust-version-matrix.sh', 'scripts/assurance/check-bare-metal.sh',
        '.github/workflows/ci.yml', 'README.md', 'crates/brynja/README.md', 'crates/brynja-hash-sha2/README.md',
        'crates/brynja-hash-sha3/README.md', 'docs/VERIFICATION_STATUS.md', 'docs/current-status.md',
        'docs/RELEASE_PLAN.md', 'release-notes/RELEASE_NOTES_0.24.11.md', 'requirements/domains/cryptography.toml',
        'standards/surface-policy.json', 'security/cryptographic-api-profile-policy.toml',
        'crates/brynja-crypto-cpu/src/lib.rs', 'scripts/hash/final_acceptance.py', 'scripts/hash/final-acceptance-hashes.toml']
    result[('python3', 'scripts/hash/test-final-acceptance.py')] = dict(paths=paths, patterns=[],
        markers=['combined hash closure rejects 11 claim and evidence regressions'])
    boundary = 'security/cpu-acceleration-boundary.toml'
    declared = tomllib.loads((Path(__file__).resolve().parents[2] / boundary).read_text())
    for mode in ('check', 'test'):
        result[('python3', f'scripts/cpu/{mode}-cpu-boundary.py')] = dict(
            paths=['Cargo.toml', 'package-policy.toml', boundary, 'scripts/checks.sh', '.github/workflows/ci.yml',
                'scripts/cpu/cpu_boundary_policy.py', 'scripts/cpu/cpu_boundary_backends.py',
                'scripts/cpu/cpu_boundary_windows.py', 'scripts/cpu/cpu_facade_policy.py',
                'crates/brynja-crypto-cpu/src', 'crates/brynja-crypto-cpu-std/src',
                *[r['path'] for r in declared['evidence']]],
            patterns=['crates/*/Cargo.toml'],
            optional_paths=['crates/brynja-crypto-cpu/build.rs', 'crates/brynja-crypto-cpu-std/build.rs'],
            markers=['Original CPU candidate dispatch: seven kernels, zero admissions; opt-in raw static authority is checked separately']
            if mode == 'check' else [
                'Windows CPU inventory rejects six source, membership and qualification regressions',
                'CPU workspace pin rejects five default-feature/path/version/activation regressions',
                'CPU boundary rejects existing and protected-resource package/source regressions'])
    return result


def build(rows):
    known = definitions()
    scripts = {argv[1] for argv in known}
    groups = {'record-policy-python': {'tools': [{'program': 'python3'}]}}
    checks = []
    for row in rows:
        argv = tuple(row['command'])
        if row['phase'] != 'repository' or len(argv) < 2 or argv[0] != 'python3' or argv[1] not in scripts:
            continue
        if argv not in known or row.get('environment') or row.get('stdin'):
            raise ValueError('unreviewed record-policy selector: ' + row['id'])
        spec = known[argv]
        key = 'record-policy-' + row['id']
        groups[key] = dict(paths=[argv[1], *spec['paths']], patterns=spec['patterns'])
        if 'optional_paths' in spec:
            groups[key]['optional_paths'] = spec['optional_paths']
        checks.append(dict(component=row['families'][0], id=row['id'], name=row['label'], category='repository',
            command=list(argv), cwd='.', inputs=['record-policy-python', key], environment=dict(ENV),
            reject_environment=REJECT, timeout_seconds=300, log_bytes=16777216,
            success={'contains': spec['markers'], 'unique_lines': spec['markers']},
            establishes='Existing offline record/source-policy or checker mutations only. Sanitizer commands '
                        'in the SHA-2 batch regression suites are mocked. No compiler, crypto, native, sanitizer '
                        'or proof execution. Raw lock/manifest and historical gate/review inputs affect only '
                        'this policy row, not previous implementation results.'))
    return dict(schema=1, groups=groups, checks=checks)
