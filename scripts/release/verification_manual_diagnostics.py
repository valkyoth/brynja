"""Owner-approved manual diagnostics, not missing cryptographic checks.

Only named orchestration areas and known broad commands are classified here.
Component tests outside those areas remain unresolved, never blanket exempted.
Commands, categories and historical observations are retained unchanged.
"""
from verification_extra_sanitizers import MANUAL
from verification_matrix_bindings import VERSIONS

AREAS = {
    'scripts/release/': 'Release/evidence bookkeeping diagnostic; review the release task before manually invoking it. Not a cryptographic component obligation.',
    'scripts/repository/': 'Repository layout, packaging or documentation diagnostic; run deliberately for the relevant repository change, not to reopen every algorithm.',
    'scripts/standards/': 'Standards/reference-ledger diagnostic, not a cryptographic execution. May require local references or network preparation.',
}
BROAD_CARGO = {
    ('check', '--workspace', '--all-features'),
    ('check', '--workspace', '--no-default-features'),
    ('test', '--workspace', '--all-features'),
    ('doc', '--workspace', '--all-features', '--no-deps'),
    ('fmt', '--all', '--check'),
    ('fetch', '--locked'),
    ('clippy', '--workspace', '--all-targets', '--no-default-features', '--', '-A', 'clippy::chunks_exact_to_as_chunks', '-D', 'warnings'),
    ('clippy', '--workspace', '--all-targets', '--all-features', '--', '-A', 'clippy::chunks_exact_to_as_chunks', '-D', 'warnings'),
    ('test', '--locked', '--offline', '--manifest-path', 'assurance/crate-readmes/Cargo.toml', '--doc'),
}

# Exact commands, not a test-*-native wildcard: actual native execution checks
# (for example legacy HMAC) must remain component assessments.
NATIVE_RECORD_TESTS = {
    'scripts/md5/test-md5-execution-native.py',
    'scripts/md5/test-md5-hardened-native.py',
    'scripts/sha2/test-sha2-hardened-native.py',
    'scripts/sha3/test-keccak-batch-native.py',
    'scripts/sha3/test-keccak-hardened-native.py',
    'scripts/kmac/test-kmac-execution-native.py',
    'scripts/tuplehash/test-tuplehash-execution-native.py',
    'scripts/parallelhash/test-parallelhash-execution-native.py',
}
EVIDENCE_DIAGNOSTICS = {
    'scripts/cpu/check-cpu-evidence.py', 'scripts/cpu/test-cpu-evidence.py',
    'scripts/cpu/test-cpu-evidence-runner.py',
    'scripts/constant-time/check-constant-time-evidence.py',
    'scripts/constant-time/test-constant-time-evidence.py',
    'scripts/zeroization/check-zeroization-evidence.py',
    'scripts/zeroization/test-zeroization-evidence.py',
}

# These exact selectors inspect historical campaign selection, reviewed-input
# inventories or whole-workspace metadata. They do not execute a component's
# cryptographic tests/proofs. Keep available for maintenance of those tools,
# without importing the old campaign policy into the new runner.
ORCHESTRATION_DIAGNOSTICS = {
    ('python3', 'scripts/zeroization/miri_scope.py', '--check'),
    ('python3', 'scripts/zeroization/test-scope-inputs.py'),
    ('python3', 'scripts/zeroization/test-miri-scope.py'),
    ('python3', 'scripts/hmac/test-hmac-verification.py'),
    ('python3', 'scripts/legacy-hmac/test-legacy-hmac-verification.py'),
    ('python3', 'scripts/hmac/test-hmac-workspace.py'),
    ('python3', 'scripts/assurance/check-assurance.py'),
    ('python3', 'scripts/assurance/test-assurance.py'),
    ('scripts/assurance/check-kani.sh', '--policy-only'),
    ('python3', 'scripts/cpu/check-hosted-execution.py', '--policy-only'),
    ('python3', 'scripts/cpu/check-static-execution.py', '--policy-only'),
    ('python3', 'scripts/sha2/check-sha2-hardened-execution.py', '--policy-only'),
}

# Historical multi-family milestone rollups: these combine frozen review/pin
# validation with real fixture/package campaigns. They are NOT source-only
# diagnostics or replacements for their individual component checks.
MILESTONE_CAMPAIGNS = {
    'scripts/legacy-hash/check-legacy-acceptance.py':
        'v0.24.20 SHA-1/MD5 frozen reference, vector, package, isolation and panic-profile campaign',
    'scripts/legacy-hash/check-legacy-final-acceptance.py':
        'legacy SHA-1/MD5 final review plus fixture formatting, tests, release execution and Clippy',
    'scripts/hash/check-final-acceptance.py':
        'v0.24.11 combined SHA-2/SHA-3/SHAKE review and fixture campaign',
    'scripts/sp800185/check-portable-acceptance.py':
        'v0.24.16 combined SP 800-185 portable review and fixture campaign',
    'scripts/sp800185/check-execution-acceptance.py':
        'v0.24.17 combined SP 800-185 execution review and fixture campaign',
}


def reason(row):
    argv = row['command']
    if row['phase'] == 'asan':
        return MANUAL.get(row['id'])
    if row['phase'] == 'matrix' and len(argv) >= 2 and argv[:1] == ['cargo']:
        if argv[1].removeprefix('+') in VERSIONS and tuple(argv[2:]) == ('check', '--workspace', '--all-features'):
            return 'Whole-workspace compiler diagnostic; no component scope. Run only when that broad compatibility assessment is explicitly wanted.'
    if row['phase'] != 'repository' or not argv:
        return None
    if len(argv) == 2 and argv[0] == 'python3' and argv[1] in MILESTONE_CAMPAIGNS:
        return ('Historical aggregate milestone: ' + MILESTONE_CAMPAIGNS[argv[1]] +
                '. Explicit invocation can compile and execute real tests; this is not a cheap status scan. '
                'Retain as an owner-selected campaign, not another automatic component obligation. '
                'Individual fixture, package and policy-regression checks retain their separate bindings or unresolved status.')
    if tuple(argv) in ORCHESTRATION_DIAGNOSTICS:
        return ('Historical campaign-selection, tool-pin/review inventory or whole-workspace metadata diagnostic. '
                'No cryptographic test/proof execution is established by this selector; retain for maintenance of that tooling, '
                'not as an unfinished component assessment. Non-policy execution variants remain separate.')
    if argv[0] == 'cargo' and tuple(argv[1:]) in BROAD_CARGO:
        return 'Whole-workspace build, documentation, formatting or dependency-preparation diagnostic; not an unfinished component assessment.'
    path = argv[1] if argv[0] in ('python3', 'bash') and len(argv) > 1 else argv[0]
    if argv == ['python3', path]:
        if path in NATIVE_RECORD_TESTS:
            return ('Native-record schema/capture-orchestration regression diagnostic, not native cryptographic qualification. '
                    'Retain for changes to that evidence tooling; some commands compile synthetic libtest fixtures or mock sanitizer drivers.')
        if path in EVIDENCE_DIAGNOSTICS:
            return ('Historical evidence-ledger, bundle or CI-binding diagnostic. Retain for changes to that bookkeeping; '
                    'not a missing cryptographic execution or a requirement to refresh completed component evidence.')
    for area, explanation in AREAS.items():
        if path.startswith(area):
            return explanation
    return None
