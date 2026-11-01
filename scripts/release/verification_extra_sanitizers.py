"""Remaining scoped sanitizer selections; legacy policy campaigns stay manual."""
from verification_cargo_bindings import source_inputs, fixture_inputs
from verification_miri_bindings import BASE, CPU, HOST, SHA2, SHA3, NIGHTLY, REJECT

MANUAL = {
    'asan-2ca5d70133b3620f': 'Native SHA-NI diagnostic uses a preflight that rejects sanitizer overrides; retain its original setup rather than silently changing its leak-policy contract.',
    'asan-721a39c8b6089628': 'Combined native KMAC oracle and legacy review-policy campaign; requires deliberate native setup and review context, not a standalone memory test.',
    'asan-75789fa22376eff8': 'Combined native TupleHash oracle and legacy review-policy campaign; requires deliberate native setup and review context, not a standalone memory test.',
}
NATIVE = {
    'scripts/sha2/check-sha512-batch-asan.py': (BASE | {SHA2, CPU}, ['scripts/sha2/sha512_batch_acceptance.py'], ['Native SHA-512-family batch ASan and enforced LeakSanitizer: PASS; Avx2']),
    'scripts/sha2/check-sha256-batch-asan.py': (BASE | {SHA2, CPU}, ['scripts/sha2/sha256_batch_acceptance.py'], ['Native SHA-224/256 batch ASan and enforced LeakSanitizer: PASS; Avx2']),
    'scripts/sha3/check-keccak-batch-asan.py': (BASE | {SHA3, CPU}, ['scripts/sha3/keccak_batch_codegen.py'], ['Native Keccak batch ASan/forced LeakSanitizer: PASS; Avx2']),
    'scripts/sha3/check-keccak-hardened-asan.py': (BASE | {SHA3, CPU}, [], ['Native AVX2 hardened Keccak ASan: PASS', 'HARDENED_KECCAK_EXECUTION: X86Keccak; permutations=1024']),
    'scripts/sha1/check-sha1-hardened-asan.py': (BASE | {'brynja-legacy-sha1'}, ['scripts/sha1/hardened_native.py', 'scripts/sha1/hardened_policy.py', 'scripts/sha1/capture-sha1-cpu-native.py', 'scripts/sha1/cpu_policy.py'], ['Native SHA-1 hardened ASan: PASS; detect_leaks=1 (forced); sanitizer failures are fatal']),
    'scripts/hmac/check-hmac-asan.py': (BASE | {'brynja-mac-hmac', SHA2, SHA3, CPU, HOST}, ['scripts/hmac/hmac_verifiers.py', 'scripts/repository/facade_cargo_environment.py', 'assurance/policy.toml'], ['Portable HMAC ASan/LSan: PASS; leak detection forced; no hardware qualification claim', 'Protected HMAC public-policy ASan: PASS; protected native execution not inferred', 'Mac resident HMAC public-policy ASan: PASS; no Mac execution/residency inferred']),
    'scripts/legacy-hmac/check-legacy-hmac-asan.py': (BASE | {'brynja-legacy-hmac', 'brynja-legacy-hmac-std', 'brynja-legacy-md5', 'brynja-legacy-sha1', SHA2, SHA3, CPU, HOST}, ['scripts/legacy-hmac/legacy_hmac_verifiers.py', 'scripts/hmac/hmac_verifiers.py', 'scripts/repository/facade_cargo_environment.py', 'assurance/policy.toml'], ['Legacy HMAC portable/public-metadata ASan/LSan: PASS; no native hardware/residency claim']),
}


def build(rows, already):
    groups = {
        'extra-asan-tools': {'tools': [{'program': p, 'toolchain': NIGHTLY} for p in ('cargo', 'rustc')] + [{'program': 'python3'}]},
        'extra-asan-workspace': {'toml': {'Cargo.toml': ['workspace.package.edition', 'workspace.package.rust-version', 'workspace.lints', 'workspace.resolver', 'profile.dev', 'profile.test', 'profile.release']}},
    }
    checks = []
    for row in rows:
        if row['phase'] != 'asan' or row['id'] in already or row['id'] in MANUAL:
            continue
        command = row['command'].copy()
        key = 'extra-' + row['id']
        inputs = ['extra-asan-tools', 'extra-asan-workspace']
        env = {'RUSTUP_AUTO_INSTALL': '0', 'CARGO_NET_OFFLINE': 'true',
               'ASAN_OPTIONS': 'detect_leaks=1:halt_on_error=1:exitcode=1', 'LSAN_OPTIONS': 'exitcode=23'}
        if command[0] == 'python3':
            if len(command) != 2 or command[1] not in NATIVE:
                raise ValueError('unreviewed native sanitizer command')
            selected, helpers, markers = NATIVE[command[1]]
            groups[key] = {'paths': [command[1], *helpers]}
            inputs += [key] + source_inputs(groups, key, selected, 'Cargo.lock')
            success = {'contains': markers, 'unique_lines': markers}
        elif command[0] == 'cargo' and command[1] == '+' + NIGHTLY:
            env['RUSTFLAGS'] = '-Zsanitizer=address'
            env['CARGO_ENCODED_RUSTFLAGS'] = ''
            for flag in ['--locked', '--offline']:
                if flag not in command:
                    command.insert(3, flag)
            selected = set()
            if '--manifest-path' in command:
                manifest = command[command.index('--manifest-path') + 1]
                name = manifest.removeprefix('assurance/').removesuffix('/Cargo.toml')
                if name not in ('general-sha512-t', 'legacy-hash-final', 'legacy-hash-public-api/current'):
                    raise ValueError('unreviewed sanitizer fixture')
                inputs += fixture_inputs(groups, name, key)
            else:
                packages = {command[i + 1] for i, arg in enumerate(command[:-1]) if arg == '-p'}
                features = command[command.index('--features') + 1] if '--features' in command else 'ALL'
                if packages == {CPU} and features in ('static-execution', 'runtime-execution'):
                    selected = {CPU}
                elif packages == {HOST} and features in ('runtime-execution', 'sponge-execution'):
                    selected = BASE | {CPU, HOST, SHA2} | ({SHA3} if features == 'sponge-execution' else set())
                elif packages == {CPU, SHA2} and features == 'ALL':
                    selected = BASE | {CPU, SHA2}
                else:
                    raise ValueError('unreviewed shared sanitizer package/features')
                inputs += source_inputs(groups, key, selected, 'Cargo.lock')
            success = dict(contains=['test result: ok.'], minimum_tests=1)
            if command[2] == 'run':
                marker = 'General SHA-512/t performance profile: PASS; rows=50; scalar-only'
                success = dict(contains=[marker], unique_lines=[marker])
        else:
            raise ValueError('unreviewed sanitizer executable')
        if selected:
            groups[key + '-tests'] = {'optional_paths': ['crates/' + p + '/tests' for p in sorted(selected)]}
            inputs.append(key + '-tests')
        component = 'static_cpu' if 'static_cpu' in row['families'] else row['families'][0]
        checks.append(dict(component=component, id=row['id'], name=row['label'], category='asan',
            establishes='Existing sanitizer selection only. Native claims require the original guarded harness markers; public-policy tests do not establish residency.',
            command=command, cwd='.', inputs=inputs, platform='linux-x86_64', environment=env,
            reject_environment=REJECT + ['ASAN_OPTIONS', 'LSAN_OPTIONS'], success=success, timeout_seconds=1800, log_bytes=16777216))
    return dict(schema=1, groups=groups, checks=checks)
