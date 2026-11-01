"""Explicit standalone source contracts and differential comparisons.

Only reviewed commands below are selected. Registration never imports or runs
their implementation; no old release campaign or reviewed-input gate is added.
"""
from verification_cargo_bindings import cargo_inputs, fixture_inputs, source_inputs
from verification_miri_bindings import BASE, SHA2, SHA3, REJECT

CORE = 'crates/brynja-core/src/'
FOUNDATIONS = {
    'clock-contract': ('clock_contract_policy', ['clock.rs', 'clock'],
        ['crates/brynja-test-support/src/deterministic_clock.rs'],
        'typed wall and monotonic clock source policy: PASS',
        'clock policy rejects nine type, state, isolation, low-level, size, and hash regressions'),
    'entropy-contract': ('entropy_contract_policy', ['entropy.rs', 'secure_random.rs'],
        ['crates/brynja-test-support/src/deterministic_random.rs'],
        'entropy and secure-random source policy: PASS',
        'entropy policy rejects nine trait, state, teardown, isolation, low-level, and hash regressions'),
    'provider-contract': ('provider_contract_policy', ['provider.rs', 'provider_capability.rs', 'provider_contract.rs', 'provider_request.rs'], [],
        'provider capability and opaque-handle source policy: PASS',
        'provider policy rejects thirteen capability, fallback, mutability, duty, identity, result-forgery, work, dependency-inversion, token, and hash regressions'),
    'pending-contract': ('pending_contract_policy', ['pending.rs', 'pending', 'provider_request.rs'], [],
        'pending operation and accelerator lifecycle source policy: PASS',
        'pending policy rejects twenty-one admission, identity, work, begin/unwind, cleanup, low-level, size, and hash regressions'),
    'fips-architecture': ('fips_architecture_policy', ['fips.rs', 'fips_build.rs', 'fips_service.rs', 'fips_session.rs'], [],
        'FIPS-aware provider architecture source policy: PASS',
        'FIPS policy rejects twenty-four architecture, isolation, lifecycle, indicator, size, unsafe, and hash regressions'),
    'security-event': ('security_event_policy', ['security_event.rs', 'security_event', 'lib.rs'], [],
        'bounded observational security-event source policy: PASS',
        'security-event policy rejects twenty-two authority, payload, queue, timestamp, boundary, size, and hash regressions'),
    'security-outcome': ('security_outcome_policy', ['security_outcome.rs', 'security_outcome'], [],
        'mandatory security-outcome authority source policy: PASS',
        'security-outcome policy rejects twenty-nine domain, authority, evidence, disposition, commit, abandonment, self-test, destruction, low-level, size, and hash regressions'),
}

KECCAK = ['scripts/sha3/check-sha3-bit-differential.py']
CSHAKE = KECCAK + ['scripts/sha3/check-cshake-differential.py']
# fixture, oracle dependencies, exact existing completion line.
DIFFERENTIAL = {
    'scripts/sha3/check-sha3-differential.py': ('sha3-differential', [],
        'all six FIPS 202 functions match hashlib across 328 messages; three oversized XOF requests and two aggregate campaigns fail cleanly'),
    'scripts/md5/check-md5-differential.py': ('md5-public-api', [],
        'MD5 independent bit differential: 1136 cases; 10 malformed requests rejected'),
    'scripts/sha1/check-sha1-differential.py': ('sha1-public-api', [],
        'SHA-1 independent bit differential: 1135 cases; 10 malformed requests rejected'),
    'scripts/sha2/check-sha2-bit-differential.py': ('sha2-bit-differential', [],
        'SHA-2 arbitrary-bit differential oracle: PASS (1008 results, 6 malformed requests rejected)'),
    'scripts/sha3/check-sha3-bit-differential.py': ('sha3-bit-differential', ['crates/brynja-hash-sha3/tests/vectors/nist-bit-selected.txt'],
        '76 NIST and 440 independent bit cases passed; malformed inputs reject cleanly'),
    'scripts/sha3/check-cshake-differential.py': ('cshake-differential', KECCAK,
        'cSHAKE differential oracle: PASS (480 arbitrary-bit results)'),
    'scripts/kmac/check-kmac-differential.py': ('kmac-differential', CSHAKE,
        'KMAC/KMACXOF differential oracle: PASS (272 arbitrary-bit results)'),
    'scripts/tuplehash/check-tuplehash-differential.py': ('tuplehash-differential', CSHAKE,
        'TupleHash/TupleHashXOF differential oracle: PASS (256 arbitrary-bit results)'),
    'scripts/parallelhash/check-parallelhash-differential.py': ('parallelhash-differential', CSHAKE,
        'ParallelHash/ParallelHashXOF differential oracle: PASS (256 arbitrary-bit results)'),
}


def boundary_definitions():
    """Source-only policies: no compiler closure or native execution implied."""
    definitions = {}
    for directory, name, policy, package, sources, extra, check_marker, test_marker in [
        ('pki', 'der-reader', 'der_reader_policy', 'brynja-pki',
         ['lib.rs', 'der.rs', 'der/error.rs', 'der/limits.rs', 'der/reader.rs', 'der/tag.rs'], [],
         'bounded DER-reader source policy: PASS',
         'DER-reader policy rejects thirty-three allocation, recursion, canonicality, bound, package, size, and hash regressions'),
        ('pki', 'asn1-values', 'asn1_value_policy', 'brynja-pki',
         ['lib.rs', 'asn1.rs', *['asn1/' + name + '.rs' for name in
          ('bit_string', 'constructed', 'error', 'integer', 'object_identifier', 'string', 'time', 'value')]],
         ['crates/brynja-pki/tests/asn1.rs'],
         'canonical ASN.1 value source policy: PASS',
         'ASN.1 value policy rejects forty allocation, canonicality, overflow, ordering, package, size, test, and hash regressions'),
        ('protocols', 'record-framing', 'record_framing_policy', 'brynja-protocol',
         ['lib.rs', 'tls.rs', *['tls/' + name + '.rs' for name in
          ('content_type', 'error', 'record', 'dtls', 'dtls12_ciphertext')]], [],
         'TLS and DTLS record-framing source policy: PASS',
         'record-framing policy rejects thirty profile, cleartext, heartbeat, bound, package, size, and hash regressions'),
    ]:
        manifest = f'crates/{package}/Cargo.toml'
        fields = ['packages.' + package]
        if package == 'brynja-protocol':
            fields += ['packages.' + engine + '.required' for engine in ('brynja-tls12', 'brynja-tls13', 'brynja-dtls')]
        for mode, marker in [('check', check_marker), ('test', test_marker)]:
            paths = [f'scripts/{directory}/{policy}.py', *[f'crates/{package}/src/{s}' for s in sources], *extra]
            group = {'paths': paths}
            if mode == 'test':
                # These existing mutation scripts replace literal TOML text.
                # Formatting/anchor changes can affect them even if parsed
                # values match; do not claim semantic-only reuse for the tests.
                paths += [manifest, 'package-policy.toml']
            else:
                group['toml'] = {manifest: ['dependencies', 'features'], 'package-policy.toml': fields}
            definitions[f'scripts/{directory}/{mode}-{name}.py'] = (group, marker, None)
    for mode, marker in [
        ('check', 'CPU backend capability and dispatch source policy: PASS'),
        ('test', 'backend policy rejects twenty-three execution, evidence, instance, CPU-context, thread, generation, quarantine, operation, approval, registry, and hash regressions'),
    ]:
        paths = ['scripts/cpu/backend_contract_policy.py', *[CORE + name + '.rs' for name in
                 ('backend', 'backend_instance', 'backend_session', 'backend_kat', 'backend_dispatch',
                  'backend_execution', 'backend_session_tests', 'backend_security_tests')]]
        definitions[f'scripts/cpu/{mode}-backend-contract.py'] = ({'paths': paths}, marker, None)
    return definitions


def definitions():
    result = boundary_definitions()
    for name, (policy, sources, extra, check_marker, test_marker) in FOUNDATIONS.items():
        for mode, marker in [('check', check_marker), ('test', test_marker)]:
            script = f'scripts/foundations/{mode}-{name}.py'
            paths = [CORE + path for path in sources] + extra + ['scripts/foundations/' + policy + '.py']
            group = {'paths': paths}
            if name in ('clock-contract', 'entropy-contract'):
                # Only these policy fields are read. Mutation fixtures need raw
                # TOML text as well; retain that narrower executable distinction.
                if mode == 'test':
                    paths += ['package-policy.toml', 'crates/brynja-test-support/Cargo.toml']
                else:
                    group['toml'] = {'package-policy.toml': ['packages.brynja-test-support'],
                        'crates/brynja-test-support/Cargo.toml': ['package.publish', 'dependencies']}
            result[script] = (group, marker, None)
    for mode, marker in [
        ('check', 'constant-time foundation source policy: PASS'),
        ('test', 'constant-time policy rejects fourteen control, width, trait, barrier, coverage, and hash regressions'),
    ]:
        result[f'scripts/constant-time/{mode}-constant-time.py'] = (
            {'paths': [CORE + 'constant_time', 'scripts/constant-time/constant_time_policy.py']}, marker, None)
    result['scripts/constant-time/test-constant-time-codegen.py'] = (
        {'paths': ['scripts/constant-time/constant_time_codegen.py']},
        'constant-time codegen rejects all 18 RISC-V conditional forms and ten focused branch/address regressions', None)
    result['scripts/md5/test-md5-execution-asan.py'] = (
        {'paths': ['scripts/md5/check-md5-execution-asan.py']},
        'MD5 ASan/LSan enforcement: 8 clean/hostile environment and fatal child cases passed', None)
    for script, (fixture, paths, marker) in DIFFERENTIAL.items():
        result[script] = ({'paths': list(paths)}, marker, ['--manifest-path', 'assurance/' + fixture + '/Cargo.toml'])
    result['scripts/hmac/check-hmac-general-differential.py'] = (
        {'paths': ['scripts/sha2/sha512_t_digest_oracle.py', 'scripts/sha2/sha512_t_iv_oracle.py']},
        'HMAC_GENERAL_ORACLE: 6128 cases; 383 parameters; exact-bit inner and outer messages',
        ['-p', 'brynja-mac-hmac'])
    result['scripts/hmac/check-hmac-differential.py'] = (
        {'paths': []}, 'HMAC_ORACLE: 1100 cases; 10 algorithms; 4 partitions and truncation per case',
        ['-p', 'brynja-mac-hmac'])
    result['scripts/hmac/check-hmac-bit-differential.py'] = (
        {'paths': ['scripts/sha2/check-sha2-bit-differential.py', 'scripts/sha3/check-sha3-bit-differential.py']},
        'HMAC_BIT_ORACLE: 1040 cases; 10 algorithms; bit finalization and truncated verification',
        ['-p', 'brynja-mac-hmac'])
    return result


def build(rows):
    known = definitions()
    groups = {'script-python': {'tools': [{'program': 'python3'}]},
              'script-rust': {'tools': [{'program': p, 'toolchain': '1.99.1'} for p in ('cargo', 'rustc')],
                  'toml': {'Cargo.toml': ['workspace.package.edition', 'workspace.package.rust-version',
                                        'workspace.lints', 'workspace.resolver', 'profile.dev', 'profile.test', 'profile.release']}}}
    checks = []
    for row in rows:
        argv = row['command']
        if row['phase'] != 'repository' or len(argv) < 2 or argv[0] != 'python3' or argv[1] not in known:
            continue
        if len(argv) != 2 or row.get('environment') or row.get('stdin'):
            raise ValueError('unreviewed script arguments/environment: ' + row['id'])
        group, marker, cargo = known[argv[1]]
        key = 'script-' + row['id']
        groups[key] = {**group, 'paths': [argv[1], *group.get('paths', [])]}
        inputs = ['script-python', key]
        env = {'PYTHONOPTIMIZE': '0', 'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
        if cargo:
            if argv[1] in ('scripts/hmac/check-hmac-general-differential.py',
                           'scripts/hmac/check-hmac-differential.py', 'scripts/hmac/check-hmac-bit-differential.py'):
                inputs += ['script-rust'] + source_inputs(groups, key + '-source',
                    BASE | {SHA2, SHA3, 'brynja-mac-hmac'}, 'Cargo.lock')
                harness = {'check-hmac-general-differential.py': 'general_differential',
                           'check-hmac-differential.py': 'differential',
                           'check-hmac-bit-differential.py': 'bit_differential'}[argv[1].rsplit('/', 1)[1]]
                groups[key]['paths'] += [f'crates/brynja-mac-hmac/tests/{harness}.rs',
                                         'crates/brynja-mac-hmac/tests/support']
                if harness == 'bit_differential':
                    groups[key]['paths'].append('crates/brynja-mac-hmac/tests/bit_support')
            elif argv[1] == 'scripts/parallelhash/check-parallelhash-differential.py':
                # This command does not enable the fixture's optional hosted/
                # CPU execution dependencies, unlike its existing Clippy check.
                inputs += ['script-rust'] + fixture_inputs(groups, 'parallelhash-differential',
                    key + '-source', selected_override=BASE | {SHA3, 'brynja-hash-parallel'})
            else:
                inputs += ['script-rust'] + cargo_inputs(groups, cargo, key + '-source')
            env.update(RUSTUP_TOOLCHAIN='1.99.1', RUSTUP_AUTO_INSTALL='0', CARGO_NET_OFFLINE='true')
        success = dict(contains=[marker], unique_lines=[marker])
        if argv[1] in ('scripts/hmac/check-hmac-general-differential.py',
                       'scripts/hmac/check-hmac-differential.py', 'scripts/hmac/check-hmac-bit-differential.py'):
            success.update(minimum_tests=1, exact_tests=1)
        checks.append(dict(component=row['families'][0], id=row['id'], name=row['label'],
            category='repository', command=argv.copy(), cwd='.', inputs=inputs, environment=env,
            reject_environment=REJECT, success=success, timeout_seconds=1800 if cargo else 120,
            log_bytes=16777216, establishes='Existing standalone differential comparison.' if cargo else
            'Existing source contract or checker regression only; not native execution, timing qualification or a proof.'))
    return dict(schema=1, groups=groups, checks=checks)
