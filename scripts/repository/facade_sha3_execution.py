"""Ordinary SHA-3/SHAKE/cSHAKE acceptance through real facade archives."""
import json
from pathlib import Path
import re

import facade_tuplehash_acceptance as selection
import facade_tuplehash_probes as probes
import facade_parallelhash_acceptance as shared
import facade_sha3_negatives as negatives

ROOT = shared.ROOT
FEATURES = ['sha3-runtime-execution']
HOST = ('host = { package="brynja-crypto-cpu-std", version="=0.1.1", '
        'default-features=false, features=["sponge-execution"] }\n')
CASES = {'execution_cases': 'nist-bit-selected.txt', 'cshake_execution_cases': 'cshake-execution.txt'}
TESTS = {'execution': 4, 'cshake_execution': 2}
MODES = ('portable', 'prefer', 'static', 'hosted')


def require(value, message):
    if not value:
        raise ValueError('facade ordinary SHA-3: ' + message)


def rewrite(text, package):
    require(package in ('brynja', 'brynja-crypto'), 'unknown facade')
    namespace = 'facade::crypto' if package == 'brynja' else 'facade'
    text = text.replace('brynja_crypto_cpu_std', 'host').replace('brynja_crypto_cpu', namespace + '::cpu')
    text = text.replace('brynja_hash_sha3', namespace + '::sha3')
    require(not re.search(r'\bbrynja_[a-z_]+\b', text), 'unexpected leaf import')
    return text


def fixture_main(text):
    for name in CASES:
        before = f'#[path = "../../../crates/brynja-hash-sha3/tests/{name}/mod.rs"]'
        require(text.count(before) == 1, 'fixture path anchor')
        text = text.replace(before, f'#[path = "{name}/mod.rs"]')
    return '#![forbid(unsafe_code)]\n' + text


def install(api, consumer, roots, package):
    (consumer / 'src/bin').mkdir(parents=True, exist_ok=True)
    api.manifest(consumer, roots, package, FEATURES, extra=HOST)
    api.source(consumer, package, '')
    main = (ROOT / 'assurance/sha3-execution/src/main.rs').read_text()
    (consumer / 'src/main.rs').write_text(rewrite(fixture_main(main), package))
    (consumer / 'src/bin/route-probe.rs').write_text(rewrite(probes.PROBE, package))
    leaf = roots['brynja-hash-sha3'] / 'tests'
    for location in ('src', 'tests'):
        base = consumer / location
        (base / 'vectors').mkdir(parents=True, exist_ok=True)
        for name, vector in CASES.items():
            (base / name).mkdir(exist_ok=True)
            require({p.name for p in (leaf / name).rglob('*') if p.is_file()} == {'mod.rs'}, 'corpus module inventory')
            (base / name / 'mod.rs').write_text(rewrite((leaf / name / 'mod.rs').read_text(), package))
            (base / 'vectors' / vector).write_bytes((leaf / 'vectors' / vector).read_bytes())
    for name in TESTS:
        text = (leaf / (name + '.rs')).read_text()
        guard = '#![cfg(feature = "static-execution")]'
        require(text.count(guard) == 1, 'consumer test guard')
        (consumer / 'tests' / (name + '.rs')).write_text(rewrite(text.replace(guard, '#![forbid(unsafe_code)]'), package))


def expected(mode, selected):
    require(mode in MODES, 'unknown mode')
    _, kernel, static, hosted = selected
    if mode == 'static':
        if static != 'ready':
            return None, 'acceptance failed: SHA-3 execution failure: Backend(' + static + ')'
        return (f'Static({kernel})', 'PortableRequested'), None
    if mode == 'hosted' and hosted != 'ready':
        return None, f'acceptance failed: hosted selection: Hosted(Unavailable({hosted}))'
    if mode in ('prefer', 'hosted') and hosted == 'ready':
        return (f'Runtime({kernel})', 'Accelerated'), None
    return ('Portable', f'PortableFallback({hosted})' if mode == 'prefer' else 'PortableRequested'), None


def check_result(result, route):
    selected, host = route
    require(result.returncode == 0 and not result.stderr and result.stdout.splitlines() == [
        f'SHA-3/SHAKE ordinary execution: PASS; cases=1084; route={selected}',
        f'cSHAKE ordinary execution: PASS; cases=628; route={selected}',
        f'hosted selection: {host}',
        'public-only; independently verified: NO; FIPS validated: NO'], 'population/route/qualification output')


def check_error(result, message):
    require(result.returncode == 1 and not result.stdout and result.stderr.strip() == message,
            'unexpected runtime rejection: ' + result.stderr[-1000:])


def campaign(api, consumer, cargo, env, selected):
    for profile in ((), ('--release',)):
        for test, count in TESTS.items():
            result = api.run(cargo + ['test', '--offline', *profile, '--test', test], consumer, env)
            require(f'test result: ok. {count} passed; 0 failed; 0 ignored;' in result.stdout, 'test population')
        api.run(cargo + ['build', '--offline', *profile, '--bin', 'facade-consumer'], consumer, env)
        for mode in MODES:
            route, error = expected(mode, selected)
            result = api.run([str(shared.binary(env, profile)), mode], consumer, env, success=error is None)
            if error:
                check_error(result, error)
            else:
                check_result(result, route)
        print(f'PASS: ordinary SHA-3: 1084 SHA-3/SHAKE and 628 cSHAKE cases; '
              f'profile={"release" if profile else "debug"}; static={selected[2]}; hosted={selected[3]}', flush=True)


# Each altered implementation must first compile, then reach the fixture's
# explicit mismatch, not a compiler failure, panic, signal or unrelated error.
MUTANTS = (
    ('route.rs', 'Inner::Portable => crate::keccak::permute(state),', 'Inner::Portable => { let _ = state; },', 1, 'SHA-3 execution acceptance mismatch'),
    ('fixed.rs', 'input.0, 0x06, 3', 'input.0, 0x1f, 5', 1, 'SHA-3 execution acceptance mismatch'),
    ('xof.rs', 'input.0, 0x1f, 5', 'input.0, 0x06, 3', 1, 'SHA-3 execution acceptance mismatch'),
    ('engine.rs', 'output.copy_from_slice(scratch);', 'let _ = output;', 1, 'SHA-3 execution acceptance mismatch'),
    ('engine.rs', '*self = candidate;', 'let _ = candidate;', 2, 'SHA-3 execution acceptance mismatch'),
    ('engine.rs', 'count.checked_add(1)', 'count.checked_add(0)', 1, 'SHA-3 execution acceptance mismatch'),
    ('engine.rs', '*last &= u8::MAX >> 8_u8.saturating_sub(valid);', 'let _ = last;', 1, 'SHA-3 execution acceptance mismatch'),
    ('cshake.rs', 'if self.customized', 'if false', 1, 'cSHAKE execution mismatch'),
    ('cshake.rs', '(0x04, 3)', '(0x06, 3)', 1, 'cSHAKE execution mismatch'),
    ('cshake.rs', 'function_name.0,', 'customization.0,', 1, 'cSHAKE execution mismatch'),
    ('cshake.rs', 'setup_bytes = state.message_bytes', 'setup_bytes = 0', 1, 'cSHAKE execution mismatch'),
)


def mutants(api, consumer, roots, cargo, env):
    for filename, before, after, count, error in MUTANTS:
        path = roots['brynja-hash-sha3'] / 'src/execution' / filename
        original = path.read_text()
        require(original.count(before) == count, 'mutation anchor')
        try:
            path.write_text(original.replace(before, after))
            api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
            check_error(api.run([str(shared.binary(env, True)), 'portable'], consumer, env, success=False),
                        'acceptance failed: ' + error)
        finally:
            path.write_text(original)
    api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
    check_result(api.run([str(shared.binary(env, True)), 'portable'], consumer, env), ('Portable', 'PortableRequested'))
    print('PASS: ordinary SHA-3: eleven compiled permutation/domain/output/state/count/masking mutants rejected', flush=True)


NATIVE_MUTANTS = (
    (('Inner::Static(session) => session.permute_keccak(raw::PublicData::new(state))?,',
      'Inner::Static(session) => { let _ = (session, state); },'),),
    (('route: self.route,', 'route: Route::Portable,'),
     ('Some(owner) => Inner::Static(owner.session()?),', 'Some(_owner) => Inner::Portable,')),
)


def native_mutants(api, consumer, roots, cargo, env, selected):
    path = roots['brynja-hash-sha3'] / 'src/execution/route.rs'
    original = path.read_text()
    for index, replacements in enumerate(NATIVE_MUTANTS):
        changed = original
        for before, after in replacements:
            require(changed.count(before) == 1, 'native mutation anchor')
            changed = changed.replace(before, after)
        try:
            path.write_text(changed)
            api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
            result = api.run([str(shared.binary(env, True)), 'static'], consumer, env, success=index == 1)
            if index == 0:
                check_error(result, 'acceptance failed: SHA-3 execution acceptance mismatch')
            else:
                # A runnable correct-output portable downgrade, not a compile
                # failure. The required-static observation must reject it.
                check_result(result, ('Portable', 'PortableRequested'))
                try:
                    check_result(result, expected('static', selected)[0])
                except ValueError:
                    pass
                else:
                    raise ValueError('required static downgrade survived')
        finally:
            path.write_text(original)
    api.run(cargo + ['build', '--offline', '--release', '--bin', 'facade-consumer'], consumer, env)
    check_result(api.run([str(shared.binary(env, True)), 'static'], consumer, env), expected('static', selected)[0])
    print('PASS: ordinary SHA-3: compiled native no-op and correct-output portable downgrade rejected', flush=True)


def execute(api, root, roots, cargo, env, native=False):
    consumer = root / 'sha3-execution-consumer'
    env = dict(env, CARGO_TARGET_DIR=str(root / 'sha3-execution-target'))
    for package in ('brynja-crypto', 'brynja'):
        install(api, consumer, roots, package)
        metadata = api.resolved_metadata(cargo, consumer, env, roots)
        api.graph(json.loads(metadata.stdout), FEATURES, hosted=True)
        probe = cargo + ['run', '--offline', '--bin', 'route-probe']
        selected = selection.probe_result(api.run(probe, consumer, env).stdout)
        campaign(api, consumer, cargo, env, selected)
        negatives.execute(api, consumer, package, cargo, env)
        mutants(api, consumer, roots, cargo, env)
        if native:
            require(selected[0] in ('avx2', 'arm-keccak'), 'native CPU bundle unavailable')
            flags = '+avx2' if selected[0] == 'avx2' else '+neon,+sha2,+sha3'
            accelerated = dict(env, RUSTFLAGS='-C target-feature=' + flags,
                               CARGO_TARGET_DIR=str(root / 'sha3-execution-native-target'))
            selected = selection.probe_result(api.run(probe, consumer, accelerated).stdout)
            require(selected[2] == 'ready', 'native static authority unavailable')
            campaign(api, consumer, cargo, accelerated, selected)
            native_mutants(api, consumer, roots, cargo, accelerated, selected)
        print(f'PASS: {package}: ordinary SHA-3/SHAKE/cSHAKE acceptance; native_requested={native}', flush=True)
