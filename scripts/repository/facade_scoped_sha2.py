"""Extracted facade acceptance for scoped named and general-t SHA-2 owners."""
import json

import facade_sha2_execution as shared
import facade_scoped_sha2_sources as sources
import facade_scoped_sha2_lifecycle as lifecycle

ROOT = shared.ROOT


def require(value, message):
    if not value:
        raise ValueError('facade scoped SHA-2: ' + message)


# Fixtures come from the reviewed repository; runtime dependencies remain extracted archives.
def install(api, consumer, roots, package):
    (consumer / 'src/bin').mkdir(parents=True, exist_ok=True)
    api.manifest(consumer, roots, package, shared.FEATURES, extra=shared.HOST)
    api.source(consumer, package, '')
    fixture = ROOT / 'assurance/sha2-hardened-execution/src'
    bodies = {
        'main.rs': sources.main((fixture / 'main.rs').read_text()),
        'named.rs': sources.named((fixture / 'named.rs').read_text()),
        'general.rs': sources.GENERAL,
        'lifecycle.rs': lifecycle.RUST,
        'acceptance.rs': shared.sources.ERROR,
        'corpus.rs': shared.sources.corpus((ROOT / 'assurance/general-sha512-t/src/corpus.rs').read_text()),
        'bin/route-probe.rs': shared.sources.PROBE,
    }
    for name, body in bodies.items():
        require('../../../crates/' not in body, 'workspace corpus path')
        (consumer / 'src' / name).write_text(shared.rewrite(body, package))
    (consumer / 'src/vectors').mkdir(exist_ok=True)
    for name in shared.VECTORS:
        (consumer / 'src/vectors' / name).write_bytes((ROOT / 'crates/brynja-hash-sha2/tests/vectors' / name).read_bytes())


def check_result(result, routes):
    revoked = (2 if routes[0] != 'Portable' else 0) + (9 if routes[1] != 'Portable' else 0)
    require(result.returncode == 0 and not result.stderr and result.stdout.splitlines() == [
        f'SHA-2 scoped execution acceptance: PASS; named=240; general=4590; lifecycle=11; revocations={revoked}',
        f'narrow={routes[0]}; wide={routes[1]}',
        'consumer-observable output/reuse checks; no private-storage qualification; independently verified: NO; FIPS validated: NO'],
        'corpus/route/lifecycle population mismatch')


def campaign(api, consumer, cargo, env, selected):
    for profile in ((), ('--release',)):
        result = api.run(cargo + ['test', '--offline', *profile, '--bin', 'facade-consumer'], consumer, env)
        require(result.stdout.count('test result: ok. 2 passed; 0 failed; 0 ignored;') == 1, 'parser regression population')
        api.run(cargo + ['build', '--offline', *profile, '--bin', 'facade-consumer'], consumer, env)
        for mode, narrow in shared.MODES:
            routes, error = shared.expected(selected, mode, narrow)
            command = [str(shared.shared.binary(env, profile)), mode] + (['narrow'] if narrow else [])
            result = api.run(command, consumer, env, success=error is None)
            if error:
                shared.check_error(result, error)
            else:
                check_result(result, routes)
        print(f'PASS: scoped SHA-2: named=240; general=4590; lifecycle=11; profile={"release" if profile else "debug"}; '
              f'static={selected["STATIC", "narrow"]}/{selected["STATIC", "wide"]}', flush=True)


def execute(api, root, roots, cargo, env, native=False):
    from facade_scoped_sha2_regressions import negatives, mutants
    consumer = root / 'scoped-sha2-consumer'
    env = dict(env, CARGO_TARGET_DIR=str(root / 'scoped-sha2-target'))
    for package in ('brynja-crypto', 'brynja'):
        install(api, consumer, roots, package)
        api.graph(json.loads(api.resolved_metadata(cargo, consumer, env, roots).stdout), shared.FEATURES, hosted=True)
        probe = cargo + ['run', '--offline', '--bin', 'route-probe']
        selected = shared.probe_result(api.run(probe, consumer, env).stdout)
        campaign(api, consumer, cargo, env, selected)
        negatives(api, consumer, package, cargo, env)
        mutants(api, consumer, roots, cargo, env)
        if native:
            accelerated = dict(env, RUSTFLAGS='-C target-feature=' + shared.native_flags(selected),
                               CARGO_TARGET_DIR=str(root / 'scoped-sha2-native-target'))
            selected = shared.probe_result(api.run(probe, consumer, accelerated).stdout)
            require(selected['STATIC', 'narrow'] == 'ready' and
                    (selected['CPU', 'wide'] != 'true' or selected['STATIC', 'wide'] == 'ready'), 'native route not compiled')
            campaign(api, consumer, cargo, accelerated, selected)
            shared.regressions.native_mutants(api, consumer, roots, cargo, accelerated, True,
                selected['STATIC', 'wide'] == 'ready',
                shared.expected(selected, 'static', selected['STATIC', 'wide'] != 'ready')[0],
                shared.check_error, lambda result, _hardened, routes: check_result(result, routes))
        print(f'PASS: {package}: scoped named/general-t SHA-2; native_requested={native}', flush=True)
