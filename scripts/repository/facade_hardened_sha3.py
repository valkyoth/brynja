"""Hardened SHA-3/SHAKE/cSHAKE facade acceptance without skip-as-pass lanes."""
import json

import facade_sha3_execution as ordinary
import facade_tuplehash_acceptance as shared
import facade_hardened_sha3_sources as sources
import facade_hardened_sha3_scoped as scoped

ROOT = shared.ROOT
FEATURES = ['sha3-runtime-execution', 'sha3-hardened-execution']
TESTS = {'owned': 6, 'corpus': 2, 'scoped': 3}
MARKERS = {
    'owned': 'Hardened Keccak operation properties: PASS; seed=17037; cases=64; identities=4',
    'corpus': 'HARDENED_SHA3_CORPUS: nist=76; cshake=628; owned/scoped; public/secret',
}


def require(value, message):
    if not value:
        raise ValueError('facade hardened SHA-3: ' + message)


def install(api, consumer, roots, package):
    (consumer / 'src/bin').mkdir(parents=True, exist_ok=True)
    api.manifest(consumer, roots, package, FEATURES, extra=shared.HOST)
    api.source(consumer, package, '')
    (consumer / 'src/bin/route-probe.rs').write_text(ordinary.rewrite(shared.probes.PROBE, package))
    tests = consumer / 'tests'
    (tests / 'keccak_properties').mkdir(parents=True, exist_ok=True)
    (tests / 'vectors').mkdir(exist_ok=True)
    leaf = roots['brynja-hash-sha3'] / 'tests'
    text = sources.owned((leaf / 'hardened_execution.rs').read_text())
    (tests / 'owned.rs').write_text(ordinary.rewrite(text, package))
    (tests / 'keccak_properties/mod.rs').write_text(ordinary.rewrite((leaf / 'keccak_properties/mod.rs').read_text(), package))
    for name, body in (('corpus', sources.CORPUS), ('scoped', scoped.RUST)):
        (tests / (name + '.rs')).write_text(ordinary.rewrite('#![forbid(unsafe_code)]\n' + sources.COMMON + body, package))
    for name in ordinary.CASES.values():
        (tests / 'vectors' / name).write_bytes((leaf / 'vectors' / name).read_bytes())


def check_result(result, name, available):
    count = TESTS[name] if available else 1
    require(result.returncode == 0 and
            result.stdout.count(f'test result: ok. {count} passed; 0 failed; 0 ignored;') == 1,
            'runtime population: ' + name)
    marker = MARKERS.get(name)
    if marker:
        require(result.stdout.splitlines().count(marker) == int(available), 'executed corpus/property marker: ' + name)


def campaign(api, consumer, cargo, env, selected):
    for mode, status in (('static', selected[2]), ('hosted', selected[3])):
        expected = status if mode == 'static' or status == 'ready' else f'Unavailable({status})'
        lane = dict(env, FACADE_SHA3_MODE=mode, FACADE_SHA3_EXPECT=expected)
        for profile in ((), ('--release',)):
            for name in TESTS:
                command = cargo + ['test', '--offline', *profile, '--test', name]
                # Always compile the complete suite, but never call an
                # unexecuted generic kernel test successful native coverage.
                api.run(command + ['--no-run'], consumer, lane)
                args = ['--', '--nocapture'] if status == 'ready' else ['required_admission', '--', '--exact', '--nocapture']
                check_result(api.run(command + args, consumer, lane), name, status == 'ready')
        print(f'PASS: hardened SHA-3: {mode}={status}; ' +
              ('704 recorded vectors owned/scoped, lifecycle and properties executed' if status == 'ready' else 'admission rejection only; kernel tests compiled, NOT executed'), flush=True)


def execute(api, root, roots, cargo, env, native=False):
    from facade_hardened_sha3_regressions import negatives, mutants
    consumer = root / 'hardened-sha3-consumer'
    env = dict(env, CARGO_TARGET_DIR=str(root / 'hardened-sha3-target'),
               BRYNJA_KECCAK_PROPERTY_SEED='17037', BRYNJA_KECCAK_PROPERTY_CASES='64')
    for package in ('brynja-crypto', 'brynja'):
        install(api, consumer, roots, package)
        api.graph(json.loads(api.resolved_metadata(cargo, consumer, env, roots).stdout), FEATURES, hosted=True)
        probe = cargo + ['run', '--offline', '--bin', 'route-probe']
        selected = shared.probe_result(api.run(probe, consumer, env).stdout)
        campaign(api, consumer, cargo, env, selected)
        negatives(api, consumer, package, cargo, env)
        if native:
            require(selected[0] in ('avx2', 'arm-keccak'), 'native CPU bundle unavailable')
            flags = '+avx2' if selected[0] == 'avx2' else '+neon,+sha2,+sha3'
            accelerated = dict(env, RUSTFLAGS='-C target-feature=' + flags,
                               CARGO_TARGET_DIR=str(root / 'hardened-sha3-native-target'))
            selected = shared.probe_result(api.run(probe, consumer, accelerated).stdout)
            require(selected[2] == 'ready', 'compiled static authority unavailable')
            campaign(api, consumer, cargo, accelerated, selected)
            mutants(api, consumer, roots, cargo, accelerated)
        print(f'PASS: {package}: hardened SHA-3 facade; native_requested={native}', flush=True)
