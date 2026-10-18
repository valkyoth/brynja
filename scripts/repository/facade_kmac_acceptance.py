"""Production KMAC/KMACXOF consumers of extracted facade archives."""
import json

import facade_kmac_sources as sources
import facade_kmac_corpus as oracle
import facade_kmac_probes as probes
import facade_tuplehash_acceptance as shared

ROOT = shared.ROOT
FEATURES = ['kmac-runtime-execution']
HOST = shared.HOST
TESTS = {'scoped.rs', 'scoped/xof.rs'}
# This fixture deliberately constructs leaf conformance owners to test their
# production finalizers. It remains covered by the leaf package admission
# campaign, but cannot be imported into a production-only facade consumer.
LEAF_ONLY_TESTS = {'production_admission.rs'}


def require(value, message):
    if not value:
        raise ValueError('facade KMAC: ' + message)


def install(api, consumer, roots, package):
    (consumer / 'src/bin').mkdir(parents=True, exist_ok=True)
    api.manifest(consumer, roots, package, FEATURES, extra=HOST)
    api.source(consumer, package, '')
    fixture = ROOT / 'assurance/kmac-execution'
    require({p.relative_to(fixture / 'src').as_posix() for p in (fixture / 'src').rglob('*.rs')} == set(sources.COUNTS), 'fixture inventory')
    for name in sources.COUNTS:
        text = sources.production(name, (fixture / 'src' / name).read_text())
        if name == 'main.rs':
            text = '#![forbid(unsafe_code)]\n' + text
        (consumer / 'src' / name).write_text(sources.rewrite(text, package))
    (consumer / 'src/bin/route-probe.rs').write_text(sources.rewrite(shared.probes.PROBE, package))
    require(not TESTS & LEAF_ONLY_TESTS, 'overlapping test classification')
    require({p.relative_to(fixture / 'tests').as_posix() for p in (fixture / 'tests').rglob('*.rs')} == TESTS | LEAF_ONLY_TESTS, 'scoped test inventory')
    for name in TESTS:
        path = consumer / 'tests' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(sources.rewrite(sources.scoped_tests(name, (fixture / 'tests' / name).read_text()), package))
    text = sources.execution_tests((roots['brynja-mac-kmac'] / 'tests/execution.rs').read_text())
    (consumer / 'tests/execution.rs').write_text(sources.rewrite(text, package))


def check_result(result, expected, mode, kernel):
    require(result.returncode == 0 and len(expected) == 268 and result.stdout.splitlines() == expected,
            'oracle output/population mismatch')
    require(result.stderr.strip() == 'KMAC_EXECUTION_ROUTE: ' + shared.route(mode, kernel), 'route identity/health')


def check_failure(result, mode, kernel, kind, error):
    require(result.returncode == 1 and not result.stdout and result.stderr.splitlines() == [
        'KMAC_EXECUTION_ROUTE: ' + shared.route(mode, kernel),
        'Error: Custom { kind: ' + kind + ', error: ' + json.dumps(error) + ' }'],
        'unexpected/nonatomic failure: ' + result.stderr[-1500:])


def campaign(api, consumer, cargo, env, data, selected):
    _, kernel, static, hosted = selected
    requests, answers = data
    for profile in ((), ('--release',)):
        tests = [('execution', 7)] + ([('scoped', 4)] if static == 'ready' else [])
        for name, count in tests:
            result = api.run(cargo + ['test', '--offline', *profile, '--test', name], consumer, env)
            require(f'test result: ok. {count} passed; 0 failed; 0 ignored;' in result.stdout, 'lifecycle population: ' + name)
        api.run(cargo + ['build', '--offline', *profile, '--bin', 'facade-consumer'], consumer, env)
        for mode in ('portable', 'prefer-portable', 'static', 'prefer', 'hosted'):
            reason = static if mode in ('static', 'prefer') else hosted if mode == 'hosted' else 'ready'
            command = [str(shared.binary(env, profile)), mode]
            result = api.run(command, consumer, env, data=requests, success=reason == 'ready')
            if reason != 'ready':
                shared.check_unavailable(result, reason, mode == 'hosted')
                continue
            check_result(result, answers, mode, kernel)
            for bad, kind, error in oracle.invalid():
                for index, prefix in enumerate(('', requests.splitlines()[0] + '\n'), 1):
                    result = api.run(command, consumer, env, data=prefix + bad + '\n', success=False)
                    check_failure(result, mode, kernel, kind, f'line {index}: {error}' if kind == 'InvalidData' else error)
            print(f'PASS: KMAC: 268 independent cases; mode={mode}; profile={"release" if profile else "debug"}; scoped={mode not in ("portable", "prefer-portable")}', flush=True)


def execute(api, root, roots, cargo, env, native=False):
    consumer = root / 'kmac-facade-consumer'
    env = dict(env, CARGO_TARGET_DIR=str(root / 'kmac-facade-target'))
    data = oracle.render(oracle.cases())
    for package in ('brynja-crypto', 'brynja'):
        install(api, consumer, roots, package)
        api.graph(json.loads(api.resolved_metadata(cargo, consumer, env, roots).stdout), FEATURES, hosted=True)
        probe = cargo + ['run', '--offline', '--bin', 'route-probe']
        selected = shared.probe_result(api.run(probe, consumer, env).stdout)
        campaign(api, consumer, cargo, env, data, selected)
        probes.negatives(api, consumer, package, cargo, env)
        probes.algorithm_mutants(api, consumer, roots, cargo, env, data, selected[1], check_result, check_failure)
        probes.cleanup_mutant(api, consumer, roots, cargo, env)
        if native:
            require(selected[0] in ('avx2', 'arm-keccak'), 'native Keccak bundle unavailable')
            flags = '+avx2' if selected[0] == 'avx2' else '+neon,+sha2,+sha3'
            accelerated = dict(env, RUSTFLAGS='-C target-feature=' + flags,
                               CARGO_TARGET_DIR=str(root / 'kmac-facade-native-target'))
            available = shared.probe_result(api.run(probe, consumer, accelerated).stdout)
            require(available[2] == 'ready', 'compiled KMAC route unavailable')
            campaign(api, consumer, cargo, accelerated, data, available)
            probes.cleanup_mutant(api, consumer, roots, cargo, accelerated, scoped=True)
            probes.fallback_mutant(api, consumer, roots, cargo, accelerated, data, available[1], check_result, check_failure)
        print(f'PASS: {package}: production KMAC execution/scoped acceptance; native_requested={native}', flush=True)
