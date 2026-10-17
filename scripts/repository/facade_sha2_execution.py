"""Extracted ordinary and hardened single-state SHA-2 facade consumers."""
import json
import re

import facade_parallelhash_acceptance as shared
import facade_sha2_execution_sources as sources
import facade_sha2_execution_regressions as regressions

ROOT = shared.ROOT
FEATURES = ['sha2-runtime-execution', 'sha2-hardened-execution', 'general-sha512-t']
HOST = ('host = { package="brynja-crypto-cpu-std", version="=0.1.1", '
        'default-features=false, features=["runtime-execution"] }\n')
VECTORS = ('nist-bit-selected.txt', 'general-sha512-t-digest.txt')
MODES = (('portable', False), ('prefer', False), ('static', False), ('static', True),
         ('hosted', False), ('hosted', True))


def require(value, message):
    if not value:
        raise ValueError('facade SHA-2 execution: ' + message)


def rewrite(text, package):
    require(package in ('brynja', 'brynja-crypto'), 'unknown facade')
    namespace = 'facade::crypto' if package == 'brynja' else 'facade'
    text = text.replace('brynja_crypto_cpu_std', 'host').replace('brynja_crypto_cpu', namespace + '::cpu')
    text = text.replace('brynja_hash_sha2', namespace + '::sha2')
    require(not re.search(r'\bbrynja_[a-z_]+\b', text), 'unexpected leaf import')
    return text


def install(api, consumer, roots, package, hardened):
    (consumer / 'src/bin').mkdir(parents=True, exist_ok=True)
    api.manifest(consumer, roots, package, FEATURES, extra=HOST)
    api.source(consumer, package, '')
    source = ROOT / 'assurance' / ('sha2-hardened-execution' if hardened else 'sha2-execution') / 'src'
    require({p.relative_to(source).as_posix() for p in source.rglob('*.rs')} == {'main.rs', 'named.rs', 'general.rs'}, 'fixture inventory')
    for filename in ('main.rs', 'named.rs', 'general.rs'):
        text = (source / filename).read_text()
        if filename == 'main.rs':
            text = sources.once(text, 'mod general;', 'mod acceptance;\nmod corpus;\nmod general;')
            text = '#![forbid(unsafe_code)]\n' + text
        if filename == 'general.rs':
            text = sources.once(text, 'brynja_general_sha512_t_consumer::visit_corpus', 'crate::corpus::visit')
            text = sources.once(text, 'brynja_general_sha512_t_consumer::acceptance::Error', 'crate::acceptance::Error')
        for vector in VECTORS:
            text = text.replace('../../../crates/brynja-hash-sha2/tests/vectors/' + vector, 'vectors/' + vector)
        require('../../../crates/' not in text, 'workspace corpus path')
        (consumer / 'src' / filename).write_text(rewrite(text, package))
    (consumer / 'src/acceptance.rs').write_text(sources.ERROR)
    (consumer / 'src/corpus.rs').write_text(sources.corpus((ROOT / 'assurance/general-sha512-t/src/corpus.rs').read_text()))
    (consumer / 'src/bin/route-probe.rs').write_text(rewrite(sources.PROBE, package))
    (consumer / 'src/vectors').mkdir(exist_ok=True)
    for vector in VECTORS:
        (consumer / 'src/vectors' / vector).write_bytes((roots['brynja-hash-sha2'] / 'tests/vectors' / vector).read_bytes())
    (consumer / 'tests').mkdir(exist_ok=True)
    text = (roots['brynja-hash-sha2'] / 'tests/execution.rs').read_text()
    text = sources.once(text, '#![cfg(feature = "static-execution")]', '#![forbid(unsafe_code)]')
    text = sources.once(text, '#[cfg(feature = "general-sha512-t")]\n', '')
    (consumer / 'tests/execution.rs').write_text(rewrite(text, package))


def probe_result(output):
    lines = output.splitlines()
    require(len(lines) == 7 and lines[0].startswith('ARCH:'), 'probe population')
    arch = lines[0][5:]
    require(bool(re.fullmatch(r'[a-zA-Z0-9_]+', arch)), 'architecture')
    result = {'arch': arch}
    for line in lines[1:]:
        fields = line.split(':')
        require(len(fields) == 3, 'probe shape')
        kind, width, value = fields
        require(kind in ('CPU', 'STATIC', 'HOST') and width in ('narrow', 'wide') and
                (kind, width) not in result, 'probe identity')
        allowed = {'CPU': {'true', 'false'}, 'STATIC': {'ready', 'MissingTargetFeatures', 'WrongArchitecture'},
                   'HOST': {'ready', 'WrongArchitecture', 'MissingFeaturesOrOsState', 'MissingMigrationGuarantee'}}
        require(value in allowed[kind], 'probe availability')
        result[kind, width] = value
    require(len(result) == 7, 'missing probe lane')
    for width in ('narrow', 'wide'):
        require(result['STATIC', width] != 'ready' or result['CPU', width] == 'true', 'compiled route without CPU support')
        require(result['HOST', width] != 'ready' or (arch in ('aarch64', 'x86_64') and result['CPU', width] == 'true'), 'host route without CPU support')
        if arch not in ('x86_64', 'aarch64'):
            require(result['CPU', width] == 'false' and result['STATIC', width] == 'WrongArchitecture' and
                    result['HOST', width] == 'WrongArchitecture', 'unsupported architecture claims')
    return result


def expected(selected, mode, narrow_only):
    require((mode, narrow_only) in MODES, 'unknown mode')
    routes = []
    for width in ('narrow', 'wide'):
        active = 'portable' if narrow_only and width == 'wide' else mode
        kind = 'STATIC' if active == 'static' else 'HOST'
        status = selected[kind, width]
        if active in ('static', 'hosted') and status != 'ready':
            error = f'Backend({status})' if active == 'static' else f'Unavailable({status})'
            return None, error
        if active == 'portable' or (active == 'prefer' and status != 'ready'):
            routes.append('Portable')
        else:
            kernel = ('X86' if selected['arch'] == 'x86_64' else 'Arm') + ('Sha256' if width == 'narrow' else 'Sha512')
            routes.append(('Static' if active == 'static' else 'Runtime') + f'({kernel})')
    return tuple(routes), None


def check_result(result, hardened, routes):
    require(result.returncode == 0 and not result.stderr and result.stdout.splitlines() == [
        f'SHA-2 {"hardened" if hardened else "ordinary"} execution acceptance: PASS; named=240; general=4590',
        f'narrow={routes[0]}; wide={routes[1]}',
        ('owned-memory cleanup; no register/spill guarantee' if hardened else 'public-only') +
        '; independently verified: NO; FIPS validated: NO'], 'population/route/qualification output')


def check_error(result, error):
    require(result.returncode == 1 and not result.stdout and result.stderr.strip() ==
            'Error: Custom { kind: Other, error: ' + json.dumps('acceptance failed: ' + error) + ' }',
            'unexpected rejection: ' + result.stderr[-1000:])


def campaign(api, consumer, cargo, env, selected, hardened):
    for profile in ((), ('--release',)):
        for args, count in ((['--test', 'execution'], 5), (['--bin', 'facade-consumer'], 2)):
            result = api.run(cargo + ['test', '--offline', *profile, *args], consumer, env)
            require(f'test result: ok. {count} passed; 0 failed; 0 ignored;' in result.stdout, 'lifecycle/parser test population')
        api.run(cargo + ['build', '--offline', *profile, '--bin', 'facade-consumer'], consumer, env)
        for mode, narrow in MODES:
            routes, error = expected(selected, mode, narrow)
            result = api.run([str(shared.binary(env, profile)), mode] + (['narrow'] if narrow else []), consumer, env, success=error is None)
            if error:
                check_error(result, error)
            else:
                check_result(result, hardened, routes)
        print(f'PASS: SHA-2 {"hardened" if hardened else "ordinary"}: named=240; general=4590; '
              f'profile={"release" if profile else "debug"}; static={selected["STATIC", "narrow"]}/{selected["STATIC", "wide"]}', flush=True)


def native_flags(selected):
    require(selected['CPU', 'narrow'] == 'true' and selected['arch'] in ('x86_64', 'aarch64'), 'native SHA-256 instruction bundle unavailable')
    wide = selected['CPU', 'wide'] == 'true'
    return ('+sha,+sse2' + (',+sha512,+avx2,+avx' if wide else '') if selected['arch'] == 'x86_64'
            else '+neon,+sha2' + (',+sha3' if wide else ''))


def execute(api, root, roots, cargo, env, native=False):
    consumer = root / 'sha2-execution-consumer'
    env = dict(env, CARGO_TARGET_DIR=str(root / 'sha2-execution-target'))
    for package in ('brynja-crypto', 'brynja'):
        for hardened in (False, True):
            install(api, consumer, roots, package, hardened)
            api.graph(json.loads(api.resolved_metadata(cargo, consumer, env, roots).stdout), FEATURES, hosted=True)
            probe = cargo + ['run', '--offline', '--bin', 'route-probe']
            selected = probe_result(api.run(probe, consumer, env).stdout)
            campaign(api, consumer, cargo, env, selected, hardened)
            regressions.negatives(api, consumer, package, cargo, env, hardened)
            regressions.mutants(api, consumer, roots, cargo, env, hardened, check_error, check_result)
            if native:
                accelerated = dict(env, RUSTFLAGS='-C target-feature=' + native_flags(selected),
                    CARGO_TARGET_DIR=str(root / 'sha2-execution-native-target'))
                native_selected = probe_result(api.run(probe, consumer, accelerated).stdout)
                require(native_selected['STATIC', 'narrow'] == 'ready' and
                        (selected['CPU', 'wide'] != 'true' or native_selected['STATIC', 'wide'] == 'ready'), 'available native route not compiled')
                campaign(api, consumer, cargo, accelerated, native_selected, hardened)
                wide = native_selected['STATIC', 'wide'] == 'ready'
                regressions.native_mutants(api, consumer, roots, cargo, accelerated, hardened, wide,
                    expected(native_selected, 'static', not wide)[0], check_error, check_result)
            print(f'PASS: {package}: {"hardened" if hardened else "ordinary"} single-state SHA-2; native_requested={native}', flush=True)
