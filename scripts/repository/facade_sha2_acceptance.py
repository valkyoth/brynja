"""Run existing independent SHA-2 fixtures through extracted facade packages.

No cryptographic implementation or corpus is duplicated. Fixture imports alone
are redirected; hosted selection remains a separate, explicitly opted-in crate.
"""
import importlib.util
import json
from pathlib import Path
import re
import sys

import facade_sha2_routes as routes

ROOT = Path(__file__).resolve().parents[2]
FAMILIES = {
    'sha256-batch': ('sha256_batch_acceptance.py', 384, 'SHA256_BATCH_ACCEPTANCE', 'batch'),
    'sha512-batch': ('sha512_batch_acceptance.py', 4846, 'SHA512_BATCH_ACCEPTANCE', 'batch512'),
    'hardened-sha256-batch': ('sha256_batch_acceptance.py', 384, 'HARDENED_SHA256_BATCH', 'hardened_batch'),
    'hardened-sha512-batch': ('sha512_batch_acceptance.py', 4846, 'HARDENED_SHA512_BATCH', 'hardened_batch512'),
}
FEATURES = ['general-sha512-t', 'sha2-static-execution', 'sha256-batch',
            'sha512-batch', 'sha256-hardened-batch', 'sha512-hardened-batch']
HOST = ('host = { package="brynja-crypto-cpu-std", version="=0.2.0", '
        'default-features=false, features=["sha256-batch", "sha512-batch", '
        '"sha256-hardened-batch", "sha512-hardened-batch"] }\n')


def require(condition, message):
    if not condition:
        raise ValueError('facade SHA-2 acceptance: ' + message)


def corpora():
    result = {}
    directory = ROOT / 'scripts/sha2'
    sys.path.insert(0, str(directory))
    try:
        for filename, count, _, _ in FAMILIES.values():
            if filename in result:
                continue
            spec = importlib.util.spec_from_file_location(filename[:-3], directory / filename)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            data, expected = module.corpus()
            require(len(data.splitlines()) == len(expected) == count, 'oracle population')
            result[filename] = (data, expected)
    finally:
        sys.path.pop(0)
    return result


def fixture_source(text, package):
    require(package in ('brynja', 'brynja-crypto'), 'unknown facade')
    namespace = 'facade::crypto::sha2' if package == 'brynja' else 'facade::sha2'
    text = text.replace('brynja_hash_sha2', namespace).replace('brynja_crypto_cpu_std', 'host')
    require(not re.search(r'\bbrynja_[a-z_]+\b', text), 'fixture bypasses facade/host imports')
    return text


def install(api, consumer, roots, package):
    (consumer / 'src/bin').mkdir(parents=True, exist_ok=True)
    api.manifest(consumer, roots, package, FEATURES, extra=HOST)
    api.source(consumer, package, routes.RUST)
    (consumer / 'src/bin/route-probe.rs').write_text(routes.PROBE)
    for name in FAMILIES:
        src = ROOT / 'assurance' / name / 'src'
        files = list(src.rglob('*.rs'))
        require({p.name for p in files} == {'main.rs', 'request.rs' if name.startswith('hardened') else 'benchmark.rs'}
                and all(p.parent == src for p in files), 'fixture source inventory drift: ' + name)
        destination = consumer / 'src/bin' / name
        destination.mkdir(exist_ok=True)
        for path in files:
            text = fixture_source(path.read_text(), package)
            if path.name == 'main.rs':
                text = '#![forbid(unsafe_code)]\n' + text
            (destination / path.name).write_text(text)


def probe_result(output):
    lines = output.splitlines()
    require(len(lines) == 5 and lines[0] in ('CPU:avx2', 'CPU:neon', 'CPU:none'), 'probe population/CPU')
    result = {}
    for line in lines[1:]:
        fields = line.split(':')
        require(len(fields) == 3 and fields[0] == 'ROUTE' and fields[1] in FAMILIES
                and fields[1] not in result and fields[2] in ('true', 'false'), 'route probe identity')
        result[fields[1]] = fields[2] == 'true'
    require(set(result) == set(FAMILIES), 'missing route probe')
    return lines[0][4:], result


def check_result(result, expected, marker, vector):
    require(result.returncode == 0 and result.stdout.splitlines() == expected, 'oracle output mismatch')
    matches = re.findall(r'^' + marker + r': batches=(\d+); vector_calls=(\d+)(.*)$', result.stderr, re.M)
    require(len(matches) == 1, 'missing/duplicate execution marker')
    count, calls, suffix = matches[0]
    require(int(count) == len(expected) and (int(calls) > 0) == vector, 'incorrect work marker')
    require(suffix == ('; profiles=secret,declassified,public; cleanup=drop,declassify'
                      if marker.startswith('HARDENED') else ''), 'output/cleanup profiles changed')


def check_unavailable(result):
    require(result.returncode == 1 and not result.stdout and result.stderr.strip() == 'Error: "Unavailable"',
            'required unavailable route did not fail cleanly before output')


def check_invariant(result):
    require(result.returncode == 1 and not result.stdout and
            'Error: "Invariant"' in result.stderr and 'panicked at' not in result.stderr,
            'substituted SIMD did not fail the instruction-counter check')


def campaign(api, consumer, cargo, env, data, selected, profiles=((), ('--release',))):
    for profile in profiles:
        tests = api.run(cargo + ['test', '--offline', '--lib', *profile], consumer, env)
        require('test result: ok. 4 passed; 0 failed; 0 ignored;' in tests.stdout, 'route lifecycle test population')
        for name, (filename, _, marker, _) in FAMILIES.items():
            requests, expected = data[filename]
            for mode in ('portable', 'prefer', 'required'):
                incoming, answers = requests, expected
                if mode == 'required':
                    # The first 256 batches deliberately include ineligible
                    # sparse/short work. Required mode gets full-width groups.
                    incoming = '\n'.join(requests.splitlines()[256:]) + '\n'
                    answers = expected[256:]
                available = mode != 'required' or selected[name]
                command = cargo + ['run', '--offline', *profile, '--bin', name, '--', mode]
                result = api.run(command, consumer, env, data=incoming, success=available)
                if available:
                    check_result(result, answers, marker, mode != 'portable' and selected[name])
                else:
                    require(result.returncode == 1 and not result.stdout and
                            'Error: "Unavailable"' in result.stderr,
                            'required selection failed for an unrelated reason')
                    # Cargo adds build chatter: use its binary directly for the
                    # exact error contract, after successful compilation above.
                    binary = Path(env['CARGO_TARGET_DIR']) / ('release' if profile else 'debug') / name
                    if sys.platform == 'win32':
                        binary = binary.with_suffix('.exe')
                    result = api.run([str(binary), mode], consumer, env, data=incoming, success=False)
                    check_unavailable(result)
            print(f'PASS: {name}: {len(expected)} oracle batches; '
                  f'profile={"release" if profile else "debug"}; accelerated={selected[name]}', flush=True)


def mutations(api, consumer, roots, cargo, env, data):
    leaf = roots['brynja-hash-sha2'] / 'src'
    for name, (filename, _, marker, module) in FAMILIES.items():
        if name.startswith('hardened'):
            cases = (
                ('output.rs', 'let _ = clear_owned_region(destination);', 'let _ = destination;', 'declassification cleanup'),
                ('output.rs', 'brynja_core::copy_secret_region(destination, source).map_err(|_| Error::Invariant)?;',
                 'let _ = (destination, source);', None),
            )
        else:
            cases = (
                ('mod.rs', '*output = staged;', 'let _ = staged;', None),
                ('engine.rs', '&length.to_be_bytes()', '&length.to_le_bytes()', None),
            )
        accounting = 'work' if name.startswith('hardened') else 'checked_work'
        cases += (('engine.rs', f'report.scalar_blocks = {accounting}(report.scalar_blocks, 1)?;',
                   f'report.scalar_blocks = {accounting}(report.scalar_blocks, 0)?;', 'work accounting'),)
        command = cargo + ['run', '--offline', '--release', '--bin', name, '--', 'portable']
        requests, expected = data[filename]
        for relative, before, after, failure in cases:
            path = leaf / module / relative
            original = path.read_text()
            occurrences = 2 if failure == 'work accounting' and '512' in module else 1
            require(original.count(before) == occurrences, 'mutation anchor: ' + str(path))
            try:
                path.write_text(original.replace(before, after))
                api.run(cargo + ['build', '--offline', '--release', '--bin', name], consumer, env)
                result = api.run(command, consumer, env, data=requests, success=failure is None)
                if failure:
                    require(result.returncode == 1 and f'Error: "{failure}"' in result.stderr,
                            'mutant did not reach expected cleanup rejection')
                else:
                    require(result.stdout.splitlines() != expected, 'surviving compiled output/algorithm mutant')
            finally:
                path.write_text(original)
        result = api.run(command, consumer, env, data=requests)
        check_result(result, expected, marker, False)
    print('PASS: facade SHA-2: twelve compiled output/algorithm/report/cleanup mutants rejected', flush=True)


def native_mutations(api, consumer, roots, cargo, env, data):
    for name, (filename, _, marker, module) in FAMILIES.items():
        path = roots['brynja-hash-sha2'] / 'src' / module / 'engine.rs'
        original = path.read_text()
        if name.startswith('hardened'):
            before = ('session\n                    .compress_bytes(&mut s.packed, &s.blocks, &mut s.cpu)'
                      '\n                    .map_err(Error::Backend)?;')
            replacements = ['let _ = (&mut s.packed, &s.blocks, &mut s.cpu);']
        else:
            before = ('session\n                    .compress(PublicData::new(&mut packed), PublicData::new(&blocks))'
                      '\n                    .map_err(Error::Backend)?;')
            compression = 'compress64' if name == 'sha512-batch' else 'compress'
            replacements = ['let _ = (&mut packed, &blocks);',
                            'for (state, block) in packed.iter_mut().zip(&blocks).take(width) '
                            '{ crate::' + compression + '::compress(state, block); }']
        require(original.count(before) == 1, 'native mutation anchor: ' + name)
        requests, expected = data[filename]
        requests = '\n'.join(requests.splitlines()[256:]) + '\n'
        expected = expected[256:]
        command = cargo + ['run', '--offline', '--release', '--bin', name, '--', 'required']
        for after in replacements:
            try:
                path.write_text(original.replace(before, after))
                api.run(cargo + ['build', '--offline', '--release', '--bin', name], consumer, env)
                result = api.run(command, consumer, env, data=requests, success=False)
                check_invariant(result)
            finally:
                path.write_text(original)
        check_result(api.run(command, consumer, env, data=requests), expected, marker, True)
    print('PASS: facade SHA-2: six compiled SIMD no-op/scalar-substitution mutants rejected', flush=True)


def execute(api, root, roots, cargo, env, native=False):
    consumer = root / 'sha2-facade-consumer'
    data = corpora()
    for package in ('brynja-crypto', 'brynja'):
        install(api, consumer, roots, package)
        metadata = api.resolved_metadata(cargo, consumer, env, roots)
        api.graph(json.loads(metadata.stdout), FEATURES, hosted=True)
        probe = cargo + ['run', '--offline', '--bin', 'route-probe']
        cpu, selected = probe_result(api.run(probe, consumer, env).stdout)
        campaign(api, consumer, cargo, env, data, selected)
        mutations(api, consumer, roots, cargo, env, data)
        if native:
            require(cpu in ('avx2', 'neon'), 'requested SIMD unavailable on this host')
            accelerated = dict(env, RUSTFLAGS='-C target-feature=+' + cpu,
                               CARGO_TARGET_DIR=str(root / 'sha2-native-target'))
            _, available = probe_result(api.run(probe, consumer, accelerated).stdout)
            require(all(available.values()), 'requested native routes not all available')
            campaign(api, consumer, cargo, accelerated, data, available)
            native_mutations(api, consumer, roots, cargo, accelerated, data)
        print(f'PASS: {package}: SHA-2 facade/host batch acceptance; native_requested={native}', flush=True)
