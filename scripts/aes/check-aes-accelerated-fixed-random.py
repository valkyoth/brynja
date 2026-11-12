#!/usr/bin/env python3
"""Accelerated fixed/random fixture correctness; observations are explicit and one-shot."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('accelerated_timing_performance', HERE / 'check-aes-performance.py')
performance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(performance)
campaign, packaged, ROOT = performance.campaign, performance.packaged, performance.ROOT
timing = packaged.module('accelerated_timing_policy', HERE / 'check-aes-fixed-random.py')
controls = packaged.module('accelerated_timing_controls', HERE / 'aes_timing_controls.py')
dispatch = packaged.module('accelerated_timing_dispatch', HERE / 'aes_timing_dispatch.py')
batch = packaged.module('accelerated_timing_batch', HERE / 'aes_timing_batch.py')
crossover = packaged.module('accelerated_timing_crossover', HERE / 'aes_timing_slot_crossover.py')
require, execute, oracle = packaged.require, performance.execute, timing.oracle


def substitutions():
    # Exact-count, reversible plumbing only. Timer, corpus, order, operations,
    # policy and unit tests remain the portable fixture's single source of truth.
    setup = ('let forced = brynja_aes_accelerated_fixture::forced_authority().map_err(|e| e.to_string())?;\n'
             '    let authority = forced.get().map_err(|e| e.to_string())?;\n    ')
    test_setup = ('let forced = brynja_aes_accelerated_fixture::forced_authority().unwrap();\n'
                  '        let authority = forced.get().unwrap();\n        ')
    return (
        ('brynja_aes_public_api_fixture::aes', 'brynja_aes_accelerated_fixture::aes', 1),
        ('    PublicCiphertext,', '    Authority, PublicCiphertext,', 1),
        ('fn $trial(\n', 'fn $trial(\n            authority: &Authority,\n', 1),
        ('$key::new(', '$key::new(authority, ', 1),
        ('$cached::new(', '$cached::new(authority, ', 2),
        ('type Trial = fn(', 'type Trial = fn(&Authority, ', 1),
        ('trial(owner,', 'trial(authority, owner,', 3),
        ('trial("', 'trial(authority, "', 4),
        ('    println!("AES_FIXED_RANDOM_POLICY', '    ' + setup + 'println!("AES_FIXED_RANDOM_POLICY', 1),
        ('fn all_routes_produce_one_block_and_match_cached() {\n        ',
         'fn all_routes_produce_one_block_and_match_cached() {\n        ' + test_setup, 1),
        ('        assert!(run("unknown").is_err());',
         '        ' + test_setup + 'assert!(run("unknown").is_err());', 1),
    )


def fixture(source):
    for old, new, count in substitutions():
        require(source.count(old) == count, 'fixed/random fixture plumbing changed: ' + old)
        source = source.replace(old, new)
    return source


def dit_authority_fixture(source):
    """Explicit static DIT admission; never infer it from the measurement host."""
    replacements = (
        ('Authority::new(kernel).map_err',
         'Authority::new_with_dit(kernel, public::execution::DitPolicy::Require).map_err'),
        ('    result.get()?;',
         '    if !result.get()?.dit_enabled() {\n'
         '        return Err("required DIT scope was not admitted".into());\n'
         '    }'),
    )
    for old, new in replacements:
        require(source.count(old) == 1, 'DIT authority fixture plumbing changed: ' + old)
        source = source.replace(old, new)
    return source


def dit_configuration(target, flags, kernel, required):
    if not required:
        return flags
    require(kernel == 'ArmAes' and target in ('aarch64-unknown-linux-gnu', 'aarch64-unknown-linux-musl', 'aarch64-apple-darwin'),
            'required DIT timing is ARM-only')
    require(flags == '-Ctarget-feature=+aes,+neon', 'unexpected DIT timing target flags')
    return flags + ',+dit'


def probe_host(compiler, target, probe, directory, env, artifacts, required, execution_prefix=()):
    require(not env.get('RUSTFLAGS') and not env.get('CARGO_ENCODED_RUSTFLAGS'),
            'host probe must precede specialized target flags')
    source = ROOT / ('assurance/aes-accelerated-campaigns/dit-probe.rs' if required
                     else 'assurance/aes-kernel-candidate/probe.rs')
    require(source.is_file() and not any(p.is_symlink() for p in (source, *source.parents)),
            'missing/symlinked timing host probe')
    require(execution_prefix in ((), ('qemu-aarch64', '-cpu', 'max')), 'unsupported capability probe runner')
    linker = ['-C', 'linker=rust-lld'] if execution_prefix else []
    execute(['rustc', '+' + compiler, '--edition=2024', *linker, str(source),
             '--target', target, '-o', str(probe)], directory, env, artifacts, 'probe-build')
    observed = execute([*execution_prefix, str(probe)], directory, env, artifacts, 'probe')
    marker = 'AES_DIT_HOST_BUNDLE_PASS' if required else 'AES_STATIC_HOST_BUNDLE_PASS'
    require(not observed.stderr and observed.stdout.splitlines() == [marker], 'ISA probe failed')
    return source


def payload(output, kernel):
    first, separator, rest = output.partition('\n')
    require(separator and first == performance.authority_marker(kernel), 'wrong/missing accelerated timing authority')
    return rest  # The shared strict parser rejects additional authority markers.


def collect(binary, directory, env, artifacts, kernel, control=None, policy=timing, diagnostic_only=False):
    require(not diagnostic_only or control in ('separate-values', 'separate-identical'),
            'only class-coupled address controls may be diagnostic-only')
    with performance.measurement_affinity() as cpu:
        host = performance.apple_host_info() if cpu is None else timing.host_info(cpu)
        (artifacts / 'host.json').write_text(json.dumps(host, indent=2) + '\n')
        result = execute([str(binary), 'measure', *([] if control is None else [control])], directory, env, artifacts, 'measure')
        require(not result.stderr, 'unexpected timing measurement diagnostics')
        text = payload(result.stdout, kernel)
        if control is not None:
            text = controls.payload(text, control)
        rows = policy.parse(text)
        summary = {'campaigns': rows, 'alarms': sum(row['alarm'] for row in rows),
                   'inconclusive': sum(row['inconclusive'] for row in rows)}
        if diagnostic_only:
            summary['comparison_role'] = 'class-coupled address diagnostic; not a value-dependence verdict'
        (artifacts / 'summary.json').write_text(json.dumps(summary, indent=2, allow_nan=False) + '\n')
        if diagnostic_only:
            print(f'AES_TIMING_ADDRESS_DIAGNOSTIC_RETAINED: {control}; '
                  f"alarms={summary['alarms']}; noise={summary['inconclusive']}; not a timing pass", flush=True)
            return
        require(not summary['alarms'] and not summary['inconclusive'],
                'fixed/random alarm or inconclusive noise: retain samples and investigate; do not retry-to-pass')
    print('AES_ACCELERATED_FIXED_RANDOM_OBSERVED: ' + (control + '; ' if control else '')
          + '39 campaigns; 8192 pairs; zero alarms; noise policy satisfied', flush=True)


def collect_overhead(binary, directory, env, artifacts, policy=timing):
    with performance.measurement_affinity() as cpu:
        host = performance.apple_host_info() if cpu is None else timing.host_info(cpu)
        (artifacts / 'overhead-host.json').write_text(json.dumps(host, indent=2) + '\n')
        result = execute([str(binary), 'overhead', 'shared-identical'], directory, env, artifacts, 'overhead')
        require(not result.stderr, 'unexpected overhead diagnostics')
        summary = dispatch.parse_overhead(result.stdout, policy)
        (artifacts / 'overhead-summary.json').write_text(json.dumps(summary, indent=2, allow_nan=False) + '\n')


def validate_controls_and_observe(binary, directory, env, artifacts, kernel, executable, binary_hash, oracle_hash, observation, isolate_dispatch=False, policy=timing, value_controls=False, execution_prefix=()):
    require(execution_prefix in ((), ('qemu-aarch64', '-cpu', 'max')), 'unsupported fixture runner')
    require(not execution_prefix or observation is None, 'emulation cannot collect timing observations')
    for control in controls.CONTROLS:
        result = execute([*execution_prefix, str(binary), 'preflight', control], directory, env, artifacts, 'preflight-' + control)
        require(not result.stderr, 'unexpected controlled preflight diagnostics')
        text = controls.payload(payload(result.stdout, kernel), control)
        controls.preflight(text, control, executable, env, policy)
    require(oracle.digest(binary) == binary_hash and oracle.digest(executable) == oracle_hash, 'timing/oracle executable changed')
    failures = []
    try:
        if observation is not None:
            extra = {'policy': policy} if policy is not timing else {}
            if isolate_dispatch:
                collect_overhead(binary, directory, env, artifacts, **extra)
            for control in controls.CONTROLS:
                require(oracle.digest(binary) == binary_hash and oracle.digest(executable) == oracle_hash, 'timing/oracle executable changed')
                destination = artifacts / control
                destination.mkdir()
                try:
                    role = {'diagnostic_only': True} if value_controls and control.startswith('separate-') else {}
                    collect(binary, directory, env, destination, kernel, control, **extra, **role)
                except (ValueError, OSError, subprocess.SubprocessError) as error:
                    failures.append({'control': control, 'error': str(error)})
                    print(f'CONTROL_NONPASS: {control}: {error}', flush=True)
                require(oracle.digest(binary) == binary_hash and oracle.digest(executable) == oracle_hash, 'timing/oracle executable changed')
            interpretation = {'value_comparison': 'shared-values', 'negative_control': 'shared-identical',
                              'address_diagnostics': ['separate-values', 'separate-identical'],
                              'scope': 'prospective shared-address screen; no historical pass conversion'} if value_controls else {}
            (artifacts / 'experiment.json').write_text(json.dumps({'controls': controls.CONTROLS, 'failures': failures,
                                                                  **interpretation}, indent=2) + '\n')
    finally:
        require(oracle.digest(binary) == binary_hash and oracle.digest(executable) == oracle_hash, 'timing/oracle executable changed')
    require(not failures, 'controlled timing experiment has non-pass results; retain every arm, no retry')


def validate_and_observe(binary, directory, env, artifacts, kernel, executable, binary_hash, oracle_hash, observation):
    result = execute([str(binary), 'preflight'], directory, env, artifacts, 'preflight')
    require(not result.stderr, 'unexpected timing preflight diagnostics')
    timing.preflight(payload(result.stdout, kernel), executable, env)
    # Validate identities before any measurement and on every exit afterward,
    # including an alarm, malformed samples, process failure or timeout.
    require(oracle.digest(binary) == binary_hash and oracle.digest(executable) == oracle_hash, 'timing/oracle executable changed')
    try:
        if observation is not None:
            collect(binary, directory, env, artifacts, kernel)
    finally:
        require(oracle.digest(binary) == binary_hash and oracle.digest(executable) == oracle_hash, 'timing/oracle executable changed')


def check(compiler, route, observation=None, with_controls=False, isolate_dispatch=False, long_batch=False, slot_crossover=False, value_controls=False, require_dit=False, qemu_aarch64=False):
    require(compiler in ('1.90.0', '1.99.1') and route in ('direct', 'facade'), 'unsupported timing configuration')
    require(not value_controls or (with_controls and not slot_crossover and not isolate_dispatch and not long_batch),
            'value screening requires --controls without crossover, dispatch or batch experiments')
    require(not require_dit or value_controls, 'required DIT timing requires shared-address value controls')
    require(not qemu_aarch64 or (observation is None and require_dit),
            'ARM cross preparation requires DIT and forbids observations')
    require(not slot_crossover or (observation is None and not with_controls and not isolate_dispatch and not long_batch),
            'slot crossover is correctness-only and cannot mix experiments or collect observations')
    require(observation is None or value_controls,
            'new timing observations require --controls --value-controls; class-coupled baseline is reference-only')
    require(not isolate_dispatch or with_controls, 'dispatch isolation requires address/value controls')
    require(not long_batch or isolate_dispatch, 'long batch requires dispatch isolation and controls')
    policy = batch.policy(timing) if long_batch else timing
    require(observation is None or re.fullmatch(r'[a-z0-9][a-z0-9-]{0,79}', observation), 'invalid observation name')
    target, flags, kernel = performance.native_configuration(platform.system(), platform.machine())
    execution_prefix = ()
    if qemu_aarch64:
        require((platform.system(), platform.machine()) == ('Linux', 'x86_64'),
                'ARM cross preparation requires a Linux x86_64 build host')
        target, flags, kernel = 'aarch64-unknown-linux-musl', '-Ctarget-feature=+aes,+neon', 'ArmAes'
        execution_prefix = ('qemu-aarch64', '-cpu', 'max')
    flags = dit_configuration(target, flags, kernel, require_dit)
    for name in performance.REJECT:
        require(name not in os.environ, 'remove ambient ' + name)
    executable = oracle.select(os.environ)
    oracle_hash = oracle.digest(executable)
    base = ROOT / 'target/aes-accelerated-fixed-random'
    base.mkdir(parents=True, exist_ok=True)
    if observation is None:
        artifacts = Path(tempfile.mkdtemp(prefix=f'check-{compiler}-{route}-', dir=base))
    else:
        artifacts = base / observation
        artifacts.mkdir()  # No overwrite and no automatic retry.
    print(f'Artifacts: {artifacts}', flush=True)
    with packaged.archives.cargo_environment.private_directory(ROOT) as temporary:
        root = Path(temporary)
        env = packaged.archives.isolated_env(root)
        env['OPENSSL_CONF'] = '/dev/null'
        oracle.preflight(executable, env)
        versions = packaged.package_sources(root, env)
        directory = root / 'consumers/aes'
        (directory / 'src/bin').mkdir(parents=True)
        for source in (timing.FIXTURE, ROOT / 'assurance/aes-accelerated-campaigns/lib.rs'):
            require(source.is_file() and not any(p.is_symlink() for p in (source, *source.parents)), 'missing/symlinked timing fixture')
        authority_source = (ROOT / 'assurance/aes-accelerated-campaigns/lib.rs').read_text()
        if require_dit:
            authority_source = dit_authority_fixture(authority_source)
        (directory / 'src/lib.rs').write_text(authority_source)
        source = fixture(timing.FIXTURE.read_text())
        if with_controls:
            module = ROOT / 'assurance/aes-accelerated-campaigns/timing-controls.rs'
            require(module.is_file() and not any(p.is_symlink() for p in (module, *module.parents)), 'missing/symlinked timing controls')
            source = controls.fixture(source, module.read_text())
        if isolate_dispatch:
            modules = [ROOT / f'assurance/aes-accelerated-campaigns/timing-{name}.rs' for name in ('dispatch', 'overhead')]
            for module in modules:
                require(module.is_file() and not any(p.is_symlink() for p in (module, *module.parents)), 'missing/symlinked dispatch fixture')
            source = dispatch.fixture(source, *(module.read_text() for module in modules))
        if long_batch:
            source = batch.fixture(source)
        if slot_crossover:
            modules = [ROOT / f'assurance/aes-accelerated-campaigns/timing-slot-{name}.rs' for name in ('crossover', 'driver')]
            for module in modules:
                require(module.is_file() and not any(p.is_symlink() for p in (module, *module.parents)), 'missing/symlinked crossover fixture')
            source = crossover.fixture(source, *(module.read_text() for module in modules))
        (directory / 'src/bin/fixed-random.rs').write_text(source)
        manifest = campaign.manifest(versions, route, 'static') + 'opt-level=3\nlto="fat"\ncodegen-units=1\npanic="abort"\n'
        (directory / 'Cargo.toml').write_text(manifest)
        cargo = ['cargo', '+' + compiler]
        selection = ['--locked', '--offline', '--no-default-features', '--features', route]
        execute(cargo + ['generate-lockfile', '--offline'], directory, env, artifacts, 'lock')
        metadata = execute(cargo + ['metadata', '--format-version=1', '--filter-platform', target, *selection], directory, env, artifacts, 'metadata')
        campaign.graph(json.loads(metadata.stdout), versions, directory, route, 'static')
        probe = root / 'probe'
        probe_source = probe_host(compiler, target, probe, directory, env, artifacts, require_dit, execution_prefix)
        shutil.copy2(probe, artifacts / 'host-probe')
        env['RUSTFLAGS'] = flags
        if qemu_aarch64:
            env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER'] = 'rust-lld'
            env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER'] = ' '.join(execution_prefix)
        tests = execute(cargo + ['test', *selection, '--target', target, '--release', '--bin', 'fixed-random', '--', '--test-threads=1'], directory, env, artifacts, 'tests')
        if slot_crossover:
            crossover.check_tests(tests.stdout, timing)
        elif with_controls:
            controls.check_tests(tests.stdout, timing, dispatch.TESTS if isolate_dispatch else frozenset())
        else:
            timing.check_tests(tests.stdout)
        print(tests.stdout, end='', flush=True)
        execute(cargo + ['build', *selection, '--target', target, '--release', '--bin', 'fixed-random'], directory, env, artifacts, 'build')
        built = Path(env['CARGO_TARGET_DIR']) / target / 'release/fixed-random'
        binary = artifacts / 'fixed-random'
        shutil.copy2(built, binary)
        before = oracle.digest(binary)
        require(oracle.digest(built) == before, 'retained timing binary differs from build')
        compiler_info = execute(['rustc', '+' + compiler, '-vV'], directory, env, artifacts, 'compiler').stdout
        (artifacts / 'identity.json').write_text(json.dumps({'compiler': compiler_info, 'route': route,
            'admission': 'static', 'target': target, 'profile': timing.PROFILE, 'kernel': kernel,
            'binary_sha256': before, 'flags': flags, 'versions': versions, 'oracle': str(executable),
            'dit_policy': 'Require' if require_dit else 'IfAvailable (compiled target features)',
            'correctness_execution': 'QEMU max; no native execution or timing' if qemu_aarch64 else 'native host',
            'authority_fixture_sha256': hashlib.sha256(authority_source.encode()).hexdigest(),
            'host_probe_sha256': oracle.digest(probe_source),
            'host_probe_binary_sha256': oracle.digest(artifacts / 'host-probe'),
            'oracle_sha256': oracle_hash, 'observation': observation,
            'controls': list(controls.CONTROLS) if with_controls else None,
            **({'value_controls': 'shared-values primary; shared-identical negative; separate arms diagnostic'} if value_controls else {}),
            'dispatch_isolated': isolate_dispatch,
            'long_batch': long_batch,
            **({'slot_crossover': 'correctness-only'} if slot_crossover else {}),
            'archive_sha256': {name: oracle.digest(root / f'target/package/{name}-{version}.crate')
                               for name, version in versions.items()},
            'fixture_sha256': hashlib.sha256(source.encode()).hexdigest(),
            'pairs': policy.SAMPLES, 'repeat': policy.REPEAT, 'warmup': policy.WARMUP, 'seed': policy.SEED,
            'threshold': timing.LIMIT, 'maximum_cv': timing.MAX_CV,
            'policy': 'no rejection/cropping/adaptive stopping/retry-to-pass',
            'source': 'byte-checked working-tree archives; not a clean tagged release'}, indent=2) + '\n')
        if slot_crossover:
            try:
                require(oracle.digest(binary) == before and oracle.digest(executable) == oracle_hash, 'timing/oracle executable changed')
                result = execute([str(binary), 'crossover-preflight'], directory, env, artifacts, 'preflight')
                crossover.validate_preflight(result, executable, env, kernel, payload, timing)
            finally:
                require(oracle.digest(binary) == before and oracle.digest(executable) == oracle_hash, 'timing/oracle executable changed')
        else:
            validate = validate_controls_and_observe if with_controls else validate_and_observe
            extra = {'isolate_dispatch': True} if isolate_dispatch else {}
            if value_controls:
                extra['value_controls'] = True
            if execution_prefix:
                extra['execution_prefix'] = execution_prefix
            if long_batch:
                extra['policy'] = policy
            validate(binary, directory, env, artifacts, kernel, executable, before, oracle_hash, observation, **extra)
    if slot_crossover:
        print(f'AES_ACCELERATED_TIMING_CROSSOVER_FIXTURE_PASS: {compiler} {route}; 13 tests; 576 vectors; correctness only', flush=True)
    elif long_batch:
        print(f'AES_ACCELERATED_TIMING_BATCH_FIXTURE_PASS: {compiler} {route}; 10 tests; 936 vectors; correctness only', flush=True)
    elif isolate_dispatch:
        print(f'AES_ACCELERATED_TIMING_DISPATCH_FIXTURE_PASS: {compiler} {route}; 10 tests; 936 vectors; correctness only', flush=True)
    elif with_controls:
        print(f'AES_ACCELERATED_TIMING_CONTROLS_FIXTURE_PASS: {compiler} {route}; 8 tests; 936 vectors; correctness only', flush=True)
    else:
        print(f'AES_ACCELERATED_TIMING_FIXTURE_PASS: {compiler} {route}; 4 tests; 234 vectors; correctness only', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=('1.90.0', '1.99.1'), required=True)
    parser.add_argument('--route', choices=('direct', 'facade'), required=True)
    parser.add_argument('--observation', help='Explicit one-shot observation in a new directory; alarms/noise retained')
    parser.add_argument('--controls', action='store_true', help='Address/value factorial controls; one shared binary, all four arms, no retries')
    parser.add_argument('--value-controls', action='store_true', help='Required for new observations: shared-address value/negative screens; separate-address arms retained as diagnostics')
    parser.add_argument('--require-dit', action='store_true', help='ARM-only: baseline-probe DIT, compile +dit and require scoped DIT admission; requires --controls --value-controls')
    parser.add_argument('--qemu-aarch64', action='store_true', help='Cross-build musl ARM DIT fixture and check correctness under QEMU; no observations allowed')
    parser.add_argument('--isolate-dispatch', action='store_true', help='Separate experiment: dispatch outside timer and diagnostic overhead controls; requires --controls')
    parser.add_argument('--long-batch', action='store_true', help='Separate fixed 1024-operation experiment; requires --controls --isolate-dispatch')
    parser.add_argument('--slot-crossover', action='store_true', help='Class/slot crossover fixture correctness only; observations disabled')
    args = parser.parse_args()
    try:
        check(args.toolchain, args.route, args.observation, args.controls, args.isolate_dispatch, args.long_batch, args.slot_crossover, args.value_controls, args.require_dit, args.qemu_aarch64)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'AES accelerated fixed/random FAIL: {error}', flush=True)
        raise SystemExit(2) from error
