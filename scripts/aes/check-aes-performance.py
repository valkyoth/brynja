#!/usr/bin/env python3
"""Packaged AES performance-fixture correctness; measurements require explicit opt-in."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import statistics
import subprocess
import tempfile
from contextlib import contextmanager

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('performance_campaign', HERE / 'check-aes-accelerated-campaigns.py')
campaign = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(campaign)
packaged, ROOT = campaign.packaged, campaign.ROOT
require = packaged.require
SAMPLES, BATCH, WARMUP = 9, 64, 8
OPERATIONS = ('construct-clear', 'encrypt', 'decrypt', 'public')
TESTS = {'tests::every_route_matches_vectors_and_clears', 'tests::malformed_configuration_is_rejected',
         'tests::wrong_output_or_operation_failure_cannot_complete_batch', 'tests::policy_and_operation_population_are_fixed'}
REJECT = (*packaged.archives.REJECT_ENV, 'PYTHONOPTIMIZE', 'PYTHONPATH', 'LD_PRELOAD', 'LD_AUDIT', 'LD_LIBRARY_PATH')
PROFILE = 'opt3-fat-lto-cgu1-overflow-unwind'
PREFLIGHT = 'AES_PERFORMANCE_PREFLIGHT_PASS: 48 cases'
HEADER = f'AES_PERFORMANCE_POLICY: {SAMPLES} {BATCH} {WARMUP}'
END = 'AES_PERFORMANCE_END: 432 samples; diagnostic only'


def native_configuration(system, machine):
    if (system, machine) == ('Darwin', 'arm64'):
        return ('aarch64-apple-darwin', '-Ctarget-feature=+aes,+neon', 'ArmAes')
    require(system == 'Linux', 'performance diagnostic requires Linux or arm64 macOS')
    configurations = {
        'x86_64': ('x86_64-unknown-linux-gnu', '-Ctarget-feature=+aes,+sse2', 'X86AesNi'),
        'aarch64': ('aarch64-unknown-linux-gnu', '-Ctarget-feature=+aes,+neon', 'ArmAes'),
    }
    require(machine in configurations, 'unsupported native performance architecture')
    return configurations[machine]


@contextmanager
def measurement_affinity():
    """Linux pins/restores; Apple explicitly makes no CPU-placement claim."""
    system = platform.system()
    if system == 'Darwin':
        require(platform.machine() == 'arm64', 'unsupported Apple measurement architecture')
        yield None
        return
    require(system == 'Linux', 'unsupported measurement platform')
    affinity = os.sched_getaffinity(0)
    require(bool(affinity), 'empty host affinity')
    try:
        os.sched_setaffinity(0, {min(affinity)})
        yield min(affinity)
    finally:
        os.sched_setaffinity(0, affinity)


def apple_host_info():
    """Public host context collected before timing; failed queries stop the run."""
    require((platform.system(), platform.machine()) == ('Darwin', 'arm64'),
            'Apple host context requires native arm64 macOS')
    def query(command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=True)
        require(not result.stderr and result.stdout.strip(), 'missing Apple host context')
        return result.stdout.strip()
    return dict(platform=platform.platform(), machine=platform.machine(),
                os_version=query(['/usr/bin/sw_vers']),
                sysctl={name:query(['/usr/sbin/sysctl', '-n', name]) for name in
                        ('machdep.cpu.brand_string', 'hw.physicalcpu', 'hw.logicalcpu')},
                logical_cpu=None, affinity='not pinned; macOS scheduler chooses CPU/core class',
                load_before=list(os.getloadavg()), governor='unavailable', boost='unavailable',
                limitation='Core migration, heterogeneous cores and power policy are uncontrolled; no affinity guarantee.')


def authority_marker(kernel):
    require(kernel in ('X86AesNi', 'ArmAes'), 'unsupported performance authority')
    return 'AES_FORCED_AUTHORITY: ' + kernel


def manifest(versions, route):
    return campaign.manifest(versions, route, 'static') + 'opt-level=3\nlto="fat"\ncodegen-units=1\npanic="unwind"\n'


def check_tests(output):
    names = re.findall(r'^test ([^\s]+) \.\.\. ok$', output, re.MULTILINE)
    summaries = re.findall(r'^test result:.*$', output, re.MULTILINE)
    require(len(names) == 4 and set(names) == TESTS and len(summaries) == 1 and
            re.fullmatch(r'test result: ok\. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in [0-9.]+s', summaries[0]),
            'performance fixture tests incomplete')


def preflight(output, kernel='X86AesNi'):
    require(output.splitlines() == [authority_marker(kernel), PREFLIGHT], 'performance preflight mismatch')


def parse(output, kernel='X86AesNi'):
    lines = output.splitlines()
    require(len(lines) == 436 and lines[:3] == [authority_marker(kernel), PREFLIGHT, HEADER]
            and lines[-1] == END, 'performance policy/population/completion mismatch')
    rows, cursor = [], 3
    for bits in (128, 192, 256):
        for owner in ('raw', 'cached'):
            for operation in OPERATIONS:
                values = {'portable': [], 'accelerated': []}
                for sample in range(SAMPLES):
                    order = ('portable', 'accelerated') if sample % 2 == 0 else ('accelerated', 'portable')
                    for backend in order:
                        fields = lines[cursor].split()
                        cursor += 1
                        require(len(fields) == 7 and fields[:6] == ['SAMPLE', str(bits), owner, operation, str(sample), backend]
                                and re.fullmatch(r'[1-9][0-9]{0,18}', fields[6]), 'invalid performance sample identity or duration')
                        values[backend].append(int(fields[6]))
                for backend in values:
                    samples = values[backend]
                    rows.append({'bits': bits, 'owner': owner, 'operation': operation, 'backend': backend,
                                 'samples_ns': samples, 'median_ns_per_operation': statistics.median(samples) / BATCH,
                                 'min_ns_per_operation': min(samples) / BATCH, 'max_ns_per_operation': max(samples) / BATCH})
    return rows


def execute(command, directory, env, artifacts, label):
    packaged.archives.cargo_environment.check(directory, env)
    try:
        result = subprocess.run(command, cwd=directory, env=env, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired as error:
        def decode(value):
            return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
        (artifacts / (label + '.json')).write_text(json.dumps({'command': command, 'timeout': True,
            'stdout': decode(error.stdout), 'stderr': decode(error.stderr)}, indent=2) + '\n')
        raise
    (artifacts / (label + '.json')).write_text(json.dumps({'command': command, 'returncode': result.returncode,
        'stdout': result.stdout, 'stderr': result.stderr}, indent=2) + '\n')
    require(result.returncode == 0, label + ' failed: ' + result.stdout[-1500:] + result.stderr[-1500:])
    return result


def collect(binary, directory, env, artifacts, kernel='X86AesNi'):
    def read(path):
        source = Path(path)
        return source.read_text() if source.is_file() else 'unavailable'
    with measurement_affinity() as cpu:
        host = apple_host_info() if cpu is None else {'platform': platform.platform(), 'machine': platform.machine(), 'logical_cpu': cpu,
            'cpuinfo': read('/proc/cpuinfo'), 'load_before': list(os.getloadavg()),
            'governor': read(f'/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor'),
            'siblings': read(f'/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list'),
            'boost': read('/sys/devices/system/cpu/cpufreq/boost')}
        host['policy'] = '9 samples of 64 operations; 8 warmup batches; alternating pair order; all samples retained; no threshold or retries'
        (artifacts / 'host.json').write_text(json.dumps(host, indent=2) + '\n')
        result = execute([str(binary), '--measure'], directory, env, artifacts, 'measure')
        require(not result.stderr, 'unexpected performance measurement diagnostics')
        rows = parse(result.stdout, kernel)
        (artifacts / 'summary.json').write_text(json.dumps(rows, indent=2, allow_nan=False) + '\n')
    print('AES_PERFORMANCE_OBSERVED: 48 cases; 432 retained samples; no speed or side-channel verdict', flush=True)


def check(compiler, route, observation=None):
    require(compiler in ('1.90.0', '1.99.1') and route in ('direct', 'facade'), 'unreviewed performance configuration')
    require(observation is None or re.fullmatch(r'[a-z0-9][a-z0-9-]{0,79}', observation), 'invalid observation name')
    target, flags, kernel = native_configuration(platform.system(), platform.machine())
    for name in REJECT:
        require(name not in os.environ, 'remove ambient ' + name)
    base = ROOT / 'target/aes-performance'
    base.mkdir(parents=True, exist_ok=True)
    if observation is None:
        artifacts = Path(tempfile.mkdtemp(prefix=f'check-{compiler}-{route}-', dir=base))
    else:
        artifacts = base / observation
        artifacts.mkdir()  # Never overwrite or implicitly repeat an observation.
    print(f'Artifacts: {artifacts}', flush=True)
    with packaged.archives.cargo_environment.private_directory(ROOT) as temporary:
        root = Path(temporary)
        env = packaged.archives.isolated_env(root)
        versions = packaged.package_sources(root, env)
        directory = root / 'consumers/aes'
        (directory / 'src/bin').mkdir(parents=True)
        for filename, destination in (('lib.rs', 'src/lib.rs'), ('performance.rs', 'src/bin/performance.rs')):
            source = ROOT / 'assurance/aes-accelerated-campaigns' / filename
            require(source.is_file() and not any(p.is_symlink() for p in (source, *source.parents)), 'missing/symlinked performance fixture')
            shutil.copyfile(source, directory / destination)
        (directory / 'Cargo.toml').write_text(manifest(versions, route))
        cargo = ['cargo', '+' + compiler]
        selection = ['--locked', '--offline', '--no-default-features', '--features', route]
        execute(cargo + ['generate-lockfile', '--offline'], directory, env, artifacts, 'lock')
        metadata = execute(cargo + ['metadata', '--format-version=1', '--filter-platform', target, *selection], directory, env, artifacts, 'metadata')
        campaign.graph(json.loads(metadata.stdout), versions, directory, route, 'static')
        probe = root / 'probe'
        execute(['rustc', '+' + compiler, '--edition=2024', str(ROOT / 'assurance/aes-kernel-candidate/probe.rs'),
                 '--target', target, '-o', str(probe)], directory, env, artifacts, 'probe-build')
        observed = execute([str(probe)], directory, env, artifacts, 'probe')
        require(not observed.stderr and observed.stdout.splitlines() == ['AES_STATIC_HOST_BUNDLE_PASS'], 'ISA probe failed')
        env['RUSTFLAGS'] = flags
        tests = execute(cargo + ['test', *selection, '--target', target, '--release', '--bin', 'performance', '--', '--test-threads=1'], directory, env, artifacts, 'tests')
        check_tests(tests.stdout)
        print(tests.stdout, end='', flush=True)
        execute(cargo + ['build', *selection, '--target', target, '--release', '--bin', 'performance'], directory, env, artifacts, 'build')
        built = Path(env['CARGO_TARGET_DIR']) / target / 'release/performance'
        binary = artifacts / 'performance'
        shutil.copy2(built, binary)
        before = hashlib.sha256(binary.read_bytes()).hexdigest()
        require(hashlib.sha256(built.read_bytes()).hexdigest() == before, 'retained performance binary differs from build')
        compiler_info = execute(['rustc', '+' + compiler, '-vV'], directory, env, artifacts, 'compiler').stdout
        (artifacts / 'identity.json').write_text(json.dumps({'compiler': compiler_info, 'route': route,
            'admission': 'static', 'target': target, 'profile': PROFILE, 'kernel': kernel,
            'binary_sha256': before, 'flags': env['RUSTFLAGS'], 'versions': versions,
            'archive_sha256': {name: hashlib.sha256((root / f'target/package/{name}-{version}.crate').read_bytes()).hexdigest()
                               for name, version in versions.items()},
            'fixture_sha256': hashlib.sha256((directory / 'src/bin/performance.rs').read_bytes()).hexdigest(),
            'observation': observation, 'source': 'byte-checked working-tree archives; not a clean tagged release'}, indent=2) + '\n')
        result = execute([str(binary), '--check'], directory, env, artifacts, 'preflight')
        require(not result.stderr, 'unexpected preflight diagnostics')
        preflight(result.stdout, kernel)
        if observation is not None:
            collect(binary, directory, env, artifacts, kernel)
        require(hashlib.sha256(binary.read_bytes()).hexdigest() == before, 'performance binary changed')
    print(f'AES_PERFORMANCE_FIXTURE_PASS: {compiler} {route}; 4 tests; 48 cases; correctness only', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=('1.90.0', '1.99.1'), required=True)
    parser.add_argument('--route', choices=('direct', 'facade'), required=True)
    parser.add_argument('--observation', help='Explicitly measure once into this new observation directory; no automatic retries')
    args = parser.parse_args()
    try:
        check(args.toolchain, args.route, args.observation)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'AES performance FAIL: {error}', flush=True)
        raise SystemExit(2) from error
