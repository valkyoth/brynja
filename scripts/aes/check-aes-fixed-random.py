#!/usr/bin/env python3
"""Predeclared packaged AES fixed/random host observation; never retry-to-pass."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import statistics
import subprocess

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('aes_fixed_random_packages', HERE / 'check-aes-packaged.py')
packaged = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packaged)
oracle = packaged.module('aes_fixed_random_oracle', HERE / 'check-aes-differential.py')
ROOT = packaged.ROOT
FIXTURE = ROOT / 'assurance/aes-fixed-random/timing.rs'
SAMPLES, REPEAT, WARMUP, LIMIT, MAX_CV = 8192, 4, 256, 4.5, 1.0
SEED = 0x0272_f17e_d00d_0001
MASK = (1 << 64) - 1
MODES = ('encrypt-key', 'encrypt-block', 'decrypt-key', 'decrypt-block', 'public-key', 'public-block')
CAMPAIGNS = tuple((bits, owner, mode) for bits in (128, 192, 256)
                  for owner in ('ephemeral', 'cached', 'cached-import')
                  for mode in (('import-key',) if owner == 'cached-import' else MODES))
HEADER = f'AES_FIXED_RANDOM_POLICY {SAMPLES} {REPEAT} {WARMUP} {SEED}'
MARKER = 'AES fixed/random: 39 campaigns; 8192 pairs; 4 repetitions; zero alarms; noise policy satisfied'
PROFILE = 'opt3-fat-lto-cgu1-overflow-abort'
TESTS = {'tests::public_generator_and_population_are_stable',
         'tests::classes_vary_only_the_declared_field',
         'tests::all_routes_produce_one_block_and_match_cached',
         'tests::malformed_configurations_fail_before_measurement'}
require = packaged.require


def corpus(campaign):
    state = SEED ^ campaign

    def next_word():
        nonlocal state
        state = (state + 0x9e3779b97f4a7c15) & MASK
        z = ((state ^ (state >> 30)) * 0xbf58476d1ce4e5b9) & MASK
        z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & MASK
        return z ^ (z >> 31)

    for _ in range(WARMUP + SAMPLES):
        key = b''.join(next_word().to_bytes(8, 'little') for _ in range(4))
        block = b''.join(next_word().to_bytes(8, 'little') for _ in range(2))
        yield key, block, next_word() & 1


def inputs(case, bits, mode, cls):
    key, block, _ = case
    return ((bytes(bits // 8) if cls == 0 else key[:bits // 8]) if mode.endswith('-key')
            else bytes([0x37]) * (bits // 8),
            (bytes(16) if cls == 0 else block) if mode.endswith('-block') else bytes([0x37]) * 16)


def preflight(output, executable, env):
    expected = [HEADER]
    for campaign, (bits, owner, mode) in enumerate(CAMPAIGNS):
        cases = list(corpus(campaign))
        for sample in (0, SAMPLES // 2, SAMPLES - 1):
            for cls in (0, 1):
                key, block = inputs(cases[WARMUP + sample], bits, mode, cls)
                result = subprocess.run([str(executable), 'enc', f'-aes-{bits}-ecb', '-nopad', '-nosalt',
                                         '-K', key.hex(), '-d' if mode.startswith('decrypt-') else '-e'],
                                        input=block, env=env, capture_output=True, timeout=15)
                require(result.returncode == 0 and not result.stderr and len(result.stdout) == 16,
                        'fixed/random independent oracle failed')
                expected.append(f'VECTOR {bits} {owner} {mode} {sample} {cls} {result.stdout.hex()}')
    require(output.splitlines() == expected + ['AES_FIXED_RANDOM_END preflight'],
            'fixed/random operation/corpus preflight mismatch')


def screen(pairs):
    require(len(pairs) == SAMPLES and all(type(n) is int and 0 < n < 10**19 for p in pairs for n in p)
            and all(len(p) == 2 for p in pairs), 'invalid fixed/random sample population')
    fixed, random = zip(*pairs)
    means = [statistics.mean(x) for x in (fixed, random)]
    variances = [statistics.variance(x) for x in (fixed, random)]
    differences = [a - b for a, b in pairs]

    def score(delta, denominator_squared):
        if denominator_squared == 0:
            # JSON has no infinity; report a separate singular-signal flag.
            return None, delta != 0
        value = abs(delta) / math.sqrt(denominator_squared)
        return value, value >= LIMIT

    welch, w_signal = score(means[0] - means[1], sum(variances) / SAMPLES)
    paired, p_signal = score(statistics.mean(differences), statistics.variance(differences) / SAMPLES)
    cv = [math.sqrt(v) / m for v, m in zip(variances, means)]
    return {'mean_ns': means, 'max_ns': [max(fixed), max(random)], 'cv': cv,
            'welch_abs_t': welch, 'paired_abs_t': paired,
            'alarm': w_signal or p_signal,
            'inconclusive': any(v == 0 for v in variances) or any(c > MAX_CV for c in cv)}


def parse(output):
    lines = output.splitlines()
    require(len(lines) == len(CAMPAIGNS) * SAMPLES + 2 and lines[0] == HEADER
            and lines[-1] == 'AES_FIXED_RANDOM_END measure', 'fixed/random policy/population/completion mismatch')
    rows, cursor = [], 1
    for campaign, (bits, owner, mode) in enumerate(CAMPAIGNS):
        cases = list(corpus(campaign))[WARMUP:]
        pairs = []
        for sample, case in enumerate(cases):
            fields = lines[cursor].split()
            cursor += 1
            require(len(fields) == 8 and fields[:6] ==
                    ['SAMPLE', str(bits), owner, mode, str(sample), str(case[2])],
                    'fixed/random sample identity/order mismatch')
            require(all(re.fullmatch(r'[1-9][0-9]{0,18}', value) for value in fields[6:]),
                    'invalid fixed/random duration')
            pairs.append(tuple(int(value) for value in fields[6:]))
        rows.append({'bits': bits, 'owner': owner, 'mode': mode, **screen(pairs)})
    return rows


def finish(output):
    rows = parse(output)
    alarms = sum(row['alarm'] for row in rows)
    inconclusive = sum(row['inconclusive'] for row in rows)
    print(json.dumps({'campaigns': rows, 'alarms': alarms, 'inconclusive': inconclusive}, allow_nan=False), flush=True)
    require(not alarms and not inconclusive,
            'fixed/random alarm or inconclusive noise: retain samples and investigate; do not retry-to-pass')
    print(MARKER, flush=True)


def prepare(directory):
    require(FIXTURE.is_file() and not FIXTURE.is_symlink() and not any(p.is_symlink() for p in FIXTURE.parents),
            'missing or symlinked fixed/random fixture')
    target = directory / 'src/bin/fixed-random.rs'
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURE, target)
    manifest = directory / 'Cargo.toml'
    text = manifest.read_text()
    old = '[profile.release]\noverflow-checks=true\n'
    require(text.count(old) == 1, 'packaged release profile changed')
    manifest.write_text(text.replace(old, old + 'opt-level=3\nlto="fat"\ncodegen-units=1\npanic="abort"\n'))


def check_tests(output):
    rows = re.findall(r'^test (\S+) \.\.\. (\S+)\s*$', output, re.M)
    require(len(rows) == 4 and {name for name, _ in rows} == TESTS and all(s == 'ok' for _, s in rows),
            'fixed/random harness tests missing/failed/ignored')
    summaries = re.findall(r'^test result: .*$', output, re.M)
    require(len(summaries) == 1 and summaries[0].startswith(
        'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'), 'wrong harness summary')


def host_info(cpu):
    def read(path):
        path = Path(path)
        return path.read_text().strip() if path.is_file() else 'unavailable'
    return {'platform': platform.platform(), 'machine': platform.machine(), 'logical_cpu': cpu,
            'cpuinfo': read('/proc/cpuinfo'),
            'governor': read(f'/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor'),
            'siblings': read(f'/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list'),
            'boost': read('/sys/devices/system/cpu/cpufreq/boost'),
            'load_before': list(os.getloadavg())}


def collect(binary, env, executable):
    for phase in ('preflight', 'measure'):
        try:
            result = subprocess.run([str(binary), phase], env=env, cwd=ROOT,
                                    capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired as error:
            partial = error.stdout or ''
            if isinstance(partial, bytes):
                partial = partial.decode(errors='replace')
            print(partial, end='', flush=True)
            raise ValueError('fixed/random timeout; partial samples retained; no pass') from error
        print(result.stdout, end='', flush=True)
        require(result.returncode == 0 and not result.stderr, 'fixed/random process failed: ' + result.stderr[-2000:])
        if phase == 'preflight':
            preflight(result.stdout, executable, env)
            print('Independent AES fixed/random preflight: PASS', flush=True)
        else:
            finish(result.stdout)


def check(compiler):
    require(compiler in packaged.consumer.TOOLCHAINS, 'unsupported fixed/random compiler')
    require(platform.system() == 'Linux' and platform.machine() in ('x86_64', 'aarch64'),
            'requires native Linux x86_64 or AArch64; no emulator runner')
    for name in (*packaged.archives.REJECT_ENV, 'PYTHONOPTIMIZE', 'PYTHONPATH'):
        require(name not in os.environ, 'remove ambient ' + name)
    executable = oracle.select(os.environ)
    before = oracle.digest(executable)
    target = platform.machine() + '-unknown-linux-gnu'
    with packaged.archives.cargo_environment.private_directory(ROOT) as temporary:
        root = Path(temporary)
        env = packaged.archives.isolated_env(root)
        env['OPENSSL_CONF'] = '/dev/null'
        oracle.preflight(executable, env)
        versions = packaged.package_sources(root, env)
        directory = root / 'consumers/aes'
        packaged.prepare(directory, versions)
        prepare(directory)
        cargo = ['cargo', '+' + compiler]
        packaged.archives.run(cargo + ['generate-lockfile', '--offline'], directory, env)
        selection = ['--locked', '--offline', '--no-default-features', '--features', 'direct']
        metadata = packaged.archives.run(cargo + ['metadata', '--format-version=1', *selection,
                                                 '--filter-platform', target], directory, env)
        packaged.graph(json.loads(metadata.stdout), 'direct', directory, root / 'unpacked', versions)
        result = packaged.archives.run(cargo + ['test', *selection, '--bin', 'fixed-random', '--target', target], directory, env)
        print(result.stdout, end='', flush=True)
        check_tests(result.stdout)
        packaged.archives.run(cargo + ['build', *selection, '--release', '--bin', 'fixed-random', '--target', target], directory, env)
        binary = Path(env['CARGO_TARGET_DIR']) / target / 'release/fixed-random'
        binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
        affinity = os.sched_getaffinity(0)
        cpu = min(affinity)
        print(json.dumps({'kind': 'AES-fixed-random-native-observation', 'host': host_info(cpu),
                          'compiler': packaged.archives.run(['rustc', '+' + compiler, '-vV'], directory, env).stdout,
                          'target': target, 'profile': PROFILE, 'binary_sha256': binary_hash,
                          'oracle': str(executable), 'oracle_sha256': before,
                          'pairs': SAMPLES, 'repeat': REPEAT, 'warmup': WARMUP, 'seed': SEED,
                          'threshold': LIMIT, 'maximum_cv': MAX_CV,
                          'policy': 'no rejection/cropping/adaptive stopping/retry-to-pass'}), flush=True)
        try:
            os.sched_setaffinity(0, {cpu})
            collect(binary, env, executable)
        finally:
            os.sched_setaffinity(0, affinity)
        require(oracle.digest(executable) == before and hashlib.sha256(binary.read_bytes()).hexdigest() == binary_hash,
                'fixed/random executable identity changed')
    print(f'AES fixed/random completed: {compiler}; native {target}; {PROFILE}', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=packaged.consumer.TOOLCHAINS, required=True)
    check(parser.parse_args().toolchain)
