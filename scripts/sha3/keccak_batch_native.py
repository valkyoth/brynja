"""Self-attested ordinary multibuffer native evidence, not backend certification."""
import os
from pathlib import Path
import platform
import re
import keccak_batch_codegen as command
import keccak_batch_policy as policy

LANES = ('amd-x86_64', 'intel-x86_64', 'aws-aarch64', 'apple-m2-aarch64')
RESULTS = {'hosted', 'portable', 'vector', 'oracle_portable', 'oracle_prefer',
           'oracle_required', 'packaged', 'codegen', 'benchmark'}
ALGORITHMS = {'Sha3_224': (144, 224), 'Sha3_256': (136, 256), 'Sha3_384': (104, 384),
              'Sha3_512': (72, 512), 'Shake128': (168, 4099), 'Shake256': (136, 4099),
              'Cshake128': (168, 4099), 'Cshake256': (136, 4099)}


def benchmark_check(text, kernel, width):
    expected = {(name, size, lanes) for name, (rate, _) in ALGORITHMS.items()
                for size in (0, rate, 4096, 16384) for lanes in range(1, 5)}
    seen, total = set(), 0
    lines = text.splitlines()
    for line in lines[:-1]:
        match = re.fullmatch(r'KECCAK_BATCH_BENCH: algorithm=(\w+); bytes_max=(\d+); lanes=(\d+); output_bits=(\d+); mode=Prefer; kernel=Some\(' + kernel +
            r'\); samples=7; portable_median_ns=([1-9][0-9]*); selected_median_ns=([1-9][0-9]*); vector_calls=(\d+)', line)
        if not match: raise ValueError('invalid benchmark row')
        name, size, lanes, bits, _, _, calls = match.groups()
        key = (name, int(size), int(lanes))
        if key not in expected or key in seen or int(bits) != ALGORITHMS[name][1]: raise ValueError('benchmark coverage/identity')
        if (int(lanes) < width) != (int(calls) == 0): raise ValueError('benchmark vector route')
        seen.add(key)
        total += int(calls)
    if seen != expected or not total or lines[-1] != f'KECCAK_BATCH_BENCHMARK: PASS; cases=128; vector_calls={total}; threshold=caller-selected; public-only':
        raise ValueError('native comparative benchmark incomplete')


def host(lane):
    if lane not in LANES: raise ValueError('unknown native lane')
    machine, system = platform.machine().lower(), platform.system()
    if lane.endswith('x86_64'):
        if machine != 'x86_64' or system != 'Linux': raise ValueError('native Linux x86_64 required')
        cpu = Path('/proc/cpuinfo').read_text()
        vendor = 'AuthenticAMD' if lane.startswith('amd') else 'GenuineIntel'
        rows = [set(line.split(':', 1)[1].split()) for line in cpu.splitlines() if line.startswith('flags')]
        vendors = [line.split(':', 1)[1].strip() for line in cpu.splitlines() if line.startswith('vendor_id')]
        if not vendors or not all(value == vendor for value in vendors) or not rows or not all({'avx', 'avx2'} <= row for row in rows):
            raise ValueError('enumerated CPU vendor/AVX2 bundle incomplete')
        return vendor, '+avx,+avx2'
    if machine not in ('arm64', 'aarch64'): raise ValueError('native Arm64 required')
    if lane == 'apple-m2-aarch64':
        if system != 'Darwin': raise ValueError('Darwin required')
        cpu = command.run(['sysctl', '-n', 'machdep.cpu.brand_string']).strip()
        if 'Apple M2' not in cpu or command.run(['sysctl', '-n', 'hw.optional.neon']).strip() != '1':
            raise ValueError('Apple M2/NEON required')
        return cpu, '+neon'
    if system != 'Linux': raise ValueError('native Linux Arm required')
    rows = [set(line.split(':', 1)[1].split()) for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('Features')]
    if not rows or not all('asimd' in row for row in rows): raise ValueError('enumerated NEON bundle incomplete')
    return 'operator-labelled AWS Arm; provider identity not authenticated', '+neon'


def environment(features=None):
    env = dict(os.environ, RUSTUP_TOOLCHAIN='1.98.1')
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
        env.pop(key, None)
    if features is not None: env['RUSTFLAGS'] = '-C target-feature=' + features
    return env


def validate(record, sources):
    keys = {'schema', 'version', 'lane', 'commit', 'compiler', 'cpu', 'system', 'features',
            'source_sha512', 'results', 'native', 'profile', 'independent_review', 'fips_validated', 'migration_safety'}
    if set(record) != keys or type(record['schema']) is not int or record['schema'] != 1 or record['version'] != '0.24.47':
        raise ValueError('native record schema')
    lane = record['lane']
    if lane not in LANES or not re.fullmatch('[0-9a-f]{40}', record['commit']): raise ValueError('native lane/commit')
    arm = not lane.endswith('x86_64')
    kernel, width = ('Neon', 2) if arm else ('Avx2', 4)
    system = 'Darwin' if lane == 'apple-m2-aarch64' else 'Linux'
    target = 'aarch64-apple-darwin' if system == 'Darwin' else ('aarch64' if arm else 'x86_64') + '-unknown-linux-gnu'
    if record['system'] != system or record['features'] != ('+neon' if arm else '+avx,+avx2'):
        raise ValueError('native platform bundle')
    compiler = record['compiler'].splitlines()
    if 'release: 1.98.1' not in compiler or 'host: ' + target not in compiler or not record['cpu']:
        raise ValueError('native compiler/CPU identity')
    if record['source_sha512'] != sources: raise ValueError('native source closure changed')
    if (record['native'] != 'operator-self-attested' or record['profile'] != 'ordinary-public-only'
            or record['independent_review'] is not False or record['fips_validated'] is not False
            or record['migration_safety'] != 'deployment obligation; not independently proven'):
        raise ValueError('native evidence overclaim')
    results = record['results']
    if set(results) != RESULTS or any(not isinstance(text, str) or not text for text in results.values()):
        raise ValueError('native results incomplete')
    for key in ('hosted', 'portable', 'vector'):
        if not re.search(r'test result: ok\. [1-9][0-9]* passed; 0 failed;', results[key]):
            raise ValueError('native tests absent: ' + key)
    for marker in (f'KECCAK_BATCH_NATIVE: {kernel}; calls=1024; width={width}', f'KECCAK_BATCH_API: {kernel}; comparisons=512'):
        if marker not in results['vector'].splitlines(): raise ValueError('actual native kernel execution absent')
    for mode in ('portable', 'prefer', 'required'):
        pattern = f'Keccak batch: 1024 independent outputs and six malformed requests PASS; mode={mode}; vector_calls=([0-9]+)'
        matches = re.findall(pattern, results['oracle_' + mode])
        if len(matches) != 1 or (mode == 'portable' and int(matches[0]) != 0) or (mode != 'portable' and int(matches[0]) == 0):
            raise ValueError('native oracle/route incomplete')
    if "Packaged Keccak batch: 23 negatives, 10 compiled mutants rejected; modes=('portable', 'prefer', 'required')" not in results['packaged'].splitlines():
        raise ValueError('native package coverage incomplete')
    if 'Packaged Keccak batch: one compiled scalar-only false-route mutant rejected' not in results['packaged'].splitlines():
        raise ValueError('native actual-route regression absent')
    if f'Keccak independent SIMD codegen: PASS; 1.98.1; {target}' not in results['codegen'].splitlines():
        raise ValueError('native codegen absent')
    benchmark_check(results['benchmark'], kernel, width)
