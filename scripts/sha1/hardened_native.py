"""Host-qualified hardened SHA-1 capture checks; no machine-erasure claim."""
import importlib.util
import os
import re
import sys
from pathlib import Path
import hardened_policy as policy

spec = importlib.util.spec_from_file_location('sha1_native_host', Path(__file__).with_name('capture-sha1-cpu-native.py'))
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)
LANES = host.LANES
RESULTS = {'hosted', 'portable', 'static', 'packaged', 'codegen'}


def clean_environment():
    env = dict(os.environ, RUSTUP_TOOLCHAIN='1.98.1')
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET',
                'CARGO_PROFILE_RELEASE_PANIC', 'CARGO_PROFILE_RELEASE_OPT_LEVEL'):
        env.pop(key, None)
    env.pop('BRYNJA_REQUIRE_HARDENED_SHA1', None)
    return env


def require(condition, message):
    if not condition: raise ValueError('hardened SHA-1 native evidence: '+message)


def validate_results(results, lane):
    require(set(results) == RESULTS, 'result inventory')
    require(all(isinstance(v, str) and 0 < len(v) <= 2_000_000 for v in results.values()), 'bounded transcripts')
    kernel = 'legacy-x86-sha1' if LANES[lane] == 'x86' else 'legacy-aarch64-sha1'
    for key in ('portable', 'static'):
        require(re.search(r'^test result: ok\. 4 passed; 0 failed;', results[key], re.M), key+' API coverage')
    require(f'HARDENED_SHA1_EXECUTION: {kernel}; blocks=512' in results['static'].splitlines(), 'actual 512-block kernel')
    require(f'SHA1_HARDENED_OPERATIONAL: {kernel}; actual hardened startup and digest passed' in results['static'].splitlines(), 'static route')
    selected = 'portable' if LANES[lane] == 'x86' else kernel
    require('SHA1_HOSTED_HARDENED: '+selected in results['hosted'].splitlines(), 'hosted route')
    require(re.search(r'^test result: ok\. 1 passed; 0 failed;', results['hosted'], re.M), 'hosted tests')
    for token in ('Independent hardened SHA-1 oracle: 1135 bit messages, public and secret destinations',
                  'Packaged hardened ownership/classification negatives: 24 rejected',
                  'Hardened output/quarantine/padding compiled mutants: 10 rejected',
                  'Compiled source-owner and scratch cleanup removals: 10 rejected'):
        require(token in results['packaged'].splitlines(), 'packaged '+token)
    target = 'x86_64-unknown-linux-gnu' if LANES[lane] == 'x86' else 'aarch64-apple-darwin' if lane == 'apple-m2-aarch64' else 'aarch64-unknown-linux-gnu'
    require(f'Hardened SHA-1 MIR/LLVM/assembly: PASS; 1.98.1; {target}; seven owned regions; no register-erasure claim' in results['codegen'].splitlines(), 'native compiler cleanup')


def collect(lane, features, env):
    test = ['cargo', '+1.98.1', 'test', '--locked', '--offline', '--release']
    ending = ['--', '--nocapture', '--test-threads=1']
    results = {}
    results['hosted'] = host.run(test+['-p', 'brynja-legacy-sha1-std', '--features', 'runtime-hardened-execution', '--test', 'hardened_execution']+ending, env)
    results['portable'] = host.run(test+['-p', 'brynja-legacy-sha1', '--features', 'hardened-execution', '--test', 'hardened_execution']+ending, env)
    static = dict(env, RUSTFLAGS='-C target-feature='+features, BRYNJA_REQUIRE_HARDENED_SHA1='1')
    results['static'] = host.run(test+['-p', 'brynja-legacy-sha1', '--features', 'hardened-execution', '--lib', '--test', 'hardened_execution']+ending, static)
    results['packaged'] = host.run([sys.executable, 'scripts/sha1/check-sha1-package.py', '--hardened'], static)
    target = 'x86_64-unknown-linux-gnu' if LANES[lane] == 'x86' else 'aarch64-apple-darwin' if lane == 'apple-m2-aarch64' else 'aarch64-unknown-linux-gnu'
    results['codegen'] = host.run([sys.executable, 'scripts/sha1/check-sha1-hardened-codegen.py', '--compiler', '1.98.1', '--target', target], env)
    validate_results(results, lane)
    return results
