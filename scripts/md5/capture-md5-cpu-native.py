#!/usr/bin/env python3
"""Collect non-authorizing, hostname-free native MD5 candidate observations."""
import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
from pathlib import Path
import md5_cpu_policy as policy

LANES = {'amd-x86_64':'x86', 'intel-x86_64':'x86', 'apple-m2-aarch64':'arm', 'aws-aarch64':'arm'}

def run(command,env=None):
    result = subprocess.run(command,cwd=policy.ROOT,env=env,text=True,capture_output=True,timeout=600)
    if result.returncode:
        raise RuntimeError(f'{command[0]} failed: {result.stderr[-6000:]}\n{result.stdout[-2000:]}')
    if len(result.stdout) > 2_000_000: raise ValueError('capture output exceeds bound')
    return result.stdout.strip()

def host(lane):
    machine = platform.machine().lower()
    if LANES[lane] == 'x86':
        if machine not in ('x86_64','amd64'): raise ValueError('wrong native architecture')
        info = Path('/proc/cpuinfo').read_text()
        vendor = 'AuthenticAMD' if lane == 'amd-x86_64' else 'GenuineIntel'
        flags = [line.split(':',1)[1].split() for line in info.splitlines() if line.startswith('flags')]
        if vendor not in info or not flags or not all({'avx2'} <= set(row) for row in flags):
            raise ValueError('every enumerated CPU must expose the exact vendor/feature bundle')
        return vendor, '+avx2'
    if machine not in ('aarch64','arm64'): raise ValueError('wrong native architecture')
    if lane == 'apple-m2-aarch64':
        brand = run(['sysctl','-n','machdep.cpu.brand_string'])
        if 'Apple M2' not in brand: raise ValueError('lane requires Apple M2')
        for flag in ('hw.optional.neon',):
            if run(['sysctl','-n',flag]) != '1': raise ValueError('missing '+flag)
        return brand, '+neon'
    flags = [line.split(':',1)[1].split() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('Features')]
    if not flags or not all({'asimd'} <= set(row) for row in flags):
        raise ValueError('every enumerated Arm CPU must expose asimd')
    return 'operator-labelled AWS Arm; provider identity not authenticated', '+neon'

def validate_benchmarks(transcript, width):
    pattern = re.compile(r'benchmark: bytes=(64|1024|16384) active=(1|4|8) samples=32 scalar_ns=([0-9]{1,20}) selected_ns=([0-9]{1,20}) vector_blocks=([0-9]{1,6})')
    expected = {(length, active) for length in (64,1024,16384) for active in (1,4,8)}
    observed = set()
    for line in transcript.splitlines():
        if not line.startswith('benchmark:'): continue
        match = pattern.fullmatch(line)
        if match is None: raise ValueError('malformed bounded benchmark record')
        length, active, scalar, selected, blocks = map(int,match.groups())
        if (length,active) in observed or not scalar or not selected:
            raise ValueError('duplicate or empty benchmark measurement')
        if blocks != (active // width) * width * (length // 64):
            raise ValueError('benchmark vector-work accounting differs')
        observed.add((length,active))
    if observed != expected: raise ValueError('incomplete native benchmark matrix')

def capture(args):
    policy.validate()
    if run(['git','status','--porcelain']): raise ValueError('capture requires a clean committed candidate')
    if args.output.exists(): raise ValueError('refusing to overwrite existing evidence')
    commit = run(['git','rev-parse','HEAD'])
    hashes = {p:hashlib.sha256((policy.ROOT/p).read_bytes()).hexdigest() for p in policy.BOUND}
    cpu, features = host(args.lane)
    compiler = run(['rustc','+1.98.1','--version','--verbose'])
    env = dict(os.environ,RUSTFLAGS=f'--cfg brynja_md5_cpu_evidence -C target-feature={features}')
    env.pop('CARGO_ENCODED_RUSTFLAGS',None)
    transcript = run(['cargo','+1.98.1','run','--locked','--offline','--release','--manifest-path',
                      'assurance/md5-cpu-public-api/Cargo.toml','--','--benchmark'],env)
    backend = 'legacy-x86_64-avx2-md5' if LANES[args.lane] == 'x86' else 'legacy-aarch64-neon-md5'
    required = ('MD5 CPU acceptance: PASS', 'frozen_cases=20; batch_comparisons=936; lane_permutations=16', 'candidate=unadmitted', 'backend='+backend)
    if not all(token in transcript for token in required): raise ValueError('incomplete acceptance output')
    validate_benchmarks(transcript,8 if LANES[args.lane]=='x86' else 4)
    if run(['git','status','--porcelain']) or run(['git','rev-parse','HEAD']) != commit:
        raise ValueError('candidate changed during capture')
    policy.validate()
    if hashes != {p:hashlib.sha256((policy.ROOT/p).read_bytes()).hexdigest() for p in policy.BOUND}:
        raise ValueError('capture source changed')
    document = dict(schema=1, milestone='0.24.22', lane=args.lane, commit=commit,
                    compiler=compiler, cpu=cpu, system=platform.system(), features=features,
                    source_sha256=hashes,
                    acceptance=transcript, native='operator-self-attested', admission='unadmitted',
                    migration_safety='unproven', side_channel_review='pending', hardened='portable-only',
                    independent_review=False, fips_validated=False)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x') as output: json.dump(document,output,indent=2); output.write('\n')
    print(f'Wrote {args.output}; no hostname; self-attested observation, not admission')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('lane',choices=LANES)
    parser.add_argument('output',type=Path)
    capture(parser.parse_args())

if __name__ == '__main__': main()
