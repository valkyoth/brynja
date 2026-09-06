#!/usr/bin/env python3
"""Collect non-authorizing, hostname-free native SHA-1 candidate observations."""
import argparse
import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path
import cpu_policy as policy

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
        if vendor not in info or not flags or not all({'sha_ni','sse2'} <= set(row) for row in flags):
            raise ValueError('every enumerated CPU must expose the exact vendor/feature bundle')
        return vendor, '+sse2,+sha'
    if machine not in ('aarch64','arm64'): raise ValueError('wrong native architecture')
    if lane == 'apple-m2-aarch64':
        brand = run(['sysctl','-n','machdep.cpu.brand_string'])
        if 'Apple M2' not in brand: raise ValueError('lane requires Apple M2')
        for flag in ('hw.optional.neon','hw.optional.arm.FEAT_SHA1','hw.optional.arm.FEAT_SHA256'):
            if run(['sysctl','-n',flag]) != '1': raise ValueError('missing '+flag)
        return brand, '+neon,+sha2'
    flags = [line.split(':',1)[1].split() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('Features')]
    if not flags or not all({'asimd','sha1','sha2'} <= set(row) for row in flags):
        raise ValueError('every enumerated Arm CPU must expose asimd/sha1/sha2')
    return 'operator-labelled AWS Arm; provider identity not authenticated', '+neon,+sha2'

def capture(args):
    policy.validate()
    if run(['git','status','--porcelain']): raise ValueError('capture requires a clean committed candidate')
    if args.output.exists(): raise ValueError('refusing to overwrite existing evidence')
    commit = run(['git','rev-parse','HEAD'])
    hashes = {p:hashlib.sha256((policy.ROOT/p).read_bytes()).hexdigest() for p in policy.BOUND}
    cpu, features = host(args.lane)
    compiler = run(['rustc','+1.98.1','--version','--verbose'])
    env = dict(os.environ,RUSTFLAGS=f'--cfg brynja_cpu_evidence -C target-feature={features}')
    env.pop('CARGO_ENCODED_RUSTFLAGS',None)
    transcript = run(['cargo','+1.98.1','run','--locked','--offline','--release','--manifest-path',
                      'assurance/sha1-cpu-public-api/Cargo.toml','--','--benchmark'],env)
    backend = 'legacy-x86-sha1' if LANES[args.lane] == 'x86' else 'legacy-aarch64-sha1'
    required = ('SHA-1 CPU acceptance: PASS', 'frozen_cases=20; nist_vectors=529', 'candidate=unadmitted', 'backend='+backend)
    if not all(token in transcript for token in required): raise ValueError('incomplete acceptance output')
    if run(['git','status','--porcelain']) or run(['git','rev-parse','HEAD']) != commit:
        raise ValueError('candidate changed during capture')
    policy.validate()
    if hashes != {p:hashlib.sha256((policy.ROOT/p).read_bytes()).hexdigest() for p in policy.BOUND}:
        raise ValueError('capture source changed')
    document = dict(schema=1, milestone='0.24.21', lane=args.lane, commit=commit,
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
