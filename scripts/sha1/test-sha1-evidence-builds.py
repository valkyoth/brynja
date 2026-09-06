#!/usr/bin/env python3
"""Prove ordinary dependency builds reject leaked cfgs and unified features."""
import argparse
import os
import platform
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--compiler')
    args = parser.parse_args()
    machine = platform.machine().lower()
    target_features = ('+sha,+sse2' if machine in ('amd64','x86_64','i686','i386')
                       else '+neon,+sha2' if machine in ('aarch64','arm64') else '')
    cases = (
        ('cpu',''),
        ('all',''),
        ('cpu','brynja_cpu_evidence'),
        ('all','brynja_cpu_evidence'),
        ('cpu','brynja_sha1_cpu_evidence'),
    )
    with tempfile.TemporaryDirectory(prefix='brynja-sha1-evidence-builds-') as directory:
        for features, cfg in cases:
            flags = '-C target-feature='+target_features if target_features else ''
            if cfg: flags += ' --cfg '+cfg
            env = dict(os.environ, RUSTFLAGS=flags, CARGO_TARGET_DIR=directory)
            env.pop('CARGO_ENCODED_RUSTFLAGS',None)
            command = ['cargo'] + (['+'+args.compiler] if args.compiler else [])
            command += ['test','--locked','--release','-p','brynja-legacy-sha1','--test','cpu']
            command += ['--all-features'] if features == 'all' else ['--no-default-features','--features',features]
            result = subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True,timeout=180)
            if result.returncode or '1 passed; 0 failed' not in result.stdout:
                raise RuntimeError(f'fail-closed build regression: {features}/{cfg}\n{result.stdout}\n{result.stderr[-6000:]}')
    print('SHA-1 evidence isolation: five release-mode feature/cfg combinations reject execution')

if __name__ == '__main__': main()
