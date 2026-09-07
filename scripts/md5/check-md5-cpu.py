#!/usr/bin/env python3
"""Check MD5 batch consumers, exact boundary and ordinary-build rejection."""
import argparse
import subprocess
import md5_cpu_policy as policy

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--write',action='store_true')
    args=parser.parse_args()
    policy.validate(hashes=not args.write)
    if args.write: (policy.ROOT/'scripts/md5/md5-cpu-reviewed.toml').write_text(policy.inventory())
    for command in (
        ['python3','scripts/md5/test-md5-evidence-builds.py'],
        ['python3','scripts/md5/test-md5-native-capture.py'],
        ['python3','scripts/md5/check-md5-package.py','--cpu'],
        ['cargo','test','--locked','-p','brynja-legacy-md5','--all-features'],
        ['cargo','test','--locked','-p','brynja-legacy-md5-std'],
    ):
        subprocess.run(command,cwd=policy.ROOT,check=True,timeout=180)
    print('MD5 batch/SIMD source, packaged APIs and production rejection: PASS; admission NONE')

if __name__=='__main__': main()
