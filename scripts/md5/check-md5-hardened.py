#!/usr/bin/env python3
"""Hardened MD5 development acceptance. Native qualification stays separate."""
import argparse
import subprocess
import md5_hardened_policy as policy

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--write',action='store_true')
    parser.add_argument('--policy-only',action='store_true')
    args=parser.parse_args()
    if args.write: policy.write()
    policy.validate()
    if not args.policy_only:
        for command in (
            ['cargo','test','--locked','--offline','-p','brynja-legacy-md5','--features','hardened-execution'],
            ['cargo','test','--locked','--offline','-p','brynja-legacy-md5-std','--features','runtime-hardened-execution'],
            ['cargo','clippy','--locked','--offline','--manifest-path','assurance/md5-hardened-execution/Cargo.toml','--all-targets','--','-D','warnings'],
            ['python3','scripts/md5/check-md5-package.py','--hardened'],
        ):
            subprocess.run(command,cwd=policy.ROOT,check=True,timeout=600)
    label = 'Hardened MD5 source policy' if args.policy_only else 'Hardened MD5 development acceptance'
    print(label + ': PASS; native evidence/retest separate')

if __name__=='__main__': main()
