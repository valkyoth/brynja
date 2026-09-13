#!/usr/bin/env python3
"""Ordinary operational MD5 acceptance, never production secret admission."""
import argparse
import subprocess
import md5_execution_policy as policy

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--write',action='store_true')
    parser.add_argument('--policy-only',action='store_true')
    args=parser.parse_args()
    if args.write: policy.write()
    policy.validate()
    if not args.policy_only:
        for command in (
            ['cargo','test','--locked','--offline','-p','brynja-legacy-md5','--features','execution','--lib','--test','execution'],
            ['cargo','test','--locked','--offline','-p','brynja-legacy-md5','--features','execution','--doc'],
            ['cargo','test','--locked','--offline','-p','brynja-legacy-md5-std','--features','runtime-execution'],
            ['cargo','clippy','--locked','--offline','-p','brynja-legacy-md5','-p','brynja-legacy-md5-std','--all-features','--all-targets','--','-A','clippy::chunks_exact_to_as_chunks','-D','warnings'],
            ['cargo','clippy','--locked','--offline','--manifest-path','assurance/md5-execution/Cargo.toml','--all-targets','--','-D','warnings'],
            ['python3','scripts/md5/check-md5-package.py','--execution'],
        ):
            subprocess.run(command,cwd=policy.ROOT,check=True,timeout=600)
    print('MD5 ordinary operational selection: PASS; public-only; native qualification separate')

if __name__=='__main__': main()
