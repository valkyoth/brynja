#!/usr/bin/env python3
"""Check the exact legacy CPU surface and production fail-closed consumer."""
import argparse
import subprocess
import cpu_policy as policy

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--write',action='store_true')
    args = parser.parse_args()
    policy.validate(hashes=not args.write)
    if args.write:
        (policy.ROOT/'scripts/sha1/cpu-reviewed.toml').write_text(policy.inventory())
    for command in (
        ['python3','scripts/sha1/test-sha1-native-capture.py'],
        ['python3','scripts/sha1/check-sha1-package.py','--cpu'],
        ['cargo','test','--locked','-p','brynja-legacy-sha1','--features','cpu','--test','cpu'],
        ['cargo','test','--locked','-p','brynja-legacy-sha1','--features','cpu','--lib','cpu::'],
        ['cargo','test','--locked','-p','brynja-legacy-sha1-std'],
        ['cargo','test','--locked','-p','brynja-legacy-sha1','--features','cpu','--doc'],
    ):
        subprocess.run(command,cwd=policy.ROOT,check=True,timeout=180)
    print('SHA-1 CPU candidate surface and ordinary-build rejection: PASS; native admission: NONE')

if __name__ == '__main__': main()
