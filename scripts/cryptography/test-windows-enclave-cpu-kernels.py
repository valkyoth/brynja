#!/usr/bin/env python3
"""Opt-in actual specialized kernels plus nonvacuous oracle corruption checks.

Only run on a native x86-64 deployment supporting SHA/SSE2/AVX/AVX2 and YMM.
No secret data is used. This does not establish enclave or cleanup qualification.
"""
import argparse
import json
from pathlib import Path
import subprocess

import windows_enclave_cpu_kernels_build as build


def run(directory, target):
    build.build(directory, target, testing=True)
    command = json.loads((directory/'cpu-kernels-build.json').read_text())['commands'][-1]
    binary = directory/'cpu-kernels-test'
    def execute(expected):
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=60)
        if (result.returncode == 0) != expected or ('6 passed; 0 failed' if expected else 'FAILED') not in result.stdout:
            raise AssertionError(result.stdout+result.stderr)
        return result.stdout
    print(execute(True))
    path = directory/'cpu_vectors.rs'
    original = path.read_text()
    for field, failures in (('SHA256_EXPECTED', 2), ('SHA512_EXPECTED', 1), ('KECCAK_EXPECTED', 2)):
        line = next(line for line in original.splitlines() if line.startswith('pub const '+field+':'))
        before, values = line.split(' = ', 1)
        data = json.loads(values.removesuffix(';'))
        data[0][0] ^= 1
        try:
            path.write_text(original.replace(line, before+' = '+json.dumps(data)+';'))
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
            output = execute(False)
            if f'{failures} failed' not in output:
                raise AssertionError('Wrong campaigns rejected corrupted oracle: '+output)
        finally:
            path.write_text(original)
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
    print(execute(True))
    print('Five specialized kernel campaigns reject three corrupted oracles; clean binary restored')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--attest-native-bundle', action='store_true', required=True)
    args = parser.parse_args()
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    if not target.startswith('x86_64-'):
        parser.error('native x86-64 required')
    run(args.directory.resolve(), target)
