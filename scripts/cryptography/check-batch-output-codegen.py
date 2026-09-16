#!/usr/bin/env python3
"""Inspect optimized LLVM and assembly output destruction, without gate changes."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile

import batch_cleanup_flow as cleanup
import batch_output_flow as flow
import batch_output_assembly as machine

ROOT = Path(__file__).resolve().parents[2]
FAMILIES = {
    'sha256': ('brynja-hash-sha2', 'hardened_batch', 8, [(128, 8)]),
    'sha512': ('brynja-hash-sha2', 'hardened_batch512', 4, [(64, 8)]),
    'keccak': ('brynja-hash-sha3', 'hardened_batch', 4, [(96, 4), (64, 32)]),
}


def compile_package(root, target, package, toolchain, platform, panic):
    features = 'hardened-batch-execution'
    if package == 'brynja-hash-sha2':
        features += ',hardened-batch512-execution'
    env = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_PROFILE_RELEASE_PANIC=panic)
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
        env.pop(key, None)
    subprocess.run(['cargo', '+' + toolchain, 'rustc', '--locked', '--offline', '--release',
                    '-p', package, '--no-default-features', '--features', features,
                    '--target', platform, '--lib', '--', '--emit=llvm-ir,asm'],
                   cwd=root, env=env, check=True, timeout=300)
    artifacts = {}
    for extension in ('ll', 's'):
        paths = list(target.rglob(package.replace('-', '_') + '-*.' + extension))
        cleanup.require(len(paths) == 1, 'unique output artifact: ' + extension)
        artifacts[extension] = paths[0].read_text()
    return artifacts


def inspect_llvm(artifacts, family, platform):
    package, module, capacity, metadata = FAMILIES[family]
    v0 = (package.replace('-', '_'), f'{len(module)}{module}', '6output', '17SecretBatchOutput', '4drop')
    legacy = package.replace('-', '_') + '..' + module + '..output..SecretBatchOutput$u20$as$u20$core..ops..drop..Drop$GT$4drop'
    bodies = re.findall(r'^define [^\n]*\{.*?^}', artifacts['ll'], re.M | re.S)
    found = [body for body in bodies if all(token in body.splitlines()[0] for token in v0)
             or legacy in body.splitlines()[0]]
    cleanup.require(len(found) == 1, 'unique exact output Drop identity')
    return flow.check(found[0], capacity, metadata)


def inspect_assembly(artifacts, family, platform):
    package, module, capacity, metadata = FAMILIES[family]
    text = artifacts['s']
    # Module terminators distinguish hardened_batch from hardened_batch512.
    token = module + '..output' if '..output..SecretBatchOutput' in text else f'{len(module)}{module}6output'
    drop = 'Drop$GT$4drop' if '..output..SecretBatchOutput' in text else '4Drop4drop'
    body = cleanup.assembly_function(text, (package.replace('-', '_'), token, 'SecretBatchOutput', drop))
    return machine.check(body, capacity, metadata, platform.startswith('aarch64'))


def inspect(artifacts, family, platform):
    count = inspect_llvm(artifacts, family, platform)
    cleanup.require(inspect_assembly(artifacts, family, platform) == count, 'matching symbolic shape coverage')
    return count


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=('1.90.0', '1.98.1'), default='1.98.1')
    parser.add_argument('--target', choices=('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-musl',
                                            'aarch64-apple-darwin'), default='x86_64-unknown-linux-gnu')
    return parser.parse_args()


def main():
    args = arguments()
    with tempfile.TemporaryDirectory(prefix='brynja-batch-output-codegen-') as directory:
        for panic in ('abort', 'unwind'):
            artifacts = {}
            for family, (package, _, _, _) in FAMILIES.items():
                if package not in artifacts:
                    artifacts[package] = compile_package(ROOT, Path(directory) / panic / package,
                                                        package, args.toolchain, args.target, panic)
                count = inspect(artifacts[package], family, args.target)
                print(f'Batch output LLVM/assembly: PASS; {family}; {args.toolchain}; {args.target}; '
                      f'panic={panic}; symbolic slot shapes={count}', flush=True)


if __name__ == '__main__':
    main()
