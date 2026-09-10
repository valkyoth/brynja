#!/usr/bin/env python3
"""Bounded emitted-code evidence for owned memory, not register erasure."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def require(value, label):
    if not value:
        raise ValueError('hardened execution codegen missing: ' + label)


def functions(mir):
    return re.findall(r'^fn [\s\S]*?^}', mir, re.M)


def one_body(mir, header):
    matches = [body for body in functions(mir) if re.search(header, body.splitlines()[0])]
    require(len(matches) == 1, header)
    return matches[0]


def check(cpu, sha2):
    scratch = one_body(cpu['mir'], r'^fn scratch::.*::wipe\(')
    require(scratch.count('= clear_owned_region(') == 2, 'two complete CPU scratch regions')
    require('[u8; 640]' in scratch and '[u8; 64]' in scratch, 'scratch region widths')
    require('Scratch::wipe' in one_body(cpu['mir'], r'^fn scratch::.*::drop\('), 'scratch Drop')
    operation = one_body(cpu['mir'], r'^fn hardened_execution::.*::drop\(.*&mut Operation')
    require('Scratch::wipe' in operation and 'quarantine' in operation, 'operation guard')
    update = one_body(sha2['mir'], r'^fn hardened_execution::engine::.*::drop\(')
    require('HardenedSha2Owner::wipe' in update and 'const true' in update, 'update unwind failure guard')
    owner = one_body(sha2['mir'], r'^fn owner::.*::wipe\(')
    require(owner.count('= clear_owned_region(') == 8, 'eight complete hash-owner regions')
    require('HardenedSha2Owner::wipe' in one_body(sha2['mir'], r'^fn owner::.*::drop\('), 'hash-owner Drop')
    for extension in ('ll', 's'):
        require(re.search(r'Scratch.*wipe', cpu[extension]), 'emitted CPU scratch clearing ' + extension)
        require('clear_owned_region' in cpu[extension], 'emitted clearing boundary ' + extension)
        require('HardenedSha2Owner' in sha2[extension] and 'wipe' in sha2[extension], 'emitted hash owner ' + extension)
    # LLVM must preserve calls for both exact memory extents, not only symbols.
    bodies = re.findall(r'^define [\s\S]*?^}', cpu['ll'], re.M)
    wipes = [body for body in bodies if re.search(r'Scratch.*wipe', body.splitlines()[0])]
    require(len(wipes) == 1, 'unique LLVM scratch wipe')
    for width in (640, 64):
        require(re.search(r'call .*clear_owned_region.*i(?:32|64)[^\n]*\b' + str(width) + r'\)', wipes[0]), 'LLVM clear width ' + str(width))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--toolchain', default='1.98.1')
    parser.add_argument('--target', default='x86_64-unknown-linux-gnu')
    args = parser.parse_args()
    require(re.fullmatch(r'1\.[0-9]+\.[0-9]+', args.toolchain), 'toolchain')
    require(args.target in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-musl'), 'reviewed target')
    with tempfile.TemporaryDirectory(prefix='brynja-hardened-codegen-') as directory:
        env = dict(os.environ, CARGO_TARGET_DIR=directory, CARGO_PROFILE_RELEASE_PANIC='unwind')
        for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
            env.pop(name, None)
        artifacts = []
        for crate in ('brynja-crypto-cpu', 'brynja-hash-sha2'):
            features = 'hardened-execution,runtime-execution'
            if crate.endswith('sha2'):
                features += ',general-sha512-t'
            subprocess.run(['cargo', '+' + args.toolchain, 'rustc', '--locked', '--offline', '-p', crate,
                            '--features', features, '--release', '--lib', '--target', args.target,
                            '--', '--emit=mir,llvm-ir,asm'], cwd=ROOT, env=env, check=True, timeout=180)
            row = {}
            for extension in ('mir', 'll', 's'):
                paths = list(Path(directory).rglob(crate.replace('-', '_') + '-*.' + extension))
                require(len(paths) == 1, 'unique compiler artifact')
                row[extension] = paths[0].read_text()
            artifacts.append(row)
        check(*artifacts)
        # Self-test the interpretation: missing region calls/widths cannot pass.
        for before, after in (('= clear_owned_region(', '= missing_clear('), ('[u8; 640]', '[u8; 639]'), ('Scratch::wipe', 'Scratch::missing')):
            mutant = dict(artifacts[0], mir=artifacts[0]['mir'].replace(before, after))
            try:
                check(mutant, artifacts[1])
            except ValueError:
                continue
            raise ValueError('cleanup artifact mutation escaped: ' + before)
    print(f'Hardened execution owned-memory MIR/LLVM/assembly: PASS; {args.toolchain} {args.target}; unwind enabled')


if __name__ == '__main__':
    main()
