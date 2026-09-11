#!/usr/bin/env python3
"""Compiler endpoint evidence for source-owned hardened Keccak memory."""
import argparse
from collections import Counter
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/cryptography'))
import mir_cleanup_flow as flow


def require(value, label):
    if not value:
        raise ValueError('hardened Keccak emitted cleanup: ' + label)


def body(mir, *parts):
    return flow.exact_function(mir, parts)


def owner(artifacts, identity, widths):
    mir = artifacts['mir']
    wipe = body(mir, '::wipe(', '&mut ' + identity)
    require(wipe.count('= clear_owned_region(') == len(widths), identity + ' MIR regions')
    drop = body(mir, '::drop(', '&mut ' + identity)
    # Unwind builds conservatively retain edges through the cross-crate clearing
    # primitive. Check owner provenance and dominance without deleting those
    # edges. Non-panicking clearing additionally relies on its reviewed source
    # and unwind tests; this check does not claim an LLVM nounwind proof.
    blocks = flow.basic_blocks(drop)
    target = identity + '::wipe('
    cleanup, argument = flow.exact_calls(blocks, target)[0]
    incoming = flow.owner_states(blocks, cleanup, target)
    require(cleanup in incoming, 'reachable cleanup')
    state = flow.statement_state(blocks[cleanup], incoming[cleanup])
    require(flow.argument_root(argument, state[0]) == '_1', 'cleanup owner provenance')
    graph, exits = flow.control_flow(blocks)
    nodes = flow.reachable(graph)
    dominance = flow.dominators(graph, nodes)
    require(exits & nodes and all(cleanup in dominance[node] for node in exits & nodes),
            'cleanup dominates every exit')
    bodies = re.findall(r'^define [\s\S]*?^}', artifacts['ll'], re.M)
    matches = [item for item in bodies if re.search(identity + r'.*wipe', item.splitlines()[0])]
    require(len(matches) == 1, identity + ' unique LLVM wipe')
    calls = re.findall(r'call [^\n]*clear_owned_region[^\n]*i(?:32|64)\s+[^\n]*?\b(\d+)\)', matches[0])
    require(Counter(map(int, calls)) == Counter(widths), identity + ' LLVM exact clearing widths')
    require(re.search(identity + r'.*wipe', artifacts['s']), identity + ' emitted assembly wipe')
    return wipe


def check(cpu, leaf):
    owner(cpu, 'KeccakScratch', [200, 40, 40, 200, 32, 32, 32])
    owner(leaf, 'Memory', [200, 16, 16, 2])
    operation = body(cpu['mir'], 'keccak::', '::drop(', '::Operation<')
    require('KeccakScratch::wipe(' in operation and 'quarantine' in operation,
            'CPU operation cleanup/quarantine')
    operation = body(leaf['mir'], 'accelerated::engine::', '::drop(', 'Operation<')
    require('cancel(' in operation, 'leaf unwind cleanup')
    for identity in ('Stage', 'BorrowedStage'):
        drop = body(leaf['mir'], '/hardened/accelerated/reader.rs:', '::drop(', '&mut ' + identity)
        require('= clear_owned_region(' in drop, identity + ' output cleanup')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--toolchain', default='1.98.1', choices=('1.90.0', '1.98.1'))
    parser.add_argument('--target', default='x86_64-unknown-linux-gnu',
                        choices=('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-musl'))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='brynja-keccak-cleanup-') as directory:
        env = dict(os.environ, CARGO_TARGET_DIR=directory, CARGO_PROFILE_RELEASE_PANIC='unwind')
        for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
            env.pop(name, None)
        artifacts = []
        for package in ('brynja-crypto-cpu', 'brynja-hash-sha3'):
            subprocess.run(['cargo', '+' + args.toolchain, 'rustc', '--locked', '--offline',
                            '-p', package, '--features', 'hardened-execution,runtime-execution',
                            '--release', '--lib', '--target', args.target,
                            '--', '--emit=mir,llvm-ir,asm'], cwd=ROOT, env=env, check=True, timeout=180)
            row = {}
            for extension in ('mir', 'll', 's'):
                paths = list(Path(directory).rglob(package.replace('-', '_') + '-*.' + extension))
                require(len(paths) == 1, 'unique compiler artifact')
                row[extension] = paths[0].read_text()
            artifacts.append(row)
        check(*artifacts)
        for index, before, after in ((0, 'KeccakScratch::wipe(', 'KeccakScratch::missing('),
                                     (1, 'Memory::wipe(', 'Memory::missing('),
                                     (0, '= clear_owned_region(', '= omitted('),
                                     (1, '= clear_owned_region(', '= omitted(')):
            changed = [dict(row) for row in artifacts]
            changed[index]['mir'] = changed[index]['mir'].replace(before, after)
            try:
                check(*changed)
            except (ValueError, flow.MirCleanupFlowError):
                continue
            raise ValueError('cleanup artifact mutant escaped: ' + before)
    print(f'Hardened Keccak MIR/LLVM/assembly cleanup: PASS; {args.toolchain} {args.target}')
    print('Source-owned memory only; no register/spill/platform erasure claim')


if __name__ == '__main__':
    main()
