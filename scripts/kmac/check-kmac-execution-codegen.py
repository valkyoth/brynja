#!/usr/bin/env python3
"""Source-owned KMAC execution cleanup under the pinned compiler endpoints."""
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
        raise ValueError('KMAC execution cleanup: ' + label)


def body(mir, owner, operation):
    return flow.exact_function(mir, ('fn execution::', '::' + operation + '(', owner))


def check(row):
    mir = row['mir']
    metadata = body(mir, '&mut Metadata)', 'wipe')
    require(metadata.count('= clear_owned_region(') == 4, 'four metadata regions')
    for identity, call in (('&mut Metadata)', 'Metadata::wipe('),
                           ("&mut Core<'_>", "Core::<'_>::cancel("),
                           ("&mut execution::xof::Reader<", "Core::<'_>::cancel(")):
        caller = body(mir, identity, 'drop')
        if 'Reader<' in identity:
            # Precisely model this reader's single borrowed Core field. Do not
            # globally strip MIR annotations or accept arbitrary projections.
            caller, count = re.subn(
                r"(\s_\d+ = )(?:no_retag )?copy \(\(\*_1\)\.0: &mut execution::core_state::Core<'_>\);",
                r'\1copy (*_1).0;', caller)
            require(count == 1, 'exact reader borrowed-owner projection')
        blocks = flow.basic_blocks(caller)
        calls = [(b, arg) for b, arg in flow.exact_calls(blocks, call)]
        require(len(calls) == 1, 'one exact destruction call')
        cleanup, argument = calls[0]
        incoming = flow.owner_states(blocks, cleanup, call)
        state = flow.statement_state(blocks[cleanup], incoming[cleanup])
        require(flow.argument_root(argument, state[0]) == '_1', 'destruction retains source owner')
        graph, exits = flow.control_flow(blocks)
        nodes = flow.reachable(graph)
        dominance = flow.dominators(graph, nodes)
        require(exits & nodes and all(cleanup in dominance[node] for node in exits & nodes),
                'destruction dominates exits')
    cancel = body(mir, "&mut Core<'_>", 'cancel')
    require('State::' in cancel and '::wipe(' in cancel and 'Metadata::wipe(' in cancel,
            'exact state and metadata destruction')
    operation = body(mir, '&mut Operation<', 'drop')
    require('cancel(' in operation, 'unwind guard clears source')
    for identity in ('&mut Stage)', '&mut BorrowedStage<'):
        require('= clear_owned_region(' in body(mir, identity, 'drop'), 'output staging cleared')
    wipe = body(mir, "&mut execution::backend::State<'_>", 'wipe')
    for token in ('HardenedCshake128::wipe_in_place(', 'HardenedCshake256::wipe_in_place(',
                  'Cshake128::', 'Cshake256::'):
        require(token in wipe, 'every hardened variant cleared: ' + token)
    definitions = re.findall(r'^define [\s\S]*?^}', row['ll'], re.M)
    selected = [item for item in definitions if re.search(r'execution.*core_state.*8Metadata.*4wipe', item.splitlines()[0])]
    require(len(selected) == 1, 'unique emitted metadata wipe')
    widths = re.findall(r'call [^\n]*clear_owned_region[^\n]*i(?:32|64)\s+[^\n]*?\b(\d+)\)', selected[0])
    require(Counter(map(int, widths)) == Counter((16, 16, 1, 1)), 'exact emitted region widths')
    require(re.search(r'execution.*core_state.*8Metadata.*4wipe', row['s']), 'assembly cleanup emitted')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--toolchain', choices=('1.90.0', '1.98.1'), default='1.98.1')
    parser.add_argument('--target', choices=('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-musl'),
                        default='x86_64-unknown-linux-gnu')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='brynja-kmac-cleanup-') as directory:
        env = dict(os.environ, CARGO_TARGET_DIR=directory, CARGO_PROFILE_RELEASE_PANIC='unwind')
        for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
            env.pop(name, None)
        subprocess.run(['cargo', '+' + args.toolchain, 'rustc', '--locked', '--offline',
            '-p', 'brynja-mac-kmac', '--features', 'hardened-execution,runtime-execution',
            '--release', '--lib', '--target', args.target, '--', '--emit=mir,llvm-ir,asm'],
            cwd=ROOT, env=env, check=True, timeout=180)
        row = {}
        for extension in ('mir', 'll', 's'):
            paths = list(Path(directory).rglob('brynja_mac_kmac-*.' + extension))
            require(len(paths) == 1, 'unique compiler artifact')
            row[extension] = paths[0].read_text()
        check(row)
        for before in ('Metadata::wipe(', '= clear_owned_region('):
            mutant = dict(row, mir=row['mir'].replace(before, 'omitted('))
            try:
                check(mutant)
            except (ValueError, flow.MirCleanupFlowError):
                continue
            raise ValueError('KMAC emitted cleanup mutant escaped')
    print(f'KMAC execution MIR/LLVM/assembly cleanup: PASS; {args.toolchain} {args.target}')
    print('Source-owned regions only; not register, spill or platform erasure')


if __name__ == '__main__':
    main()
