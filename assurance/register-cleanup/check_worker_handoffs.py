#!/usr/bin/env python3
"""Development-only MIR worker-owner check; not register/spill qualification."""
import argparse
import json
from pathlib import Path
import re
import sys

import check_callers as audit

sys.path.insert(0, str(audit.ROOT / 'scripts/cryptography'))
import mir_cleanup_flow as mir


def require(condition, message):
    if not condition:
        raise ValueError('worker handoff diagnostic: ' + message)


def check_function(function, strength):
    """No active-owner references except Drop, with Drop on every exit path.

    This deliberately supports the observed straight-line owner setup only.
    Unknown changes fail review; no assertion is made about callees' code or
    values hidden in machine registers, spills, returned loans or metadata.
    """
    name = f'ParallelHash{strength}LeafWorkspace'
    header = function.splitlines()[0]
    require(header.startswith(f'fn leaf{strength}(')
            and header.endswith(f'Result<(ParallelHash{strength}LeafResult<\'_, \'_>, bool), execution::Error> {{'),
            'unexpected leaf return signature')
    owners = re.findall(r'debug workspace => (_\d+);', function)
    require(len(owners) == 1, 'missing/ambiguous workspace local')
    owner = owners[0]
    blocks = mir.basic_blocks(function)
    calls = [(label, mir.call_definition(body)) for label, body in blocks.items()]
    calls = [(label, call) for label, call in calls
             if call is not None and call[1] == name + "::<'_>::execute("]
    require(len(calls) == 1, 'missing/ambiguous secret execution')
    label, call = calls[0]
    argument = mir.first_argument(call[2])
    matched = re.fullmatch(r'(?:move|copy) (_\d+)', argument)
    require(matched is not None, 'unmodeled workspace argument')
    alias = matched[1]
    # Only a directly borrowed owner is admitted. Its last definition must be
    # immediately before the call, so no intervening call may stash that alias.
    prefix = blocks[label].splitlines()
    call_index = next(i for i, line in enumerate(prefix) if name + "::<'_>::execute(" in line)
    setup = [line.strip() for line in prefix[:call_index] if line.strip()]
    require(setup and setup[-1] == f'{alias} = &mut {owner};', 'execution is not a direct owner borrow')
    check_paths(blocks, call, owner, alias)
    return owner


def check_paths(blocks, call, owner, alias, other_drops=()):
    successors = re.findall(r'\bbb\d+\b', call[4])
    require(len(successors) == 2 and 'unwind:' in call[4], 'execution must retain return and cleanup edges')

    def walk(block, cleared, ancestors):
        require(block in blocks, 'dangling CFG successor')
        require(block not in ancestors, 'unmodeled post-execution cycle')
        body = blocks[block]
        drops = re.findall(r'\bdrop\(([^)]+)\)', body)
        require(len(drops) <= 1 and all(value in (owner, *other_drops) for value in drops),
                'wrong or ambiguous owner Drop')
        for line in body.splitlines():
            line = line.strip()
            references = set(re.findall(r'\b_\d+\b', line)) & {owner, alias}
            if not references:
                continue
            if line.startswith(f'drop({owner}) ->'):
                require(not cleared, 'repeated owner Drop')
                cleared = True
            elif line in {f'StorageDead({owner});', f'StorageDead({alias});'}:
                require(cleared or line == f'StorageDead({alias});', 'owner storage ended before Drop')
            else:
                require(False, 'active owner/alias copied, moved, escaped or reused')
        edges = re.findall(r'\bbb\d+\b', body)
        # MIR's bare unreachable terminator represents an invalid enum state,
        # not a normal return or recoverable unwind. Do not treat it as Drop.
        impossible = body.strip().rstrip('}').strip() == 'unreachable;'
        exit_path = bool(re.search(r'\b(?:return|resume)\s*;', body)
                         or re.search(r'unwind continue', body))
        # A second panic during cleanup terminates the process; no Drop/erasure
        # guarantee is made on that non-recoverable branch. Its normal edge is
        # still traversed and must clean the workspace before returning/resuming.
        abort_path = bool(re.search(r'unwind terminate\(cleanup\)', body))
        require(edges or exit_path or impossible or abort_path, 'unmodeled CFG terminator')
        if exit_path:
            require(cleared, 'lifecycle exit bypasses owner Drop: ' + block + ': ' + body.strip())
        for edge in edges:
            walk(edge, cleared, ancestors | {block})

    for successor in successors:
        walk(successor, False, set())


def check_batch_function(function, strength):
    header = function.splitlines()[0]
    require(header.startswith(f'fn wave{strength}::{{closure#0}}::{{closure#2}}(')
            and '/src/execution/batch/in_place/worker.rs:' in header
            and header.endswith(f"Result<Leaves{strength}<'_, '_, '_>, execution::batch::Error> {{"),
            'unexpected multibuffer worker signature')
    owners = re.findall(r'debug workspace => (_\d+);', function)
    results = re.findall(r'debug result => (_\d+);', function)
    require(len(owners) == 1 and len(results) == 1, 'missing/ambiguous batch workspace/result')
    owner = owners[0]
    blocks = mir.basic_blocks(function)
    target = f"Batch{strength}::<'_, '_>::execute_into("
    calls = [(label, mir.call_definition(body)) for label, body in blocks.items()]
    calls = [(label, call) for label, call in calls if call is not None and call[1] == target]
    require(len(calls) == 1, 'missing/ambiguous batch execution')
    label, call = calls[0]
    arguments = call[2].split(', ')
    require(len(arguments) == 5, 'unmodeled batch arguments')
    matched = re.fullmatch(r'(?:move|copy) (_\d+)', arguments[2])
    require(matched is not None, 'unmodeled batch workspace argument')
    alias = matched[1]
    prefix = blocks[label][:blocks[label].index(target)].rsplit('\n', 1)[0]

    def origin(block, body, ancestors):
        require(block not in ancestors, 'cyclic workspace borrow setup')
        for line in reversed(body.splitlines()):
            line = line.strip()
            if line == f'{alias} = &mut {owner};':
                return
            if line == f'StorageLive({alias});':
                continue
            require(not (set(re.findall(r'\b_\d+\b', line)) & {owner, alias}),
                    'workspace borrow redefined or escaped before execution')
        predecessors = [key for key, value in blocks.items()
                        if block in re.findall(r'\bbb\d+\b', value)]
        require(predecessors and block != 'bb0', 'workspace argument lacks a definite borrow')
        for predecessor in predecessors:
            origin(predecessor, blocks[predecessor], ancestors | {block})

    origin(label, prefix, set())
    check_paths(blocks, call, owner, alias, other_drops=results)
    return owner


def check_parent_slots(contents):
    header = ('execution::batch::in_place::worker::', '::drop(_1: &mut GroupSlots) -> () {')
    function = mir.exact_function(contents, header)
    blocks = mir.basic_blocks(function)
    require(set(blocks) == {'bb0', 'bb1'}, 'parent slot Drop is not the reviewed two-block forwarder')
    call = mir.call_definition(blocks['bb0'])
    require(call is not None and call[1] == 'GroupSlots::clear('
            and call[2] in ('copy _1', 'move _1') and call[3] == 'bb1'
            and call[4] == 'return: bb1, unwind continue', 'parent slot Drop changed receiver or clear call')
    require(re.fullmatch(r'\s*_\d+ = GroupSlots::clear\((?:copy|move) _1\) -> \[return: bb1, unwind continue\];\s*}\s*', blocks['bb0']) is not None,
            'parent slot Drop gained instructions before clearing')
    require(re.fullmatch(r'\s*return;\s*}\s*}\s*', blocks['bb1']) is not None,
            'parent slot Drop return changed')
    # This proves forwarding only. Unlike require_owner_cleanup, it does not
    # certify a non-unwinding cleanup target: this MIR retains unwind continue.
    return function


def checked_functions(record_path, *, batch=False):
    record_path = record_path.resolve()
    record = json.loads(record_path.read_text())
    require(record.get('api_profile') == 'threaded'
            and record.get('qualifies_register_cleanup') is False,
            'expected unqualified threaded development record')
    require(record['sources'] == audit.sources(), 'record source closure is stale')
    expected = {(compiler, target, profile)
                for compiler in ('1.90.0', '1.98.1')
                for target in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-musl')
                for profile in ('debug', 'release')}
    seen = set()
    functions = []
    for row in record['records']:
        compiler = row['compiler'].splitlines()[0].split()[1]
        identity = compiler, row['target'], row['profile']
        require(identity in expected and identity not in seen, 'missing/duplicate matrix identity')
        seen.add(identity)
        candidates = []
        for relative, digest in row['artifacts'].items():
            path = (record_path.parent / relative).resolve()
            require(path.is_relative_to(record_path.parent), 'artifact outside record directory')
            require(audit.digest(path) == digest, 'artifact hash mismatch')
            if path.name.startswith('brynja_hash_parallel_std-') and path.suffix == '.mir':
                candidates.append(path)
        require(len(candidates) == 1, 'missing/ambiguous worker MIR artifact')
        contents = candidates[0].read_text()
        if batch:
            check_parent_slots(contents)
        for strength in (128, 256):
            name = f'fn wave{strength}::{{closure#0}}::{{closure#2}}(' if batch else f'fn leaf{strength}('
            function = mir.exact_function(contents, (name,))
            (check_batch_function if batch else check_function)(function, strength)
            functions.append((strength, function))
    require(seen == expected, 'incomplete compiler/target/profile matrix')
    return functions


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--batch', action='store_true', help='inspect multibuffer worker closures')
    args = parser.parse_args()
    checked = checked_functions(args.record, batch=args.batch)
    mode = 'multibuffer' if args.batch else 'single-leaf'
    print(f'Scoped {mode} worker MIR handoffs: {len(checked)} checked; no active-owner moves; Drop on return/unwind')
    if args.batch:
        print('Parent GroupSlots Drop forwards its own receiver to clear in all eight artifacts')
    print('NOT register, spill, callee or whole-thread erasure qualification; no builds rerun')
