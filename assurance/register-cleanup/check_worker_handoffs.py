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
    successors = re.findall(r'\bbb\d+\b', call[4])
    require(len(successors) == 2 and 'unwind:' in call[4], 'execution must retain return and cleanup edges')

    def walk(block, cleared, ancestors):
        require(block in blocks, 'dangling CFG successor')
        require(block not in ancestors, 'unmodeled post-execution cycle')
        body = blocks[block]
        drops = re.findall(r'\bdrop\(([^)]+)\)', body)
        require(not drops or drops == [owner], 'wrong or ambiguous owner Drop')
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
                         or re.search(r'unwind (?:continue|terminate)', body))
        require(edges or exit_path or impossible, 'unmodeled CFG terminator')
        if exit_path:
            require(cleared, 'lifecycle exit bypasses owner Drop: ' + block + ': ' + body.strip())
        for edge in edges:
            walk(edge, cleared, ancestors | {block})

    for successor in successors:
        walk(successor, False, set())
    return owner


def checked_functions(record_path):
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
        for strength in (128, 256):
            function = mir.exact_function(contents, (f'fn leaf{strength}(',))
            check_function(function, strength)
            functions.append((strength, function))
    require(seen == expected, 'incomplete compiler/target/profile matrix')
    return functions


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    args = parser.parse_args()
    checked = checked_functions(args.record)
    print(f'Scoped worker MIR handoffs: {len(checked)} checked; no active-owner moves; Drop on return/unwind')
    print('NOT register, spill, callee or whole-thread erasure qualification; no builds rerun')
