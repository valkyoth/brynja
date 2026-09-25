#!/usr/bin/env python3
"""Development-only emitted worker handoffs; NOT whole-thread qualification.

Follow actual worker LLVM after its secret execution call, not the coordinator
observer. Require direct cleanup dispatch before every return/recoverable-unwind
exit and reject workspace reads, writes, copies and escapes in that interval.
This checks dispatch, not successful completion of a destructor that panics.
Opaque callees, registers/spills, signals and abort paths remain separate reviews.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re

import check_worker_handoffs as handoffs
from check_kmac_guard_paths import call, successors
from check_kmac_verify_comparisons import definitions
from debug_write_model import blocks

require = handoffs.require
SSA = r'%[-.$\w]+'


def operation(line):
    if not re.match(r'(?:' + SSA + r' = )?(?:tail )?(?:call|invoke) ', line):
        return None
    if not re.search(r'@(?:"[^"\n]+"|[^\s(]+)\(', line):
        return None
    return call(line)


def drop_kind(name):
    # Legacy/v0 Rust mangling. These are identities, not an assertion that a
    # symbol with "drop" in its name actually erases memory.
    drop = any(token in name for token in ('drop_in_place', 'drop_glue', '4drop'))
    if not drop:
        return None
    if ('brynja_hash_parallel9execution5batch' in name
            or 'brynja_hash_parallel..execution..batch' in name) and 'Workspace' in name:
        return 'batch'
    if 'brynja_hash_sha3' in name and 'XofStorage' in name:
        return 'leaf'
    if 'brynja_hash_parallel' in name and re.search(r'ParallelHash(?:128|256)LeafWorkspace', name):
        return 'leaf'
    if 'brynja_hash_sha3' in name and 'Workspace' in name and 'hardened_batch' in name:
        return 'field'
    return None


def inspect(function, available):
    graph = blocks(function)
    allocations = re.findall(r'(' + SSA + r') = alloca \[(1088|5772) x i8\]', function)
    allocations = [(name, size) for name, size in allocations if name in ('%workspace', '%workspace.i')]
    require(len(allocations) == 1, 'one actual worker workspace')
    owner, size = allocations[0]
    kind = 'batch' if size == '5772' else 'leaf'
    entries = []
    for label, lines in graph.items():
        for index, line in enumerate(lines):
            op = operation(line)
            if op and (('LeafWorkspace' in op[0] and 'execute' in op[0])
                       or ('brynja_hash_parallel' in op[0] and 'execute_into' in op[0])):
                entries.append((label, index, op, line))
    require(len(entries) == 1, 'one secret worker execution')
    label, index, (name, args), line = entries[0]
    require(name in available, 'execution target has retained definition')
    require(len(args) == (6 if kind == 'batch' else 4), 'exact execution argument count')
    workspace_argument = args[3 if kind == 'batch' else 1]
    require(not re.search(r'\b(?:byval|sret|inalloca|preallocated)\b', workspace_argument),
            'workspace argument is borrowed, not an ABI aggregate transfer')
    require(re.fullmatch(r'ptr(?: .*?)? ' + re.escape(owner), workspace_argument),
            'execution borrows original workspace, not a copied owner')
    require(line.startswith('invoke ') and index == len(graph[label]) - 2,
            'execution exposes normal and unwind successors')

    # Track every constant subfield alias, including definitions preceding the
    # invocation. Unknown alias-producing uses fail if reached after execution.
    aliases = {owner: 0}
    changed = True
    while changed:
        changed = False
        for lines in graph.values():
            for item in lines:
                gep = re.fullmatch('(' + SSA + r') = getelementptr inbounds(?: nuw)? i8, ptr ('
                                   + SSA + r'), i64 (\d+)', item)
                if gep and gep[2] in aliases and gep[1] not in aliases:
                    aliases[gep[1]] = aliases[gep[2]] + int(gep[3])
                    changed = True
    cleanup_sites, exits, visited = set(), set(), set()

    def walk(label, dispatched, ancestors):
        require(label in graph, 'existing worker CFG successor')
        require(label not in ancestors, 'no unmodeled post-execution cycle')
        state = label, dispatched
        if state in visited:
            return
        visited.add(state)
        for index, item in enumerate(graph[label]):
            refs = set(re.findall(SSA, item)) & aliases.keys()
            if not refs:
                continue
            gep = re.fullmatch('(' + SSA + r') = getelementptr inbounds(?: nuw)? i8, ptr ('
                               + SSA + r'), i64 512', item)
            if gep:
                require(kind == 'batch' and aliases[gep[2]] == 0 and aliases[gep[1]] == 512,
                        'only reviewed batch subfield address')
                continue
            op = operation(item)
            require(op is not None, 'active workspace scalar read/write/copy/alias escape')
            target, arguments = op
            if target == 'llvm.lifetime.end.p0':
                require(dispatched and refs == {owner}, 'workspace lifetime ends only after cleanup dispatch')
                continue
            require(target in available and drop_kind(target) in (kind, 'field'),
                    'workspace only passed to retained matching cleanup target: ' + item)
            require(len(arguments) == 1 and re.fullmatch(r'ptr(?: .*?)? (' + SSA + ')', arguments[0]),
                    'cleanup has one direct workspace pointer')
            require(not re.search(r'\b(?:byval|sret|inalloca|preallocated)\b', arguments[0]),
                    'cleanup receiver cannot be an ABI aggregate transfer')
            alias = re.search(SSA + '$', arguments[0])[0]
            require(alias in aliases and refs == {alias}, 'cleanup receiver provenance')
            if drop_kind(target) == 'field':
                require(kind == 'batch' and dispatched and aliases[alias] == 512,
                        'field drop follows enclosing cleanup on original subfield')
            else:
                require(aliases[alias] == 0, 'whole cleanup uses original owner base')
                dispatched = True
                cleanup_sites.add((label, index, target))
        edges, exit_kind = successors(graph[label])
        if exit_kind in ('return', 'resume'):
            require(dispatched, 'worker exit bypasses cleanup dispatch')
            exits.add((label, exit_kind))
        # unreachable includes abort-on-second-panic; no cleanup promise there.
        for edge in edges:
            walk(edge, dispatched, ancestors | {label})

    edges, exit_kind = successors(graph[label])
    require(exit_kind is None and len(edges) == 2, 'both execution outcomes examined')
    for edge in edges:
        walk(edge, False, set())
    require(cleanup_sites and any(kind == 'return' for _, kind in exits), 'nonvacuous cleanup and normal exit')
    return kind, len(cleanup_sites), len(exits)


def cases(record_path):
    # Retain the separate MIR/source-closure/matrix/artifact checks. No compiler
    # run, tag gate change, qualification admission or CI full-sweep requirement.
    handoffs.checked_functions(record_path)
    handoffs.checked_functions(record_path, batch=True)
    record = json.loads(record_path.read_text())
    for row in record['records']:
        available, worker = set(), None
        for relative in row['artifacts']:
            path = record_path.parent / relative
            if path.suffix != '.ll':
                continue
            contents = definitions(path.read_text())
            available.update(contents)
            if path.name.startswith('brynja_hash_parallel_std-'):
                require(worker is None, 'one emitted worker module')
                worker = contents
        require(worker is not None, 'retained emitted worker module')
        selected = [(name, body) for name, body in worker.items()
                    if re.search(r'%workspace(?:\.i)? = alloca', body)
                    and re.search(r'(?:invoke|call) .*@.*(?:execute_into|LeafWorkspace.*execute)', body)]
        require(len(selected) == 6, 'two single-leaf and four fixed/XOF batch worker functions')
        kinds = Counter(inspect(body, available)[0] for _, body in selected)
        require(kinds == {'leaf': 2, 'batch': 4}, 'exact worker family coverage')
        for name, body in selected:
            yield row, name, body, available


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    args = parser.parse_args()
    results = [inspect(body, available) for _, _, body, available in cases(args.record)]
    print(f'Actual worker LLVM: {len(results)} functions; '
          f'{sum(result[1] for result in results)} cleanup-dispatch sites; '
          f'{sum(result[2] for result in results)} return/resume exits')
    print('No active workspace copies/reads/escapes after execution; NOT whole-thread/register/spill qualification')
