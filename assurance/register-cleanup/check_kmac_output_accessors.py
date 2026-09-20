#!/usr/bin/env python3
"""Inspect retained debug output-accessor closure, not output producers or erasure."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re

import check_kmac_verify_comparisons as comparison

require = comparison.require
SSA = r'%[-.$\w]+'
EDGES = {'output': ['as_ref', 'region'], 'region': ['as_deref', 'unwrap'],
         'as_deref': ['deref'], 'unwrap': ['empty'], 'as_ref': [], 'deref': [], 'empty': []}
SIZES = {'output': 24, 'region': 16, 'as_ref': 24, 'as_deref': 16, 'deref': 16}


def role(name):
    for token, kind in (('HardenedSha3SecretOutput6expose', 'output'),
                        ('OwnedSecretRegion6expose', 'region'), ('17unwrap_or_default', 'unwrap'),
                        ('8as_deref', 'as_deref'), ('6as_ref', 'as_ref'),
                        ('5deref', 'deref'), ('7default', 'empty')):
        if token in name:
            return kind
    raise ValueError('unreviewed output accessor: ' + name)


def closure(functions):
    roots = [name for name in functions if 'HardenedSha3SecretOutput6expose' in name]
    require(len(roots) == 1, 'unique retained output accessor')
    todo, selected = roots[:], {}
    while todo:
        name = todo.pop()
        if name in selected:
            continue
        require(name in functions, 'unresolved accessor callee')
        selected[name] = functions[name]
        calls = []
        for line in functions[name].splitlines()[1:]:
            if line.lstrip().startswith(';'):
                continue
            if re.search(r'\b(?:call|invoke)\b', line):
                match = re.search(comparison.SYMBOL, line)
                require(match is not None, 'direct accessor call required')
                calls.append(role(match[1]))
                todo.append(match[1])
        require(calls == EDGES[role(name)], 'exact accessor call graph')
    require(Counter(role(name) for name in selected) == Counter(EDGES.keys()), 'complete seven-function accessor closure')
    return selected


def inspect(functions):
    selected = closure(functions)
    count = 0
    for name, function in selected.items():
        kind = role(name)
        bounds = {'%self': SIZES[kind]} if kind in SIZES else {}
        origins = {key: (key, 0) for key in bounds}
        lines = [line.strip() for line in function.splitlines()[1:-1]
                 if line.strip() and not line.strip().startswith((';', '#dbg_'))]
        geps, stores, loads, calls = [], [], [], []
        for line in lines:
            allocation = re.fullmatch('(' + SSA + r') = alloca \[(\d+) x i8\], align \d+', line)
            if allocation:
                require(allocation[1] not in bounds and int(allocation[2]) <= 24, 'small unique accessor frame slot')
                bounds[allocation[1]] = int(allocation[2])
                origins[allocation[1]] = allocation[1], 0
            gep = re.match('(' + SSA + r') = getelementptr inbounds i8, ptr (' + SSA + r'), i64 (\d+)(?:,|$)', line)
            if gep:
                geps.append(gep.groups())
            store = re.fullmatch(r'store ptr (' + SSA + r'|null), ptr (' + SSA + r'), align 8(?:, ![\w.]+ !\d+)*', line)
            if store:
                stores.append(store.groups())
            load = re.match('(' + SSA + r') = load ptr, ptr (' + SSA + r'),', line)
            if load:
                loads.append(load.groups())
            if re.search(r'\bcall\b', line):
                symbol = re.search(comparison.SYMBOL, line)
                args = comparison.arguments(line, symbol.end())
                calls.append((line, role(symbol[1]), args))
        # Only unambiguous pointer stores may forward descriptor aliases.
        # Null on the empty branch is ignored for access classification, not
        # proven safe: this inspector does not prove branch conditions or UB.
        for _ in range(len(lines) + 1):
            previous = dict(origins)
            for dest, base, offset in geps:
                if base in origins:
                    root, old = origins[base]
                    origins[dest] = root, old + int(offset)
            for line, target, args in calls:
                if target == 'as_ref':
                    result = re.match('(' + SSA + r') = ', line)
                    base = comparison.pointer(args[0])
                    if result and base in origins:
                        root, offset = origins[base]
                        origins[result[1]] = root, offset + 8
            for dest, slot in loads:
                if slot not in origins:
                    continue
                root, offset = origins[slot]
                if root == '%self' and kind in SIZES:
                    continue  # Loading a payload pointer is not dereferencing it.
                candidates = [value for value, stored in stores if origins.get(stored) == (root, offset) and value != 'null']
                if candidates and all(value in origins for value in candidates):
                    aliases = {origins[value] for value in candidates}
                    if len(aliases) == 1:
                        origins[dest] = aliases.pop()
            if origins == previous:
                break

        def bounded(pointer, size):
            require(pointer in origins, 'accessor dereferences payload/unresolved pointer')
            root, offset = origins[pointer]
            require(0 <= offset <= bounds[root] - size, 'accessor descriptor/frame bounds')

        # Revalidate inferred reload aliases against the final store inventory;
        # an alias discovered early must not survive a later conflicting write.
        for dest, slot in loads:
            if dest not in origins:
                continue
            require(slot in origins, 'known descriptor alias slot')
            writes = [value for value, stored in stores if origins.get(stored) == origins[slot] and value != 'null']
            require(writes and all(origins.get(value) == origins[dest] for value in writes), 'unambiguous final descriptor alias stores')
            for line in lines:
                scalar = re.match(r'store i64 [^,]+, ptr (' + SSA + r'),', line)
                if scalar and scalar[1] in origins:
                    root, offset = origins[scalar[1]]
                    slot_root, slot_offset = origins[slot]
                    require(root != slot_root or abs(offset - slot_offset) >= 8, 'scalar overwrite of descriptor alias')

        for line, target, args in calls:
            if target in SIZES:
                require(len(args) == 1, 'descriptor-only accessor argument')
                bounded(comparison.pointer(args[0]), SIZES[target])
            elif target == 'empty':
                require(args == [''], 'empty-slice constructor has no arguments')
            else:
                require(len(args) == 2 and args[0].startswith('ptr ') and args[1].startswith('i64 '), 'slice metadata ABI')
        for line in lines:
            require(not re.search(r'\b(?:atomicrmw|cmpxchg|asm)\b|@llvm\.(?:mem|masked|vp\.)', line), 'unreviewed accessor memory operation')
            if re.search(r'\bload\b', line):
                load = re.fullmatch(SSA + r' = load (ptr|i64), ptr (' + SSA + r'), align 8(?:, ![\w.]+ !\d+)*', line)
                require(load is not None, 'descriptor-width loads only')
                bounded(load[2], 8)
                count += 1
            if line.startswith('store '):
                store = re.fullmatch(r'store (ptr|i64) (?:' + SSA + r'|null|0|inttoptr \(i64 1 to ptr\)), ptr (' + SSA + r'), align 8(?:, ![\w.]+ !\d+)*', line)
                require(store is not None, 'descriptor-width stores only')
                bounded(store[2], 8)
        # Bind the as_ref summary used above to the observed +8 field address
        # and its returned local slot. This is a structural summary, not a CFG proof.
        if kind == 'as_ref':
            returns = re.findall(r'(?m)^\s*ret ptr (' + SSA + ')', function)
            require(len(returns) == 1 and origins.get(returns[0]) == ('%self', 8), 'as_ref returns the borrowed region descriptor')
    return len(selected), count


def cases(record):
    # Reuse all existing matrix/source/artifact/log validation first.
    comparison.validate_record(json.loads(record.read_text()), record.parent)
    for row in json.loads(record.read_text())['records']:
        if row['profile'] != 'debug':
            continue  # Optimized accessors are inlined, checked in verifier bodies.
        functions = {}
        for package in ('brynja_core', 'brynja_hash_sha3'):
            path = next(record.parent / key for key in row['artifacts']
                        if Path(key).name.startswith(package + '-') and key.endswith('.ll'))
            for name, body in comparison.definitions(path.read_text()).items():
                require(name not in functions, 'unique cross-crate LLVM definition')
                functions[name] = body
        yield functions


def main(record):
    before = comparison.capture.sources()
    results = [inspect(functions) for functions in cases(record)]
    require(len(results) == 8 and all(count == 7 for count, _ in results), 'complete debug accessor matrix')
    require(before == comparison.capture.sources(), 'unchanged accessor source closure')
    print(f'Debug secret-output accessors: 56 functions, {sum(loads for _, loads in results)} descriptor loads PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Not output-producer effects, CFG/alias safety, machine-code spills or erasure qualification; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
