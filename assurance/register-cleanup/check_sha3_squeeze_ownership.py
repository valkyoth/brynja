#!/usr/bin/env python3
"""Retained squeeze initialization non-escape and write-result cleanup routing."""
import argparse
import json
from pathlib import Path
import re
from types import SimpleNamespace

import check_sha3_active_output as active
import check_secret_output_write as writing
import check_sha3_owner_wipe as wiping

adapter = active.adapter
comparison = active.comparison
require = active.require
SSA = active.SSA


def inspect(function, write, clear, bulk, compiler):
    header = function.splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    old = compiler == '1.90.0'
    require(old or compiler == '1.98.1', 'reviewed retained compiler')
    success, write_success = ('5', '4') if old else ('-1', '-1')
    require(symbol is not None and re.match(r'define internal fastcc noundef range\(i8 '
            + ('0, 6' if old else '-1, 5') + r'\) i8 @', header), 'defined squeeze result ABI')
    final = '25squeeze_final_bits_secret' in symbol[1]
    require(final or symbol[1] == bulk, 'actual final or bulk squeeze definition')
    args = comparison.arguments(header, symbol.end())
    require(len(args) == (4 if final else 3), 'complete squeeze argument inventory')
    initializer = args[3 if final else 1]
    require(args[0].startswith('ptr noalias ') and 'dereferenceable(1040)' in args[0]
            and initializer.startswith('ptr noalias ') and 'dereferenceable(24)' in initializer,
            'exclusive disjoint owner and initialization borrows')
    owner, initialization = comparison.pointer(args[0]), comparison.pointer(initializer)
    require(owner != initialization, 'distinct owner and initialization parameters')
    graph, edges, origin = adapter.routes.transfer.finish.graph_info(function)
    trace = SimpleNamespace(graph=graph, edges=edges)
    uses, writes, forwards = [], [], []
    for label, lines in graph.items():
        for index, line in enumerate(lines):
            if initialization not in re.findall(SSA, line):
                continue
            uses.append((label, index, line))
            result = re.match('(' + SSA + r') = tail call (?:fastcc )?noundef i8 @', line)
            require(result is not None, 'initialization cannot be read, copied, aliased, cast, returned or stored')
            name, params = adapter.routes.guard.call(line)
            require(len(params) == 3 and all(param.startswith('ptr noalias ') for param in params[:2]),
                    'only complete exclusive write/forward calls use initialization')
            if name == write:
                require(comparison.pointer(params[0]) == initialization
                        and origin(comparison.pointer(params[1])) == (owner, 584), 'original initialization and original squeeze staging')
                require(sum(initialization in re.findall(SSA, param) for param in params) == 1,
                        'initialization is never a payload source or length')
                if final:
                    require(params[2] == 'i64 noundef 1', 'final write is exactly one staged byte')
                else:
                    count = re.fullmatch('i64 noundef (' + SSA + ')', params[2])
                    require(count is not None, 'bulk write receives a bounded chunk count')
                    definitions = [value for block in graph.values() for value in block if value.startswith(count[1] + ' = ')]
                    require(len(definitions) == 1 and re.fullmatch(re.escape(count[1])
                            + r' = tail call noundef i64 @llvm.umin.i64\(i64 ' + SSA + r', i64 (136|168)\)', definitions[0]),
                            'bulk source length is bounded by a supported rate within the 168-byte staging region')
                writes.append((label, index, result[1], comparison.pointer(params[1])))
            else:
                require(final and name == bulk and line.startswith(result[1] + ' = tail call fastcc ')
                        and comparison.pointer(params[0]) == owner and comparison.pointer(params[1]) == initialization
                        and re.fullmatch('i64 noundef ' + SSA, params[2]), 'only original-owner bulk forwarding is allowed')
                forwards.append((label, index))
    require(len(writes) == 1 and len(forwards) == int(final) and len(uses) == 1 + int(final),
            'complete initialization use inventory')
    label, index, result, staging = writes[0]
    lines = graph[label]
    require(index == (6 if final else 0) and len(lines) == (11 if final else 4), 'closed post-write result and cleanup sequence')
    tested = re.fullmatch('(' + SSA + ') = icmp eq i8 ' + re.escape(result) + ', ' + write_success, lines[index + 1])
    require(tested is not None, 'actual core write success discriminator')
    cleanup_index = index + (3 if final and old else 2)
    cleanup = lines[cleanup_index]
    name, params = adapter.routes.guard.call(cleanup)
    require(re.match(SSA + r' = tail call noundef i8 @', cleanup) and name == clear and len(params) == 2
            and comparison.pointer(params[0]) == staging and params[1] == 'i64 noundef 168',
            'entire original staging region cleared after every normal write result')
    if final:
        selected = re.fullmatch('(' + SSA + ') = select i1 ' + re.escape(tested[1])
                               + ', i8 ' + success + ', i8 4', lines[index + (2 if old else 3)])
        require(selected is not None and len(edges[label][0]) == 1, 'final write maps success or SecretMemory error after cleanup')
        returning = edges[label][0][0]
        expected = selected[1]
    else:
        condition, progress, returning = adapter.shape.branch(trace, label)
        require(condition == tested[1] and progress != returning, 'bulk write error exits instead of continuing')
        expected = '4'
    returned = graph[returning]
    require(len(returned) == 2, 'value-only shared squeeze return')
    phi = re.fullmatch('(' + SSA + r') = phi i8 (.+)', returned[0])
    require(phi is not None and returned[1] == 'ret i8 ' + phi[1], 'returned squeeze result from actual predecessor')
    entries = re.findall(r'\[ (' + SSA + r'|-?\d+), %([^\]]+) \]', phi[2])
    require(', '.join(f'[ {value}, %{parent} ]' for value, parent in entries) == phi[2]
            and [(value, parent) for value, parent in entries if parent == label] == [(expected, label)],
            'post-cleanup write failure remains SecretMemory on its actual return edge')
    return graph, uses, (label, index, cleanup_index, returning), final


def cases(record):
    dependencies = {}
    for row, _, core, assembly in comparison.cases(record):
        if row['profile'] != 'release':
            continue
        compiler = row['compiler'].splitlines()[0].split()[1]
        arm = row['target'].startswith('aarch64')
        writer = writing.select(core)
        writing.inspect(writer, compiler)
        writing.copy_boundary.inspect(assembly, arm)
        write = re.search(comparison.SYMBOL, writer.splitlines()[0])[1]
        clear = wiping.core_check(core, assembly, compiler, arm)
        paths = [record.parent / path for path in row['artifacts']
                 if Path(path).name.startswith('brynja_hash_sha3-') and path.endswith('.ll')]
        require(len(paths) == 1, 'one source-bound SHA-3 artifact')
        for name, body in comparison.definitions(paths[0].read_text()).items():
            if 'hardened' in name and 'sponge' in name and 'squeeze' in name:
                dependencies[body] = (write, clear, compiler)
    for function, definitions, wipes in active.terminal.entry.reader.cases(record):
        _, _, secret = active.terminal.entry.reader.inspect(function, definitions, wipes)
        selected = {name: body for name, body in definitions.items()
                    if '@' + name + '(' in definitions[secret] and ('14squeeze_secret' in name or '25squeeze_final_bits_secret' in name)}
        bulk = [name for name in selected if '14squeeze_secret' in name]
        require(len(selected) == 2 and len(bulk) == 1, 'actual reader-bound bulk/final pair')
        for body in selected.values():
            require(body in dependencies, 'same source-bound core dependency closure')
            write, clear, compiler = dependencies[body]
            yield body, write, clear, bulk[0], compiler


def main(record):
    before = comparison.capture.sources()
    checks = [inspect(*case) for case in cases(record)]
    require(len(checks) == 32 and sum(len(uses) for _, uses, _, _ in checks) == 48
            and sum(final for _, _, _, final in checks) == 16 and before == comparison.capture.sources(),
            'complete unchanged squeeze ownership matrix')
    print('Squeeze initialization: 32 bulk/final bodies; 48 direct handle uses confined to bound write/bulk calls PASS')
    print('All 32 normal write-result paths clear 168-byte staging before returning SecretMemory on write rejection')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Direct initialization-use and post-write checks under valid disjoint borrows; not full squeeze arithmetic, callee effects, unwind or register/spill erasure')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
