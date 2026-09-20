#!/usr/bin/env python3
"""Inspect retained portable squeeze-loop staging, not whole-producer erasure."""
import argparse
import json
from pathlib import Path
import re

import check_kmac_verify_comparisons as comparison
import check_secret_output_write as writing

require = comparison.require
SSA = writing.SSA
match = writing.match


def blocks(function):
    graph, label = {}, None
    for raw in function.splitlines()[1:-1]:
        line = raw.strip()
        if not line or line.startswith(';'):
            continue
        found = re.fullmatch(r'([\w.]+):(?:\s*;.*)?', line)
        if found:
            label = found[1]
            require(label not in graph, 'unique squeeze block')
            graph[label] = []
        else:
            require(label is not None, 'squeeze instruction belongs to block')
            graph[label].append(re.sub(r'(?:, ![\w.]+ !\d+)+$', '', line))
    return graph


def call(line, name, pointers, lengths, fast=False):
    symbol = re.search(comparison.SYMBOL, line)
    require(symbol is not None and symbol[1] == name, 'exact staging callee')
    result = match('(' + SSA + r') = tail call ' + ('fastcc ' if fast else '')
                   + 'noundef i8 ', line[:symbol.start()])[1]
    args = comparison.arguments(line, symbol.end())
    require(len(args) == len(pointers) + len(lengths), 'staging call arity')
    require([comparison.pointer(arg) for arg in args[:len(pointers)]] == pointers,
            'staging pointer provenance')
    for arg, value in zip(args[len(pointers):], lengths):
        match('i64 noundef ' + re.escape(value), arg)
    require(line.endswith(')'), 'plain staging call suffix')
    return result


def inspect(function, sha3, core, compiler):
    require(compiler in ('1.90.0', '1.98.1'), 'reviewed compiler')
    old = compiler == '1.90.0'
    graph = blocks(function)
    require(len(graph) == 8, 'eight-block squeeze body')
    header = function.splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    params = comparison.arguments(header, symbol.end())
    require(len(params) == 3 and comparison.pointer(params[0]) == '%self'
            and comparison.pointer(params[1]) == '%initialization', 'borrowed producer ABI')
    length = re.search(SSA + '$', params[2])[0]
    write = re.search(comparison.SYMBOL, writing.select(core).splitlines()[0])[1]
    clears = [name for name in comparison.definitions(core) if '18clear_owned_region' in name]
    require(len(clears) == 1, 'unique clear callee')
    loops = [(label, body) for label, body in graph.items() if any('@llvm.umin.i64(' in line for line in body)]
    require(len(loops) == 1, 'one bounded squeeze loop')
    loop, body = loops[0]
    require(len(body) == 5, 'closed chunk/fill/branch block')
    phi = match('(' + SSA + r') = phi i64 \[ ' + re.escape(length)
                + r', %(\S+) \], \[ (' + SSA + r'), %(\S+) \]', body[0])
    remaining, preheader, next_remaining, repeat = phi.groups()
    minimum = match('(' + SSA + r') = tail call noundef i64 @llvm.umin.i64\(i64 '
                    + re.escape(remaining) + r', i64 (136|168)\)', body[1])
    count, rate = minimum.groups()
    callee = re.search(comparison.SYMBOL, body[2])
    require(callee is not None and callee[1] in comparison.definitions(sha3)
            and '12fill_staging' in callee[1] and '6sponge' in callee[1], 'actual fill definition')
    filled = call(body[2], callee[1], ['%self'], [count], fast=True)
    predicate = match('(' + SSA + ') = icmp eq i8 ' + re.escape(filled)
                      + ', ' + ('5' if old else '-1'), body[3])[1]
    edges = match('br i1 ' + re.escape(predicate) + r', label %(\S+), label %(\S+)', body[4])
    transfer, result = edges.groups()
    require(preheader in graph and len(graph[preheader]) == 2, 'closed staging-address block')
    stage = match('(' + SSA + r') = getelementptr inbounds nuw i8, ptr %self, i64 584', graph[preheader][0])[1]
    match('br label %' + re.escape(loop), graph[preheader][1])
    require(transfer in graph and len(graph[transfer]) == 4, 'closed write/clear/result block')
    body = graph[transfer]
    written = call(body[0], write, ['%initialization', stage], [count])
    ok = match('(' + SSA + ') = icmp eq i8 ' + re.escape(written)
               + ', ' + ('4' if old else '-1'), body[1])[1]
    call(body[2], clears[0], [stage], ['168'])
    match('br i1 ' + re.escape(ok) + ', label %' + re.escape(repeat)
          + ', label %' + re.escape(result), body[3])
    require(repeat in graph and len(graph[repeat]) == 3, 'closed progress block')
    body = graph[repeat]
    match(re.escape(next_remaining) + ' = sub nuw i64 ' + re.escape(remaining) + ', ' + re.escape(count), body[0])
    again = match('(' + SSA + ') = icmp ugt i64 ' + re.escape(remaining) + ', ' + rate, body[1])[1]
    complete = match('br i1 ' + re.escape(again) + ', label %' + re.escape(loop) + r', label %(\S+)', body[2])[1]
    require(complete in graph and graph[complete][-1] == 'br label %' + result, 'completion joins result')
    require(result in graph and len(graph[result]) == 2, 'value-free result block')
    value = match('(' + SSA + ') = phi i8 (.+)', graph[result][0])
    entries = re.findall(r'\[ (-?\d+|' + SSA + r'), %(\S+) \]', value[2])
    require(len(entries) == 4 and len({label for _, label in entries}) == 4
            and ', '.join(f'[ {item}, %{label} ]' for item, label in entries) == value[2]
            and dict((label, item) for item, label in entries) ==
            {'start': '2', complete: '5' if old else '-1', loop: filled, transfer: '4'},
            'fill/write errors never become success')
    match('ret i8 ' + re.escape(value[1]), graph[result][1])
    require(len({loop, preheader, transfer, repeat, result, complete, 'start'}) == 7,
            'distinct loop/error blocks')
    return int(rate)


def cases(record):
    record = record.resolve()
    document = json.loads(record.read_text())
    comparison.validate_record(document, record.parent)
    for row in document['records']:
        if row['profile'] != 'release':
            continue
        def artifact(package):
            return next((record.parent / path).read_text() for path in row['artifacts']
                        if Path(path).name.startswith(package + '-') and path.endswith('.ll'))
        sha3, core = artifact('brynja_hash_sha3'), artifact('brynja_core')
        functions = [body for name, body in comparison.definitions(sha3).items()
                     if '6sponge' in name and '14squeeze_secret' in name]
        require(len(functions) == 2, 'both portable XOF rates present')
        compiler = row['compiler'].splitlines()[0].split()[1]
        require({inspect(body, sha3, core, compiler) for body in functions} == {136, 168}, 'both rate identities')
        for function in functions:
            yield function, sha3, core, compiler


def main(record):
    before = comparison.capture.sources()
    count = sum(1 for _ in cases(record))
    require(count == 16 and before == comparison.capture.sources(), 'complete unchanged staging matrix')
    print('Portable secret squeeze staging: 16 optimized loops PASS; both rates in eight configurations')
    print('Bounded fill, exact borrowed write and full 168-byte clear request precede write-result branch')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Not fill/clear callee correctness, whole CFG, debug/accelerated paths, spills or native qualification; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
