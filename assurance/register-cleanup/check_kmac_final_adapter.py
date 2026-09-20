#!/usr/bin/env python3
"""Retained portable KMAC final-reader adapter success-result handoff."""
import argparse
import json
from pathlib import Path
import re
from types import SimpleNamespace

import check_kmac_reader_results as readers

routes = readers.routes
shape = readers.shape
comparison = routes.comparison
require = routes.require
SSA = routes.SSA


def final_symbols(text):
    definitions = comparison.definitions(text)
    selected = {name for name in definitions if '8in_place3xof' in name and
                '25squeeze_final_bits_secret' in name and '11accelerated' not in name}
    for line in text.splitlines():
        if not (line.startswith('@') and '8in_place3xof' in line and
                '25squeeze_final_bits_secret' in line and '11accelerated' not in line and ' alias ' in line):
            continue
        alias = re.fullmatch(r'@([^ ]+) = unnamed_addr alias void \(ptr, ptr, i1, ptr\), ptr @([^ ]+)', line)
        require(alias is not None, 'portable final-reader alias ABI')
        name, target = alias.groups()
        first = re.search(r'15Cshake(128|256)Reader25squeeze_final_bits_secret', name)
        second = re.search(r'14Shake(128|256)Reader25squeeze_final_bits_secret', target)
        require(first is not None and second is not None and first[1] == second[1]
                and target in selected and target in definitions and name not in selected,
                'unique final-reader alias bound to the matching defined strength')
        header = definitions[target].splitlines()[0]
        symbol = re.search(comparison.SYMBOL, header)
        args = comparison.arguments(header, symbol.end())
        require(header.startswith('define void @') and len(args) == 4 and 'sret([24 x i8])' in args[0]
                and args[1].startswith('ptr ') and args[2].startswith('i1 ') and args[3].startswith('ptr '),
                'portable final-reader alias target ABI')
        selected.add(name)
    return selected


def inspect(function, callees):
    header = function.splitlines()[0]
    symbol = re.search(comparison.SYMBOL, header)
    require(symbol is not None and header.startswith('define void @'), 'portable adapter return ABI')
    parameters = comparison.arguments(header, symbol.end())
    expected = ('%_0', '%self.0', '%self.1', '%output.0', '%output.1', '%valid')
    require(len(parameters) == 6 and 'sret([24 x i8])' in parameters[0]
            and all(arg.endswith(' ' + name) for arg, name in zip(parameters, expected)), 'original adapter parameter identities')
    graph, edges, _ = routes.transfer.finish.graph_info(function)
    trace = SimpleNamespace(graph=graph, edges=edges)
    calls = [(label, index, routes.guard.call(line)) for label, lines in graph.items()
             for index, line in enumerate(lines) if line.startswith('call void @') and '25squeeze_final_bits_secret' in line]
    require(len(calls) == 1, 'one actual portable final-reader call')
    label, index, (name, args) = calls[0]
    require(name in callees and len(args) == 4 and 'sret([24 x i8])' in args[0]
            and comparison.pointer(args[1]) == '%self.0' and args[2] == 'i1 noundef zeroext %self.1',
            'bound reader receives original portable state and lifecycle flag')
    result_match = re.search('(' + SSA + ')$', args[0])
    require(result_match is not None, 'reader result slot')
    result = result_match[1]
    require(result != '%_0' and result + ' = alloca [24 x i8], align 8' in graph['start'], 'distinct bounded reader result allocation')
    suffix = graph[label][index + 1:]
    require(len(suffix) == 3, 'closed reader return-to-decision slice')
    loaded = re.fullmatch('(' + SSA + r') = load i64, ptr ' + re.escape(result) + ', align 8', suffix[0])
    require(loaded is not None, 'read this reader result discriminator')
    tested = re.fullmatch('(' + SSA + r') = icmp eq i64 ' + re.escape(loaded[1]) + ', 2', suffix[1])
    require(tested is not None, 'reader error discriminator')
    condition, error, success = shape.branch(trace, label)
    require(condition == tested[1] and error != success, 'successful reader result uses non-error edge')
    copying = graph[success]
    require(len(copying) == 2 and copying[0].startswith('call void @llvm.memcpy.p0.p0.i64('), 'closed descriptor success-copy block')
    _, copy_args = routes.guard.call(copying[0])
    require(len(copy_args) == 4 and comparison.pointer(copy_args[0]) == '%_0'
            and comparison.pointer(copy_args[1]) == result and copy_args[2:] == ['i64 24', 'i1 false'],
            'copy the complete reader result, not payload or a different descriptor')
    branch = re.fullmatch(r'br label %(' + shape.LABEL + ')', copying[1])
    require(branch is not None, 'success copy reaches the return block')
    returning = graph[branch[1]]
    require(len(returning) in (2, 3) and returning[-1] == 'ret void', 'no write or other work after success-copy')
    if len(returning) == 3:
        name, args = routes.guard.call(returning[0])
        staging = comparison.pointer(args[-1])
        require(name == 'llvm.lifetime.end.p0' and args in
                (['ptr nonnull ' + staging], ['i64 23', 'ptr nonnull ' + staging])
                and staging + ' = alloca [23 x i8], align 4' in graph['start'], 'only bounded local staging lifetime may also end')
    lifetime, lifetime_args = routes.guard.call(returning[-2])
    require(lifetime == 'llvm.lifetime.end.p0' and lifetime_args in
            (['ptr nonnull ' + result], ['i64 24', 'ptr nonnull ' + result]), 'only the local result lifetime ends before return')
    shape.unreachable(trace, 'start', {success}, (label, success))
    shape.unreachable(trace, error, {success, label})
    trace.adapter_blocks = {label, success, branch[1]}
    trace.adapter_details = (label, index, error, success, branch[1], result)
    return trace


def cases(record):
    for row, _, _, _, verifiers in routes.early.cases(record):
        texts = {}
        for package in ('brynja_mac_kmac-', 'brynja_hash_sha3-'):
            paths = [record.parent / path for path in row['artifacts'] if Path(path).name.startswith(package) and path.endswith('.ll')]
            require(len(paths) == 1, 'unique validated adapter dependency artifact')
            texts[package] = paths[0].read_text()
        kmac = comparison.definitions(texts['brynja_mac_kmac-'])
        callees = final_symbols(texts['brynja_hash_sha3-'])
        selected = set()
        for verifier in verifiers:
            for lines in routes.guard.metadata.model.blocks(verifier).values():
                for line in lines:
                    if line.startswith('invoke void @') and '12final_secret' in line:
                        name, _ = routes.guard.call(line)
                        require(name in kmac and 'accelerated' not in name, 'verifier-bound portable final adapter')
                        selected.add(name)
        require(len(selected) == 2, 'both portable KMAC strengths in each optimized build')
        for name in sorted(selected):
            yield row, kmac[name], callees


def main(record):
    before = comparison.capture.sources()
    functions = blocks = 0
    for _, function, callees in cases(record):
        trace = inspect(function, callees)
        functions += 1
        blocks += len(trace.adapter_blocks)
    require((functions, blocks) == (16, 48) and before == comparison.capture.sources(), 'complete unchanged final-adapter matrix')
    print(f'KMAC final adapter: {functions} verifier-bound portable adapters, {blocks} selected blocks PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Successful descriptor handoff only; not output-constructor/reader semantics, all error cleanup/encoding, alias effects or register/spill erasure')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
