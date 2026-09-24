#!/usr/bin/env python3
"""Bind reader-selected staging geometry to actual copy, clear and scalar callees."""
import argparse
import json
from pathlib import Path
import re
from types import SimpleNamespace

import check_sha3_fill as fill
import check_sha3_squeeze_progress as progress
import check_keccak_scalar as scalar
import check_secret_copy as copying

comparison = progress.comparison
require = progress.require
SSA = progress.SSA
assign = progress.assignment


def copy_bridge(function, copy_bytes, compiler):
    """Three-block length-checked borrowed-copy wrapper, with no secret loads."""
    header = function.splitlines()[0]
    params = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
    require(len(params) == 4 and comparison.pointer(params[0]) == '%destination.0'
            and comparison.pointer(params[2]) == '%input.0'
            and params[1].endswith(' %destination.1') and params[3].endswith(' %input.1')
            and all(params[i].startswith('ptr noalias ') for i in (0, 2)),
            'exclusive original copy slices')
    graph, edges, _ = progress.adapter.routes.transfer.finish.graph_info(function)
    trace = SimpleNamespace(graph=graph, edges=edges)
    require(len(graph['start']) == 2, 'closed copy-length decision')
    tested = assign(graph['start'][0], r'icmp eq i64 %destination\.1, %input\.1', 'matching slice lengths')
    condition, copying_label, returning = progress.adapter.shape.branch(trace, 'start')
    require(condition == tested and set(graph) == {'start', copying_label, returning}, 'complete copy bridge graph')
    lines = graph[copying_label]
    require(len(lines) == 2 and lines[0].startswith('tail call fastcc void @'), 'one value-free copy call')
    name, args = progress.adapter.routes.guard.call(lines[0])
    require(name == copy_bytes and len(args) == 3 and comparison.pointer(args[0]) == '%destination.0'
            and comparison.pointer(args[1]) == '%input.0'
            and re.fullmatch(r'i64 noundef (?:range\(i64 0, -9223372036854775808\) )?%destination\.1', args[2]),
            'bound copy receives original pointers and entire checked length')
    require(lines[1] == 'br label %' + returning, 'copy returns directly')
    require(compiler in ('1.90.0', '1.98.1'), 'reviewed copy compiler')
    success = '4' if compiler == '1.90.0' else '-1'
    lines = graph[returning]
    require(len(lines) == 2, 'closed copy result')
    result = assign(lines[0], r'phi i8 \[ ' + success + ', %' + re.escape(copying_label)
                    + r' \], \[ 2, %start \]', 'copy result preserves length rejection')
    require(lines[1] == 'ret i8 ' + result, 'actual copy result returned')


def inspect(function, sha3, core, compiler, sha3_assembly, core_assembly, arm, name, rate, *, thorough=True):
    definitions = comparison.definitions(sha3)
    require(re.search(comparison.SYMBOL, function.splitlines()[0])[1] == name
            and name in definitions, 'actual reader-selected fill definition')
    actual_rate, count = fill.inspect(function, sha3, core, compiler, thorough=thorough)
    require(actual_rate == rate, 'fill rate matches its bound bulk caller')
    core_defs = comparison.definitions(core)
    copy = fill.shared.unique(core_defs, '18copy_secret_region')
    copy_bytes = fill.shared.unique(core_defs, 'secret_memory_transfer10copy_bytes')
    copy_bridge(core_defs[copy], copy_bytes, compiler)
    require(re.search(r'^' + re.escape(copy_bytes) + ':', core_assembly, re.M), 'actual copy assembly identity')
    copying.inspect(core_assembly, arm)
    permutation = fill.shared.unique(definitions, '11permutation6native6scalar')
    require(re.search(r'^' + re.escape(permutation) + ':', sha3_assembly, re.M), 'actual scalar permutation assembly identity')
    scalar.inspect(sha3_assembly, arm)
    progress.ownership.wiping.core_check(core, core_assembly, compiler, arm)
    return count


def cases(record):
    selected = {}
    for bulk, *args in progress.cases(record):
        *_, rate = progress.inspect(bulk, *args)
        binding = (args[-1], rate)
        require(bulk not in selected or selected[bulk] == binding, 'consistent identical-body fill binding')
        selected[bulk] = binding
    covered = set()
    for row, _, core, core_assembly in comparison.cases(record):
        if row['profile'] != 'release':
            continue
        def artifact(suffix):
            paths = [record.parent / path for path in row['artifacts']
                     if Path(path).name.startswith('brynja_hash_sha3-') and path.endswith(suffix)]
            require(len(paths) == 1, 'one retained SHA-3 dependency artifact')
            return paths[0].read_text()
        sha3, assembly = artifact('.ll'), artifact('.s')
        definitions = comparison.definitions(sha3)
        callers = [body for body in definitions.values() if body in selected]
        require(len(callers) == 2, 'both reader-selected bulk rates in each retained configuration')
        for bulk in callers:
            name, rate = selected[bulk]
            covered.add(bulk)
            require(name in definitions, 'defined fill from same reader artifact')
            # Keep assembly and LLVM together by record row, even when compiler
            # bodies are byte-identical across different targets/build modes.
            yield (definitions[name], sha3, core, row['compiler'].splitlines()[0].split()[1],
                   assembly, core_assembly, row['target'].startswith('aarch64'), name, rate)
    require(covered == set(selected), 'all reader-selected fills covered')


def main(record):
    before = comparison.capture.sources()
    counts = [inspect(*case) for case in cases(record)]
    require(len(counts) == 16 and before == comparison.capture.sources(), 'complete unchanged reader-bound fill matrix')
    print(f'Reader-bound staging dependencies: 16 bodies; {sum(counts)} geometry/error cases PASS')
    print('Actual copy wrapper and copy/scalar return-boundary assembly checked; scratch clearing binds to core volatile implementation')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Composition of bounded models and existing assembly checks, not a new algorithm proof, whole-call erasure or native qualification; Arm remains QEMU')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
