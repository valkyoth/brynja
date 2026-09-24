#!/usr/bin/env python3
"""Retained accelerated KMAC reader forwarding and consuming cleanup boundary."""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re

import check_kmac_final_chain as chain
import check_accelerated_staging as staging

adapter, comparison, require = chain.adapter, chain.comparison, chain.require
SSA = adapter.SSA


@dataclass(frozen=True)
class Case:
    bulk: str
    final: str
    sha3: str
    core: str
    assembly: str
    compiler: str
    arm: bool


def assigned(line, pattern):
    match = re.fullmatch('(' + SSA + ') = ' + pattern, line)
    require(match is not None, 'accelerated reader instruction: ' + line)
    return match[1]


def arguments(function):
    header = function.splitlines()[0]
    match = re.search(comparison.SYMBOL, header)
    require(match is not None, 'defined accelerated reader dependency')
    return comparison.arguments(header, match.end())


def clear_storage(lines, base, wipe, clear):
    """Exact metadata transition and complete owned-region wipe requests."""
    require(len(lines) == 11 and lines[-1] == 'ret void', 'closed storage cleanup')
    for index, offset, store in ((0, 859, 'store i8 1'), (2, 616, 'store i64 0')):
        pointer = assigned(lines[index], 'getelementptr inbounds nuw i8, ptr ' + re.escape(base) + ', i64 ' + str(offset))
        require(lines[index + 1] == store + ', ptr ' + pointer + ', align ' + ('1' if index == 0 else '8'),
                'terminal engine and reset cursor in original storage')
    for index, offset, width, callee in ((4, 624, None, wipe), (6, 864, 168, clear), (8, 1056, 2, clear)):
        pointer = assigned(lines[index], 'getelementptr inbounds nuw i8, ptr ' + re.escape(base) + ', i64 ' + str(offset))
        name, args = adapter.routes.guard.call(lines[index + 1])
        require(name == callee and comparison.pointer(args[0]) == pointer
                and len(args) == (1 if width is None else 2), 'actual original storage cleanup callee')
        if width is not None:
            require(re.match(SSA + r' = tail call noundef i8 @', lines[index + 1])
                    and args[1] == f'i64 noundef {width}', 'complete stage/domain clear request')
        else:
            require(re.match(r'tail call (?:fastcc )?void @', lines[index + 1]), 'normal memory wipe call')


def memory_wipe(function, clear):
    params = arguments(function)
    require(function.startswith(('define void @', 'define internal fastcc void @'))
            and len(params) == 1 and params[0].startswith('ptr noalias ')
            and 'dereferenceable(234)' in params[0], 'exclusive actual engine memory')
    base = comparison.pointer(params[0])
    graph, _, origin = adapter.routes.transfer.finish.graph_info(function)
    require(set(graph) == {'start'} and graph['start'][-1] == 'ret void', 'straight-line memory wipe')
    regions = []
    for line in graph['start'][:-1]:
        if re.fullmatch(SSA + r' = getelementptr inbounds nuw i8, ptr ' + re.escape(base) + r', i64 (16|32|232)', line):
            continue
        require(re.match(SSA + r' = tail call noundef i8 @', line), 'only clear calls in memory wipe')
        name, args = adapter.routes.guard.call(line)
        require(name == clear and len(args) == 2, 'memory wipe uses bound core clearing')
        root, offset = origin(comparison.pointer(args[0]))
        width = re.fullmatch(r'i64 noundef (\d+)', args[1])
        require(root == base and width is not None, 'original fixed owned region')
        regions.append((offset, int(width[1])))
    require(regions == [(32, 200), (0, 16), (16, 16), (232, 2)], 'all 234 owned engine bytes cleared')


def bulk(function, borrowed):
    params = arguments(function)
    require(function.startswith('define void @') and len(params) == 4
            and 'sret([24 x i8])' in params[0] and params[0].endswith(' %_0')
            and params[1].startswith('ptr noalias ') and 'dereferenceable(8)' in params[1]
            and comparison.pointer(params[1]) == '%self' and comparison.pointer(params[2]) == '%output.0'
            and params[3].startswith('i64 ') and params[3].endswith(' %output.1'), 'bulk reader original ABI')
    graph, _, _ = adapter.routes.transfer.finish.graph_info(function)
    require(set(graph) == {'start'} and len(graph['start']) == 3 and graph['start'][-1] == 'ret void', 'closed pointer-only bulk bridge')
    owner = assigned(graph['start'][0], r'load ptr, ptr %self, align 8')
    call = graph['start'][1]
    name, args = adapter.routes.guard.call(call)
    require(call.startswith('tail call fastcc void @') and name == borrowed and len(args) == 6
            and [comparison.pointer(arg) for arg in args[:3]] == ['%_0', owner, '%output.0']
            and args[3:] == ['i64 noundef %output.1', 'i1 noundef zeroext false', 'i8 undef'],
            'original loaded storage, destination and length in bulk mode')


def final(function, definitions, borrowed, wipe, clear):
    params = arguments(function)
    require(function.startswith('define void @') and len(params) == 5
            and 'sret([24 x i8])' in params[0] and params[0].endswith(' %_0')
            and params[1].startswith('ptr noalias ') and 'dereferenceable(1088)' in params[1]
            and comparison.pointer(params[2]) == '%output.0'
            and params[3] in ('i64 noundef %output.1', 'i64 noundef range(i64 0, -9223372036854775808) %output.1')
            and params[4] == 'i8 noundef %valid_bits',
            'consuming final reader original ABI')
    base = comparison.pointer(params[1])
    graph, edges, _ = adapter.routes.transfer.finish.graph_info(function)
    require(len(graph['start']) == 2, 'one final-reader invoke')
    name, args = adapter.routes.guard.call(graph['start'][0])
    require(graph['start'][0].startswith('invoke fastcc void @') and name == borrowed and len(args) == 6
            and [comparison.pointer(arg) for arg in args[:3]] == ['%_0', base, '%output.0']
            and args[3:] == ['i64 noundef %output.1', 'i1 noundef zeroext true', 'i8 %valid_bits'],
            'final mode forwards original storage/output/valid bits to actual borrowed reader')
    normal, cleanup = edges['start'][0]
    clear_storage(graph[normal], base, wipe, clear)
    lines = graph[cleanup]
    require(len(lines) == 4 and lines[1] == 'cleanup', 'closed final-reader unwind')
    landing = assigned(lines[0], r'landingpad \{ ptr, i32 }')
    drop, args = adapter.routes.guard.call(lines[2])
    require(lines[2].startswith('invoke fastcc void @') and drop in definitions
            and 'accelerated' in drop and ('8in_place3xof' in drop or '..in_place..xof..' in drop)
            and ('drop_in_place' in drop or 'drop_glue' in drop)
            and len(args) == 1 and comparison.pointer(args[0]) == base, 'same-storage defined unwind destructor')
    destructor = definitions[drop]
    drop_params = arguments(destructor)
    require(destructor.startswith('define internal fastcc void @') and len(drop_params) == 1,
            'destructor original storage parameter and calling convention')
    drop_base = comparison.pointer(drop_params[0])
    blocks, _, _ = adapter.routes.transfer.finish.graph_info(destructor)
    require(set(blocks) == {'start'} and len(blocks['start']) == 13, 'closed actual unwind destructor')
    flag = assigned(blocks['start'][0], 'icmp ne ptr ' + re.escape(drop_base) + ', null')
    require(blocks['start'][1] == 'tail call void @llvm.assume(i1 ' + flag + ')', 'assumption about original nonnull borrow only')
    clear_storage(blocks['start'][2:], drop_base, wipe, clear)
    resume, terminate = edges[cleanup][0]
    require(graph[resume] == ['resume { ptr, i32 } ' + landing], 'resume original exception after storage cleanup')
    terminal = graph[terminate]
    require(len(terminal) == 4 and re.fullmatch(SSA + r' = landingpad \{ ptr, i32 }', terminal[0])
            and terminal[1] == 'filter [0 x ptr] zeroinitializer' and terminal[-1] == 'unreachable', 'double-panic-only excluded exit')
    panic, args = adapter.routes.guard.call(terminal[2])
    require(terminal[2].startswith('tail call void @') and '4core' in panic and '16panic_in_cleanup' in panic and args == [''],
            'identified double-panic termination')
    require(set(graph) == {'start', normal, cleanup, resume, terminate}, 'complete final-reader block inventory')
    return drop


def inspect(case):
    definitions = comparison.definitions(case.sha3)
    symbols = adapter.routes.reader_symbols(case.sha3)
    require(case.bulk in symbols and case.final in symbols, 'actual defined or reviewed-aliased readers')
    borrowed = staging.unique(definitions, 'accelerated', '8Borrowed6secret')
    params = arguments(definitions[borrowed])
    require(definitions[borrowed].startswith('define internal fastcc void @') and len(params) == 6
            and 'dereferenceable(24)' in params[0] and comparison.pointer(params[0]) == '%_0'
            and all(arg.startswith(kind + ' ') for arg, kind in zip(params, ('ptr', 'ptr', 'ptr', 'i64', 'i1', 'i8'))),
            'actual borrowed producer ABI matches both reader calls')
    wipe = staging.unique(definitions, 'accelerated', '6Memory4wipe')
    clear = chain.tail.ownership.wiping.core_check(case.core, case.assembly, case.compiler, case.arm)
    memory_wipe(definitions[wipe], clear)
    bulk(chain.resolve(case.sha3, definitions, case.bulk, 'void (ptr, ptr, ptr, i64)'), borrowed)
    drop = final(chain.resolve(case.sha3, definitions, case.final, 'void (ptr, ptr, ptr, i64, i8)'), definitions, borrowed, wipe, clear)
    staging.inspect(case.sha3, case.core, case.compiler)
    return borrowed, wipe, clear, drop


def cases(record):
    for row, verifier, *_ in adapter.routes.cases(record):
        calls = [adapter.routes.guard.call(line)[0] for line in verifier.splitlines() if line.strip().startswith('invoke void @')]
        finals = [name for name in calls if 'accelerated' in name and '25squeeze_final_bits_secret' in name]
        if not finals:
            continue
        bulks = [name for name in calls if 'accelerated' in name and '14squeeze_secret' in name]
        require(len(finals) == len(bulks) == 1, 'actual accelerated verifier reader pair')
        def artifact(package, suffix):
            paths = [record.parent / path for path in row['artifacts'] if Path(path).name.startswith(package + '-') and path.endswith(suffix)]
            require(len(paths) == 1, 'same-row dependency artifact')
            return paths[0].read_text()
        yield Case(bulks[0], finals[0], artifact('brynja_hash_sha3', '.ll'), artifact('brynja_core', '.ll'),
                   artifact('brynja_core', '.s'), row['compiler'].splitlines()[0].split()[1], row['target'].startswith('aarch64'))


def main(record):
    before = comparison.capture.sources()
    checks = [inspect(case) for case in cases(record)]
    require(len(checks) == 8 and before == comparison.capture.sources(), 'complete unchanged accelerated reader matrix')
    print('Accelerated KMAC readers: 8 actual bulk/final pairs, same-storage normal/unwind cleanup and 234-byte engine wipe PASS')
    print('168-byte staging and two-byte domain clearing bind to actual core volatile implementation; existing producer error-path checks pass')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Reader boundary and cleanup, not complete producer/ISA/machine-spill qualification; Arm remains QEMU; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
