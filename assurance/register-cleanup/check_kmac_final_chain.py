#!/usr/bin/env python3
"""Compose retained KMAC final metadata, reader lifecycle and tail dependencies."""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re

import check_fips202_output_constructor as constructor
import check_kmac_final_rejection as rejection
import check_kmac_final_error as conversion
import check_sha3_final_reader as reader
import check_sha3_output_completion as completion
import check_secret_output_begin as begin
import check_secret_output_drop as dropping
import check_sha3_final_tail as tail
import check_sha3_squeeze_counter as counter
import check_sha3_fill_dependencies as filling

adapter = reader.adapter
comparison = reader.comparison
require = reader.require


@dataclass(frozen=True)
class Case:
    caller: str
    sha3: str
    core: str
    sha3_assembly: str
    core_assembly: str
    compiler: str
    mode: str
    arm: bool
    bulk: str


def symbol(body):
    match = re.search(comparison.SYMBOL, body.splitlines()[0])
    require(match is not None, 'defined dependency symbol')
    return match[1]


def resolve(text, definitions, name, signature):
    if name not in definitions:
        targets = re.findall(r'^@' + re.escape(name) + ' = unnamed_addr alias '
                             + re.escape(signature) + r', ptr @([^\n]+)$', text, re.M)
        require(len(targets) == 1 and targets[0] in definitions, 'same-row defined alias target')
        name = targets[0]
    return definitions[name]


def bulk_bridge(function, borrowed):
    """Bulk and final calls must use the same borrowed state implementation."""
    header = function.splitlines()[0]
    params = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
    require(header.startswith('define void @') and len(params) == 4
            and 'sret([24 x i8])' in params[0] and params[0].endswith(' %_0')
            and params[1].startswith('ptr noalias ') and 'dereferenceable(16)' in params[1]
            and comparison.pointer(params[1]) == '%self'
            and params[2].startswith('ptr noalias ') and comparison.pointer(params[2]) == '%destination.0'
            and params[3].startswith('i64 ') and params[3].endswith(' %destination.1'),
            'original result, exclusive borrowed handle and complete destination')
    graph, _, _ = adapter.routes.transfer.finish.graph_info(function)
    require(set(graph) == {'start'} and len(graph['start']) == 2
            and graph['start'][1] == 'ret void', 'closed bulk forwarding with no payload work')
    line = graph['start'][0]
    name, args = adapter.routes.guard.call(line)
    require(line.startswith('tail call fastcc void @') and name == borrowed and len(args) == 6
            and 'sret' not in args[0] and comparison.pointer(args[0]) == '%_0'
            and comparison.pointer(args[1]) == '%self' and comparison.pointer(args[2]) == '%destination.0'
            and all(args[index].startswith('ptr noalias ') for index in range(3))
            and args[3:] == ['i64 noundef %destination.1', 'i1 noundef zeroext false', 'i8 undef'],
            'actual same-row borrowed reader receives original arguments in bulk mode')
    # The unused Option payload is undef, not a secret scalar or valid-bit
    # assertion. The composed active-reader checker verifies that only the
    # true/final branch reads it for final-bit work.


def inspect(case, *, thorough=True):
    """No global symbol pool: every dependency is selected from this row."""
    definitions = comparison.definitions(case.sha3)
    core_defs = comparison.definitions(case.core)
    finals = adapter.final_symbols(case.sha3)
    construct = rejection.forwarding.constructor(case.sha3)
    wipes = {name for name in adapter.routes.early.state_symbols(case.sha3)
             if 'HardenedFips202Owner' in name and '4wipe' in name}
    require(case.mode in conversion.MAPPINGS, 'recorded feature layout')
    trace, _, _ = rejection.inspect(case.caller, finals, construct,
                                    6 if case.mode == 'portable' else 18, wipes)
    conversion.inspect(case.caller, finals, case.mode)
    label, index, *_ = trace.adapter_details
    public, _ = adapter.routes.guard.call(trace.graph[label][index])
    public_body = resolve(case.sha3, definitions, public, 'void (ptr, ptr, i1, ptr)')
    _, _, borrowed = reader.inspect(public_body, definitions, wipes)
    bulk_bridge(resolve(case.sha3, definitions, case.bulk, 'void (ptr, ptr, ptr, i64)'), borrowed)

    initializer, zero = begin.select(case.core)
    drop, destructor = dropping.select(case.core)
    finish = completion.finish.select(case.core)
    writer = tail.ownership.writing.select(case.core)
    clear = tail.ownership.wiping.core_check(case.core, case.core_assembly, case.compiler, case.arm)
    begin.inspect(initializer, zero)
    dropping.inspect(destructor, zero)
    completion.finish.inspect(finish)
    calls = [re.search(comparison.SYMBOL, line)[1] for line in finish.splitlines() if 'tail call' in line]
    require(calls == [zero], 'actual finish cleanup uses same-row volatile implementation')
    tail.ownership.writing.inspect(writer, case.compiler)
    copies = [name for name in core_defs if 'secret_memory_transfer10copy_bytes' in name]
    called = [re.search(comparison.SYMBOL, line)[1] for line in writer.splitlines()
              if 'tail call fastcc void @' in line]
    require(len(copies) == 1 and called == copies, 'actual output writer uses same-row defined copy primitive')
    require(re.search(r'^' + re.escape(copies[0]) + ':', case.core_assembly, re.M), 'matching output-copy assembly identity')
    tail.ownership.writing.copy_boundary.inspect(case.core_assembly, case.arm)
    for name in wipes:
        tail.ownership.wiping.inspect(resolve(case.sha3, definitions, name, 'void (ptr)'), clear)

    body = definitions[borrowed]
    headers = {name: value.splitlines()[0] for name, value in definitions.items()}
    args = (body, symbol(initializer), wipes, drop, set(definitions))
    completion.inspect(*args, headers, symbol(finish))
    _, _, routes, _ = completion.active.inspect(*args)
    final, bulk = routes[0][1], routes[1][1]
    fills = [name for name in definitions if '12fill_staging' in name and '@' + name + '(' in definitions[bulk]]
    masks = [name for name in core_defs if '22apply_secret_byte_mask' in name]
    require(len(fills) == len(masks) == 1, 'actual same-row fill and mask definitions')
    fill, mask = fills[0], masks[0]
    bulk_args = (symbol(writer), clear, bulk, case.compiler, fill)
    _, _, _, rate = counter.progress.inspect(definitions[bulk], *bulk_args)
    counter_cases = counter.inspect(definitions[bulk], *bulk_args, thorough=thorough)
    _, _, tail_cases = tail.inspect(definitions[final], *bulk_args, mask, thorough=thorough)
    tail.dependency(case.core, case.core_assembly, case.arm)
    fill_cases = filling.inspect(definitions[fill], case.sha3, case.core, case.compiler,
                                 case.sha3_assembly, case.core_assembly, case.arm, fill, rate, thorough=thorough)
    # The constructor's exhaustive byte-domain check is reused, not modeled a
    # second time. Its output descriptor is forwarded unchanged above.
    constructor_cases = constructor.inspect(definitions[construct])
    return constructor_cases, counter_cases, tail_cases, fill_cases


def cases(record):
    for row, verifier, *_ in adapter.routes.cases(record):
        invoked = [adapter.routes.guard.call(line)[0] for line in verifier.splitlines()
                   if line.strip().startswith('invoke void @')]
        finals = [name for name in invoked if '12final_secret' in name and 'accelerated' not in name]
        if not finals:
            continue  # Accelerated verifier readers are a separate contract.
        bulks = [name for name in invoked if '14squeeze_secret' in name and 'accelerated' not in name]
        require(len(finals) == len(bulks) == 1, 'one actual bulk/final pair in the selected verifier')
        def artifact(package, suffix):
            paths = [record.parent / path for path in row['artifacts']
                     if Path(path).name.startswith(package + '-') and path.endswith(suffix)]
            require(len(paths) == 1, 'one same-row dependency artifact')
            return paths[0].read_text()
        kmac = comparison.definitions(artifact('brynja_mac_kmac', '.ll'))
        require(finals[0] in kmac, 'defined same-row final adapter')
        caller = kmac[finals[0]]
        yield Case(caller, artifact('brynja_hash_sha3', '.ll'), artifact('brynja_core', '.ll'),
                   artifact('brynja_hash_sha3', '.s'), artifact('brynja_core', '.s'),
                   row['compiler'].splitlines()[0].split()[1], row['mode'], row['target'].startswith('aarch64'), bulks[0])


def main(record):
    before = comparison.capture.sources()
    results = [inspect(case) for case in cases(record)]
    require(len(results) == 16 and before == comparison.capture.sources(), 'complete unchanged final-chain matrix')
    totals = [sum(values) for values in zip(*results)]
    print(f'KMAC final chain: 16 same-row paths; constructor/counter/tail/fill cases={totals} PASS')
    print('Actual metadata rejection, original descriptor forwarding, reader lifecycle and cleanup dependencies composed')
    print('Both actual bulk/final verifier routes bind to the same borrowed reader; bulk forwards no payload values')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Existing bounded/structural contracts, not whole-call register/spill erasure; Arm remains QEMU; no release-gate change')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
