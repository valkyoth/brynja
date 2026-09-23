#!/usr/bin/env python3
"""Retained portable KMAC final-adapter constructor rejection and unwind."""
import argparse
import json
from pathlib import Path
import re

import check_kmac_final_input as forwarding
import check_sha3_owner_wipe as wiping

comparison = forwarding.comparison
require = forwarding.require
SSA = forwarding.SSA


def inspect(function, callees, constructor, invalid_code, wipes):
    require(invalid_code in (6, 18), 'reviewed compiler-private KMAC error layout')
    trace = forwarding.inspect(function, callees, constructor)
    result, _, error, _, _ = trace.input_details
    _, _, _, _, returning, _ = trace.adapter_details
    graph, edges = trace.graph, trace.edges
    block = graph[error]
    require(len(block) == 6, 'closed constructor rejection block')
    lifetime, args = forwarding.adapter.routes.guard.call(block[0])
    require(lifetime == 'llvm.lifetime.end.p0' and args in
            (['ptr nonnull ' + result], ['i64 32', 'ptr nonnull ' + result]), 'end only constructor result on rejection')
    field = re.fullmatch('(' + SSA + r') = getelementptr inbounds nuw i8, ptr %_0, i64 8', block[1])
    require(field is not None and block[2] == f'store i8 {invalid_code}, ptr {field[1]}, align 8'
            and block[3] == 'store i64 2, ptr %_0, align 8', 'value-free error result, never a success descriptor')

    def wipe(line, prefix):
        name, params = forwarding.adapter.routes.guard.call(line)
        require(line.startswith(prefix) and name in wipes and len(params) == 1
                and comparison.pointer(params[0]) == '%self.0'
                and 'HardenedFips202Owner' in name and '4wipe' in name,
                'wipe the original portable owner')
        return name

    name = wipe(block[4], 'tail call void @')
    require(block[5] == 'br label %' + returning, 'rejection returns only after owner cleanup')
    cleanup = edges['start'][0][1]
    unwind = graph[cleanup]
    landing = re.fullmatch('(' + SSA + r') = landingpad \{ ptr, i32 }', unwind[0])
    require(len(unwind) == 4 and landing is not None and unwind[1] == 'cleanup', 'closed constructor unwind cleanup')
    require(wipe(unwind[2], 'invoke void @') == name, 'same original-owner wipe on rejection and unwind')
    resume, terminate = edges[cleanup][0]
    require(graph[resume] == ['resume { ptr, i32 } ' + landing[1]], 'resume original constructor exception after cleanup')
    terminal = graph[terminate]
    require(len(terminal) == 4 and re.fullmatch(SSA + r' = landingpad \{ ptr, i32 }', terminal[0])
            and terminal[1] == 'filter [0 x ptr] zeroinitializer' and terminal[-1] == 'unreachable', 'only double-panic terminal exit')
    panic, params = forwarding.adapter.routes.guard.call(terminal[2])
    require(terminal[2].startswith('tail call void @') and '4core' in panic and '16panic_in_cleanup' in panic
            and params == [''], 'identified cleanup panic callee')
    return trace, name, (error, cleanup, resume, terminate)


def cases(record):
    for row, function, callees in forwarding.adapter.cases(record):
        def artifact(package, suffix):
            paths = [record.parent / path for path in row['artifacts']
                     if Path(path).name.startswith(package + '-') and path.endswith(suffix)]
            require(len(paths) == 1, 'unique source-bound rejection dependency artifact')
            return paths[0].read_text()
        text = artifact('brynja_hash_sha3', '.ll')
        constructor = forwarding.constructor(text)
        code = 6 if row['mode'] == 'portable' else 18
        wipes = forwarding.adapter.routes.early.state_symbols(text)
        _, name, _ = inspect(function, callees, constructor, code, wipes)
        definitions = comparison.definitions(text)
        require(name in forwarding.adapter.routes.early.state_symbols(text), 'bound rejection wipe symbol')
        if name not in definitions:
            targets = re.findall(r'^@' + re.escape(name) + r' = unnamed_addr alias void \(ptr\), ptr @([^\n]+)$', text, re.M)
            require(len(targets) == 1 and targets[0] in definitions, 'unique rejection wipe alias target')
            name = targets[0]
        core, assembly = artifact('brynja_core', '.ll'), artifact('brynja_core', '.s')
        clear = wiping.core_check(core, assembly, row['compiler'].splitlines()[0].split()[1], row['target'].startswith('aarch64'))
        wiping.inspect(definitions[name], clear)
        yield function, callees, constructor, code, wipes


def main(record):
    before = comparison.capture.sources()
    checks = [inspect(*case) for case in cases(record)]
    require(len(checks) == 16 and before == comparison.capture.sources(), 'complete unchanged constructor rejection matrix')
    print('KMAC final rejection: 16 adapters, 64 selected blocks, 32 source-bound complete owner wipes PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Constructor rejection/unwind only; not downstream error conversion, destination clearing, abort cleanup or register/spill erasure')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
