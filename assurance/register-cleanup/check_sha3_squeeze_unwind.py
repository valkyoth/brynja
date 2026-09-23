#!/usr/bin/env python3
"""Retained squeeze unwind: drop original output, wipe owner, resume exception."""
import argparse
import json
from pathlib import Path
import re

import check_sha3_active_output as active

adapter = active.adapter
comparison = active.comparison
require = active.require
SSA = active.SSA
LABEL = adapter.shape.LABEL


def inspect(function, begin, wipes, drop, callees):
    trace, _, routes, (work, output, owner) = active.inspect(function, begin, wipes, drop, callees)
    graph = trace.graph
    unwind = routes[0][3]
    lines = graph[unwind]
    require(len(lines) == 5, 'closed squeeze exception landing pad')
    exception = re.fullmatch('(' + SSA + r') = landingpad \{ ptr, i32 }', lines[0])
    require(exception is not None and lines[1] == 'cleanup', 'original squeeze exception')
    present = re.fullmatch('(' + SSA + r') = load i64, ptr ' + re.escape(work) + ', align 8', lines[2])
    require(present is not None, 'original operation output ownership')
    condition = re.fullmatch('(' + SSA + r') = icmp eq i64 ' + re.escape(present[1]) + ', 0', lines[3])
    tested, owner_cleanup, output_cleanup = adapter.shape.branch(trace, unwind)
    require(condition is not None and tested == condition[1] and owner_cleanup != output_cleanup,
            'only absent output ownership skips destination cleanup')
    dropping = graph[output_cleanup]
    require(len(dropping) == 2 and dropping[0].startswith('invoke void @'), 'one exceptional destination destructor')
    name, args = adapter.routes.guard.call(dropping[0])
    require(name == drop and len(args) == 1 and comparison.pointer(args[0]) == output,
            'verified destructor receives original initialization handle')
    completed, double_output = trace.edges[output_cleanup][0]
    require(completed == owner_cleanup, 'owner wipe follows successful destination cleanup')
    cleanup = graph[owner_cleanup]
    require(len(cleanup) == 3 and cleanup[1].startswith('invoke void @'), 'closed owner cleanup continuation')
    phi = re.fullmatch('(' + SSA + r') = phi \{ ptr, i32 } \[ (' + SSA + '), %(' + LABEL
                       + r') \], \[ ' + re.escape(exception[1]) + ', %' + re.escape(output_cleanup)
                       + r' \], \[ ' + re.escape(exception[1]) + ', %' + re.escape(unwind) + r' \]', cleanup[0])
    require(phi is not None, 'original squeeze exception survives destination cleanup')
    extra = graph[phi[3]]
    require(extra == [phi[2] + ' = landingpad { ptr, i32 }', 'cleanup', 'br label %' + owner_cleanup],
            'separate cleanup exception enters the same owner guard')
    name, args = adapter.routes.guard.call(cleanup[1])
    require(name in wipes and len(args) == 1 and comparison.pointer(args[0]) == owner,
            'bound wipe receives the original borrowed owner')
    resume, double_owner = trace.edges[owner_cleanup][0]
    require(graph[resume] == ['resume { ptr, i32 } ' + phi[1]], 'resume selected original exception only after both cleanups')
    for terminal in (double_output, double_owner):
        block = graph[terminal]
        require(len(block) == 4 and re.fullmatch(SSA + r' = landingpad \{ ptr, i32 }', block[0])
                and block[1] == 'filter [0 x ptr] zeroinitializer' and block[-1] == 'unreachable',
                'identified double-panic termination only')
        panic, params = adapter.routes.guard.call(block[2])
        require(block[2].startswith('call void @') and '4core' in panic and '16panic_in_cleanup' in panic
                and params == [''], 'only core cleanup-panic terminal excluded')
    require(len({unwind, output_cleanup, owner_cleanup, phi[3], resume, double_output, double_owner}) == 7,
            'distinct complete reviewed unwind blocks')
    return trace, (unwind, output_cleanup, owner_cleanup, phi[3], resume, double_output, double_owner)


def main(record):
    before = comparison.capture.sources()
    checks = [inspect(*case) for case in active.cases(record)]
    require(len(checks) == 16 and before == comparison.capture.sources(), 'complete unchanged squeeze-unwind matrix')
    print('Squeeze unwind: 16 readers, 32 squeeze invoke edges, 112 selected blocks; destination Drop then original-owner wipe PASS')
    print('Original exception resumed after cleanup; double-panic termination explicitly excluded')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Exceptional caller routing only; assumes callee preserves ownership descriptor, excludes abort and whole-call register/spill erasure')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
