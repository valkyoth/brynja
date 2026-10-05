"""All saved worker memcpy/memset call edges, including interior cleanup ranges.

Does not prove pointer lengths, transitive stack bounds, or handler semantics.
"""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_worker_boundaries as workers
import windows_enclave_caller_handlers as handlers
import windows_enclave_route_memory as memory

shared, obj = workers.shared, workers.obj
require, digest = shared.require, shared.digest
COUNTS = (40,47,55,25,88,20,28,20,35,45,61,21,37,26,10,9,23)


def population(data):
    rows, symbols = obj.tables(data); ranges = obj.ranges(data, rows, symbols); result = []
    for index, section in enumerate(rows, 1):
        if not section['flags'] & 0x20000000: continue
        for at, ref in obj.relocations(data, section, symbols).items():
            name = symbols[ref['symbol']]['name']
            if name not in ('memcpy','memset'): continue
            require(ref['kind'] == 4 and 0 < at <= len(section['code'])-4 and
                    section['code'][at-1] in (0xe8,0xe9) and section['code'][at:at+4] == bytes(4),
                    'direct memory call/tail with zero addend')
            scopes = [r for r in ranges if r['section'] == index and r['start'] <= at-1 and at+4 <= r['end']]
            require(len(scopes) == 1, 'exact memory caller runtime range')
            start = scopes[0]['start']
            owners = [s for s in symbols.values() if s['section'] == index and s['kind'] == 0x20 and s['value'] == start]
            require(len(owners) == 1, 'one actual function per runtime start')
            result.append([owners[0]['name'],at-start,name])
    return sorted(result)


def bind_callers(data,image,names,anchors=()):
    records = {}; pending = set(names)
    while pending:
        failures = {}
        for name in sorted(pending):
            try: records[name] = handlers.bind(data,image,name,(*anchors,*records.values()))
            except ValueError as error: failures[name] = str(error)
        require(len(failures) < len(pending), 'unresolved memory caller identities: '+repr(failures))
        pending = set(failures)
    return records


def reconcile(calls,records,targets):
    require(set(records) == {n for n,_,_ in calls}, 'all memory callers bound')
    for name,_,callee in calls:
        require(records[name]['reference_targets'].get(callee) == targets[callee], 'actual reviewed memory destination')


def inspect(data,image,count):
    calls = population(data); require(len(calls) == count, 'complete saved memory call count')
    records = bind_callers(data,image,{n for n,_,_ in calls})
    fills = {r['reference_targets']['memset'] for r in records.values() if 'memset' in r['reference_targets']}
    require(len(fills) == 1, 'one fill runtime shared by all actual callers')
    runtime = memory.inspect(image,next(iter(fills)))
    targets = {'memcpy':runtime['frames']['copy']['rva'], 'memset':runtime['frames']['fill']['rva']}
    reconcile(calls,records,targets)
    return dict(object_sha256=digest(data),image_sha256=digest(image),calls=calls,runtime_targets=targets,
                callers={n:dict(rva=r['rva'],bytes=r['size'],unwind_header=r['unwind_header'],
                               handler_rva=r['handler']['target_rva'] if r['handler'] else None,
                               xdata_rva=r['xdata_rva'],xdata_bytes=r['xdata_bytes'],
                               incoming=r['incoming']) for n,r in records.items()},
                all_direct_memory_edges_bound=True, pointer_lengths_qualified=False,
                handler_semantics_qualified=False, maximum_whole_image_depth_qualified=False,
                live_runtime_selector_initialization_qualified=False, whole_image_qualified=False)


def collect(base,catalog,spec_raw):
    rows = shared.catalog(catalog)[1:]; spec = workers.specification(spec_raw)
    require([r['route'] for r in rows] == [p['route'] for p in spec['profiles']], 'complete route order')
    result = []
    for row,profile,count in zip(rows,spec['profiles'],COUNTS):
        lib = (base/Path(row['object']).parent/'normal_rust.lib').read_bytes()
        require(digest(lib) == profile['archive_sha256'], 'saved worker archive')
        data = workers.archive.members(lib)[profile['member']]; image = (base/row['image']).read_bytes()
        require(digest(data) == profile['object_sha256'] and digest(image) == row['sha256'], 'saved member/image')
        result.append(dict(route=row['route'],**inspect(data,image,count)))
    return dict(schema=1,date='2026-10-05',status='SAVED_WORKER_MEMORY_CALL_BINDINGS',records=result,
                direct_memory_calls=sum(len(r['calls']) for r in result),
                caller_bindings=sum(len(r['callers']) for r in result),
                independently_verified=False,native_run_added=False,release_gate_changed=False,whole_image_qualified=False)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('saved_directory',type=Path)
    p.add_argument('--catalog',type=Path,default=shared.CATALOG); p.add_argument('--spec',type=Path,default=workers.SPEC)
    p.add_argument('--output',type=Path); a = p.parse_args()
    result = collect(a.saved_directory,a.catalog.read_bytes(),a.spec.read_bytes())
    paths = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    paths.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-worker-memory.py')))
    result['source_sha256'] = {p.name:digest(p.read_bytes()) for p in sorted(paths)}
    text = json.dumps(result,indent=2)+'\n'
    if a.output: a.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
