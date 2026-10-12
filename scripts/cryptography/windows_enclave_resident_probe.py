"""Native public vectors and resident-staging failure controls; not qualification."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import windows_enclave_isolated_probe as original
from windows_enclave_resident_lock import Resident, flags_check

require = original.require


def cases():
    return original.cases() + [(name,b'abc',status,0) for name,status in
        [('deny-stage',17), ('after-stage-lock',17), ('stage-observe',18), ('partial-input',14)]]


def expected_events(name, body):
    if name in ('bad-descriptor','oversize','unknown-control','identity-drift'):
        return [], set()
    events = ['stage-admit']
    snapshots = set()
    if name == 'deny-stage':
        events += ['stage-deny']
    else:
        events += ['stage-lock']
        snapshots |= {'before','admitted','cleared'}
        if name == 'after-stage-lock': events += ['stage-reject-after-lock']
        elif name not in ('bad-input','partial-input'):
            events += ['stage-observe']
            snapshots.add('staged')
            if name == 'stage-observe': events += ['stage-reject-observe']
    if body or name == 'deny': events += ['window-0','window-1']
    events += ['stage-clear-confirmed']
    if name != 'deny-stage': events += ['stage-unlock']
    return events+['stage-finish'], snapshots


def validate(rows):
    require(type(rows) is list and len(rows) == len(cases()), 'complete resident campaign')
    for row,(name,_,status,body) in zip(rows,cases(),strict=True):
        events,names = expected_events(name,body)
        allocated = bool(events)
        require(set(row) == {'case','status','observations','events','snapshots','window_trace','reentry'},
                'canonical resident row')
        require(row['case'] == name and type(row['status']) is int and row['status'] == status,
                'ordered status')
        require(type(row['observations']) is list and all(type(v) is int for v in row['observations'])
                and row['observations'] == [body,int(status == 1),status,1,4096*allocated,int(allocated)],
                'full-page retirement and mapping release')
        require(row['events'] == events and set(row['snapshots']) == names, 'exact staging lifecycle')
        for label,flags in row['snapshots'].items(): flags_check(flags,4096,label != 'before')
        trace = ['admit','lock','all-pages-locked','admit-ack','clear-confirmed','still-locked','unlock','finish-ack']
        require(row['window_trace'] == (trace if body else
            ['admit','deny','clear-confirmed','finish-ack'] if name == 'deny' else []), 'window lifecycle')
        require(row['reentry'] == ([0,0,0] if name == 'reentry' else []),
                'reject reentry during admission, staged observation and compute admission')


def exercise(image):
    api,host = original.Native(),original.Windows()
    require(host.geometry() == (4096,65536), 'reviewed page/allocation geometry')
    base,initialized,rows = api.create(),False,[]
    partial = None
    try:
        loaded,error = api.load(base,image)
        require(loaded,'resident image load: '+str(error))
        api.initialize(base)
        initialized = True
        # A valid public prefix followed by an inaccessible host page. A failed
        # OS copy is not assumed atomic: retirement must cover the whole page.
        partial = host.reserve(8192)
        host.commit(partial,4096)
        c.memset(partial+4096-32,0xa5,32)
        def export(name): return api.check(api.GetProcAddress(base,name.encode()),name)
        work,observe,register = map(export,('PublicIsolatedSha256','PublicIsolatedObserve','PublicLockedHost'))
        for name,data,status,body in cases():
            source = c.create_string_buffer(data)
            output = (c.c_ubyte*32)(*[0xa5]*32)
            request = original.Request(c.addressof(source),len(data),c.addressof(output),0)
            if name == 'oversize': request.length = 1025
            if name == 'unknown-control': request.control = 2
            if name == 'identity-drift': request.control = 1
            if name == 'bad-input': request.input = 1
            if name == 'partial-input': request.input,request.length = partial+4096-32,64
            if name == 'bad-output': request.output = 1
            resident = Resident(host,base,name if name in
                ('deny-stage','after-stage-lock','stage-observe','deny') else None)
            nested,errors = [],[]
            def callback(argument):
                try:
                    if name == 'reentry' and argument & 15 in (8,9,0):
                        nested.append(api.call(work,c.addressof(request)))
                    return resident(argument)
                except BaseException as error:
                    errors.append(str(error))
                    return 0
            bound = c.WINFUNCTYPE(c.c_void_p,c.c_void_p)(callback)
            require(api.call(register,c.cast(bound,c.c_void_p).value) == 1,'register')
            result = api.call(work,1 if name == 'bad-descriptor' else c.addressof(request))
            require(not errors and resident.error is None and not resident.locked
                    and not resident.window.locked,'callbacks/lock ownership: '+repr((errors,resident.error)))
            require(bytes(output) == (hashlib.sha256(data).digest() if status == 1 else bytes([0xa5]*32)),
                    'independent digest or unchanged destination '+name)
            rows.append(dict(case=name,status=result,observations=[api.call(observe,i) for i in range(6)],
                events=resident.events,snapshots=resident.snapshots,
                window_trace=resident.window.trace,reentry=nested))
    finally:
        try:
            if initialized: api.terminate(base)
        finally:
            try: api.delete(base)
            finally:
                if partial is not None: host.release(partial)
    validate(rows)
    return dict(schema=1,status='PUBLIC_RESIDENT_CANARY_NATIVE_ONLY',cases=rows,
        native_machine=api.machine,terminated=True,deleted=True,production_qualified=False,
        transport_payload_handling_qualified=False,whole_image_qualified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image',type=Path)
    parser.add_argument('--child',action='store_true')
    parser.add_argument('--expect-dirty',action='store_true')
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    if args.child:
        require(not args.expect_dirty,'parent-only expectation')
        print(json.dumps(exercise(image)))
        return
    before = hashlib.sha256(image.read_bytes()).hexdigest()
    result = subprocess.run([sys.executable,__file__,str(image),'--child'],
                            capture_output=True,text=True,timeout=90)
    if args.expect_dirty:
        original.validate_dirty(result)
        record = dict(status='PUBLIC_RESIDENT_DIRTY_FASTFAIL_CONTROL',returncode=result.returncode,
                      cleanup_success_claimed=False,production_qualified=False)
    else:
        require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) < 100000,
                'clean bounded resident child: '+result.stderr[-5000:])
        record = json.loads(result.stdout)
        validate(record['cases'])
    require(before == hashlib.sha256(image.read_bytes()).hexdigest(),'unchanged image')
    record.update(image_sha256=before,windows_build=sys.getwindowsversion().build,python=sys.version,
        source_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items()
             if n.startswith(('windows_enclave_','windows_protection_'))}|{Path(__file__)})})
    print(json.dumps(record,indent=2))


if __name__ == '__main__': main()
