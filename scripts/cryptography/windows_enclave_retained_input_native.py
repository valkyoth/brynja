#!/usr/bin/env python3
"""Native borrowed PUBLIC input / retained result experiment. Not strict admission."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

import windows_enclave_retained_native as previous
from windows_protection_probe import require
storage=previous.storage


def campaign():
    rows=[]
    for index in range(20):
        rows += [(0,1,True,index,'normal'),(1,2,True,index,'normal'),
                 (2,3,True,index,'normal'),(2,102,True,index,'normal'),(3,4,False,index,'normal')]
    for fault in ('stale','future','version','length','source','header-copy','payload-copy'):
        rows += [(0,1,True,1,fault),(1,121 if fault.endswith('copy') else 120,True,1,fault),
                 (2,107,True,1,fault),(3,4,False,1,fault)]
    rows += [(0,1,True,1,'normal'),(1,2,True,1,'normal'),(4,5,True,1,'normal'),
             (2,102,True,1,'normal'),(3,4,False,1,'normal')]
    rows += [(0,1,True,1,'normal'),(1,2,True,1,'normal'),(1,101,True,1,'normal'),
             (2,107,True,1,'normal'),(3,4,False,1,'normal')]
    return rows


def input_report(report, step, epoch, base, low, high):
    op,status,_,index,fault=step
    require(type(report) is list and len(report)==11 and all(type(v) is int and 0<=v<1<<64 for v in report),
            'complete input observations')
    if op!=1:
        require(report==[0]*11,'no stale input observations'); return report
    size=len(previous.vectors()[index])
    length=0 if status==120 or fault=='header-copy' else size
    successful_header=int(fault!='header-copy')
    payload=int(status!=120 and successful_header and size!=0)
    require(report[:4]==[1,successful_header,payload,payload*int(fault!='payload-copy')],
            'exact input-copy observations')
    addresses=report[4:8]
    widths=[32,1024,1170,32]
    for address,width in zip(addresses,widths):
        require(low<=address and address+width<=high,'borrowed storage inside admitted worker')
    for i in range(4):
        for j in range(i):
            require(addresses[i]+widths[i]<=addresses[j] or addresses[j]+widths[j]<=addresses[i],
                    'disjoint borrowed worker regions')
    require(report[8:]==[length,1,epoch],'input length, complete clearing and independent enclave sequence')
    return report[:4]+[v-base for v in addresses]+report[8:]


def check_record(record):
    require(type(record) is dict and set(record)==set(storage.guard.NONCLAIMS)|
            {'synthetic_only','deleted','native_machine','calls','events'},'canonical retained-input record')
    require(all(record[k] is False for k in storage.guard.NONCLAIMS) and record['synthetic_only'] is True
            and record['deleted'] is True and record['native_machine']=='0x8664','nonqualifying claims')
    require(type(record['calls']) is list and len(record['calls'])==len(campaign()),'complete retained-input campaign')
    epoch=0; previous_region=None; expected_events=[]
    for item,step in zip(record['calls'],campaign()):
        op,status,live,index,fault=step
        if op==0: epoch+=1
        values=item.get('values',[])
        checked=storage.validate(values,0,False,False,False,item.get('trace'),item.get('snapshots'),item.get('locked_until_teardown'))
        checked['guards']=storage.guard.validate_guards(item.get('guards',[]),0,values[1],values[2],'normal',False)
        report=item.get('retained')
        previous.check_report(report,(op,status,live,None))
        region,data=report[1:3]
        require(region+12288<=values[1]-4096 or region>=values[2]+4096,'retained allocation disjoint from input worker')
        if op==0:
            previous_region=region; expected_events.append(('lock',data))
        else:
            require(region==previous_region,'same retained owner across returns')
            expected_events.append(('check',data))
            if op==3: expected_events += [('clear',data),('unlock',data)]
        flags=item.get('retained_flags')
        if live: storage.flags_check(flags,4096,True)
        else: require(flags==[],'no released residency claim')
        checked['retained']=report; checked['retained_flags']=flags
        checked['input']=input_report(item.get('input'),step,epoch,0,values[1],values[2])
        expected=hashlib.sha256(previous.vectors()[index]).hexdigest() if op==2 and status==3 else 'cc'*32
        require(item.get('output')==expected,'independent borrowed digest or unchanged destination')
        checked['output']=expected
        require(checked==item,'complete canonical input operation')
    require(type(record['events']) is list and len(record['events'])==len(expected_events),'complete residency event stream')
    for event,(name,address) in zip(record['events'],expected_events):
        keys={'event','offset'}|({'before','locked'} if name=='lock' else {'locked'} if name in ('check','clear') else set())
        require(set(event)==keys and event['event']==name and event['offset']==address,'bound residency event')
        if name=='lock': storage.flags_check(event['before'],4096,False)
        if 'locked' in event: storage.flags_check(event['locked'],4096,True)
    return record


def exercise(api,host,image):
    require(api.machine=='0x8664' and host.geometry()==(4096,65536),'native x64 geometry')
    base=api.create(); initialized=False; calls=[]; epoch=0
    resident=storage.Retained(host,base,False)
    output=(c.c_ubyte*32)()
    try:
        loaded,error=api.load(base,image);require(loaded,f'image load: {error}')
        count=api.initialize_worker(base);initialized=True;require(count==1,'one serialized enclave worker')
        def export(name): return api.check(api.GetProcAddress(base,name.encode()),name)
        routine=export('PublicRetained');window=export('PublicLockedWindow');register=export('PublicLockedHost')
        control=export('PublicRetainedControl');guards=export('PublicGuardControl')
        out_register=export('PublicRetainedOutput');in_register=export('PublicRetainedInput');input_control=export('PublicInputControl')
        require(api.call(out_register,c.addressof(output))==1,'register public output')
        for step in campaign():
            op,status,live,index,fault=step
            if op==0: epoch+=1
            message=previous.vectors()[index]
            payload=(c.c_ubyte*max(1,len(message)))()
            if message: c.memmove(payload,message,len(message))
            words=[4,epoch,len(message),c.addressof(payload) if message else 0]
            if fault=='stale':words[1]-=1
            elif fault=='future':words[1]+=1
            elif fault=='version':words[0]=3
            elif fault=='length':words[2]=1025
            elif fault=='source':words[3]=0
            elif fault=='payload-copy':words[3]=1
            header=(c.c_ubyte*32).from_buffer_copy(struct.pack('<4Q',*words))
            source=1 if fault=='header-copy' else c.addressof(header)
            require(api.call(in_register,source if op==1 else 0)==1,'register metadata only')
            c.memset(output,0xcc,32)
            resident.window=storage.Handshake(host,base); trampoline=storage.guard.callback(resident)
            require(api.call(register,c.cast(trampoline,c.c_void_p).value)==1,'register scoped callback')
            values=[api.call(routine,op)]+[api.call(window,x) for x in range(2,9)]
            report=[api.call(control,x) for x in range(16,26)]
            if resident.error or resident.window.error:
                raise RuntimeError(f'retained input callback failed: {report}') from (resident.error or resident.window.error)
            item=storage.validate(values,base,False,False,False,resident.window.trace,resident.window.snapshots,resident.window.locked)
            item['guards']=storage.guard.validate_guards([api.call(guards,x) for x in range(16,29)],base,values[1],values[2],'normal',False)
            raw=[api.call(input_control,x) for x in range(16,27)]
            item['input']=input_report(raw,step,epoch,base,values[1],values[2])
            report[1:3]=[v-base if v else 0 for v in report[1:3]]
            previous.check_report(report,(op,status,live,None))
            item['retained']=report;item['retained_flags']=resident.snapshot() if resident.locked else []
            item['output']=bytes(output).hex();calls.append(item)
            require(api.call(register,0)==api.call(in_register,0)==1,'revoke scoped host addresses')
            # Invalidate caller input/metadata AFTER synchronous hash, before the
            # later retained-result export. No host snapshot is retained for it.
            c.memset(payload,0,len(payload)); c.memset(header,0,32)
        require(not resident.locked,'all retained owners cleared/unlocked')
        require(api.call(out_register,0)==1,'revoke public output')
    finally:
        try:
            if initialized: api.terminate(base)
        finally: api.delete(base)
    return check_record({**dict.fromkeys(storage.guard.NONCLAIMS,False),'synthetic_only':True,
        'deleted':True,'native_machine':'0x8664','calls':calls,'events':resident.events})


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('image',type=Path)
    parser.add_argument('--child',action='store_true',help=argparse.SUPPRESS);args=parser.parse_args()
    image=args.image.resolve(strict=True);require(image.suffix=='.dll' and 0<image.stat().st_size<=4*1024*1024,'bounded image')
    if args.child:
        print(json.dumps(exercise(storage.WorkerNative(),storage.Windows(),image)));return
    from windows_enclave_retained_input_worker_build import ROOT,SOURCES
    before={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES};image_hash=hashlib.sha256(image.read_bytes()).hexdigest()
    require(not subprocess.check_output(['git','status','--porcelain'],cwd=ROOT),'clean capture checkout')
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    result=subprocess.run([sys.executable,__file__,str(image),'--child'],capture_output=True,text=True,timeout=90)
    require(result.returncode==0 and not result.stderr and 0<len(result.stdout)<=4*1024*1024,
            f'bounded retained input child failed ({result.returncode}): {result.stderr[-6000:]}')
    record=check_record(json.loads(result.stdout))
    require(before=={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES}
            and image_hash==hashlib.sha256(image.read_bytes()).hexdigest(),'unchanged source/image')
    require(not subprocess.check_output(['git','status','--porcelain'],cwd=ROOT) and
            commit==subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'unchanged checkout')
    record.update(schema=1,kind='windows-enclave-retained-borrowed-input-experiment',status='OBSERVATIONS_ONLY',
                  commit=commit,source_sha256=before,image_sha256=image_hash,os=sys.getwindowsversion().build)
    print(json.dumps(record,indent=2,sort_keys=True))


if __name__=='__main__':main()
