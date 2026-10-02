#!/usr/bin/env python3
"""Public synthetic vectors in a development-signed four-lane VBS worker."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

import windows_enclave_persistent as storage
from windows_enclave_cpu_inventory import interpret
from windows_protection_probe import require

ROOT=Path(__file__).resolve().parents[2]
DIGEST,EXPORT,CANCEL=100,101,102

from windows_enclave_keccak_simd_codec import cases, failure_row, words_for, copy_counts

def exercise(api,host,image):
    require(api.machine=='0x8664' and host.geometry()==(4096,65536),'native x64 geometry')
    rows=cases(); base=api.create(); initialized=False; calls=[]; comparisons=0
    resident=storage.Retained(host,base,False); output=(c.c_ubyte*1024)()
    try:
        loaded,error=api.load(base,image); require(loaded,f'image load: {error}')
        count=api.initialize_worker(base); initialized=True
        require(count==1,'exactly one serialized enclave thread')
        for name in (b'RetainedWork',b'PublicRustBody',b'PublicKeccakSimdInput',b'PublicKeccakSimdOutput'):
            require(not api.GetProcAddress(base,name),'no exported specialized-entry bypass')
        def export(name): return api.check(api.GetProcAddress(base,name.encode()),name)
        routine=export('PublicRetained'); window=export('PublicLockedWindow'); register=export('PublicLockedHost')
        control=export('PublicRetainedControl'); guards=export('PublicGuardControl')
        out_register=export('PublicRetainedOutput'); in_register=export('PublicKeccakSimdInputSource')
        input_control=export('PublicKeccakSimdControl'); cpu=export('PublicCpuInventory')
        inventory=interpret([api.call(cpu,i) for i in range(11)])
        require(inventory['observed_prerequisites']['avx2_batch_or_keccak'],'AVX2/OS bundle inside VBS')
        protocol=export('PublicKeccakSimdProtocol')
        require(api.call(protocol,0)==0x42524235 and api.call(protocol,1)==0,'distinct version-22 protocol')
        def operation(op,sequence=0,row=None,fault=None):
            layout,data,expected=row if row is not None else rows[0]
            payload=[(c.c_ubyte*len(message)).from_buffer_copy(message) for message in data]
            words=words_for(op,sequence,layout,[c.addressof(p) for p in payload])
            if fault=='version': words[0]=21
            elif fault=='sequence': words[1]=0
            elif fault=='route': words[3]=1
            elif fault=='identity': words[37]=9
            elif fault=='length': words[39]=1025
            elif fault=='last': words[40]=9
            elif fault=='budget': words[2]=0
            elif fault=='bits':
                # First lane has 65 bytes/1 last bit for this rejection row.
                payload[0][-1]|=128
            elif fault=='wrong-plan': words[4]=8
            elif fault=='replay': words[1]=1
            elif fault=='export-budget': words[2]=1
            elif fault and fault.startswith('payload-'):
                index=int(fault.split('-')[1]); words[8+11*(index//3)+3*(index%3)]=1
            header=(c.c_ubyte*384).from_buffer_copy(struct.pack('<48Q',*words))
            source=1 if fault=='header-copy' else c.addressof(header)
            require(api.call(in_register,source if op>=100 else 0)==1,'register bounded request')
            require(api.call(out_register,1 if fault=='output-copy' else c.addressof(output))==1,'register explicit public output')
            c.memset(output,0xcc,1024)
            resident.window=storage.Handshake(host,base); trampoline=storage.guard.callback(resident)
            require(api.call(register,c.cast(trampoline,c.c_void_p).value)==1,'register scoped storage callback')
            values=[api.call(routine,op)]+[api.call(window,x) for x in range(2,9)]
            report=[api.call(control,x) for x in range(16,26)]
            if resident.error or resident.window.error:
                raise RuntimeError(f'SIMD storage callback failed: {report}') from (resident.error or resident.window.error)
            item=storage.validate(values,base,False,False,False,resident.window.trace,resident.window.snapshots,resident.window.locked)
            item['guards']=storage.guard.validate_guards([api.call(guards,x) for x in range(16,29)],base,values[1],values[2],'normal',False)
            status=206 if fault else 1 if op==0 else 4 if op==3 else op
            require(report[0]==status and report[3:]==[int(op!=3),int(op>=100 and not fault),
                    4096 if op==3 else 0,int(op==3),0,1,op],f'exact SIMD worker outcome: {report}, expected {status}')
            require(report[2]==report[1]+4096 and report[1]%4096==0,'exact retained page geometry')
            require(report[1]+12288<=values[1]-4096 or report[1]>=values[2]+4096,'disjoint worker and resident')
            raw=[api.call(input_control,x) for x in range(16,23)]
            if op>=100:
                require(values[1]<=raw[0] and raw[0]+384<=values[2] and
                        values[1]<=raw[1] and raw[1]+12288<=values[2] and raw[2]==1,'cleared protected copy buffers')
                require(raw[3:]==copy_counts(op,fault,layout),f'exact per-lane OS copy receipts: {raw}, fault={fault}')
                raw[:2]=[x-base for x in raw[:2]]
            else: require(raw==[0]*7,'no stale copy receipts')
            require(bytes(output)==(expected if op==EXPORT and fault is None else b'\xcc'*1024),
                    'independent oracle or unchanged public destination')
            item.update(retained=report[:1]+[x-base for x in report[1:3]]+report[3:],input=raw,
                fault=fault,output=bytes(output).hex(),retained_flags=resident.snapshot() if resident.locked else [])
            calls.append(item)
            require(api.call(register,0)==api.call(in_register,0)==api.call(out_register,0)==1,'revoke all scoped addresses')
            for buffer in payload+[header]: c.memset(buffer,0,len(buffer))

        for row in rows:
            operation(0); operation(DIGEST,1,row); operation(EXPORT,2,row); operation(3); comparisons+=1
        operation(0); operation(DIGEST,1,rows[-1]); operation(CANCEL,2)
        operation(DIGEST,3,rows[0]); operation(EXPORT,4,rows[0]); operation(3); comparisons+=1
        faults=('version','sequence','route','identity','length','last','header-copy',
                'payload-0','payload-1','payload-2','payload-3','payload-4','payload-5','payload-6','payload-7','payload-8','payload-9','payload-10','payload-11','budget','bits')
        for fault in faults:
            operation(0); operation(DIGEST,1,failure_row(),fault); operation(CANCEL,2,fault='quarantined'); operation(3)
        for fault in ('wrong-plan','replay','export-budget','output-copy'):
            operation(0); operation(DIGEST,1,rows[0]); operation(EXPORT,2,rows[0],fault)
            operation(CANCEL,3,fault='quarantined'); operation(3)
        require(not resident.locked,'all resident pages released')
    finally:
        try:
            if initialized: api.terminate(base)
        finally: api.delete(base)
    return dict(status='PUBLIC_VECTOR_SIMD_VBS_DEVELOPMENT_PASS',production_qualified=False,
        strict_api_acceleration_enabled=False,private_worker_enclave_execution=True,multi_message_simd=True,
        comparisons=comparisons,lane_comparisons=comparisons*4,native_machine=api.machine,
        deleted=True,inventory=inventory,calls=calls,events=resident.events)

def validate_completion(record):
    require(record.get('comparisons')==53 and record.get('lane_comparisons')==212 and
        len(record.get('calls',[]))==318 and record.get('deleted') is True and
        record.get('production_qualified') is False and
        record.get('private_worker_enclave_execution') is True and
        record.get('multi_message_simd') is True,'complete native campaign')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image',type=Path); parser.add_argument('build_record',type=Path)
    parser.add_argument('--child',action='store_true',help=argparse.SUPPRESS); args=parser.parse_args()
    image=args.image.resolve(strict=True)
    require(image.suffix.lower()=='.dll' and 0<image.stat().st_size<=8*1024*1024,'bounded image')
    if args.child:
        print(json.dumps(exercise(storage.WorkerNative(),storage.Windows(),image))); return
    build=json.loads(args.build_record.read_text())
    worker_path=args.build_record.parent/'keccak-simd-worker-results.json'
    require(hashlib.sha256(worker_path.read_bytes()).hexdigest()==build['worker_record_sha256'],'bound worker record')
    worker=json.loads(worker_path.read_text())
    for manifest in (worker['source_sha256'],build['source_sha256']):
        require(all(hashlib.sha256((ROOT/path).read_bytes()).hexdigest()==value
                    for path,value in manifest.items()),'bound build sources')
    require(hashlib.sha256((args.build_record.parent/'normal.dll').read_bytes()).hexdigest()==
            build['artifacts']['normal.dll'],'unchanged unsigned build artifact')
    before=worker['source_sha256']|build['source_sha256']
    for pattern in ('windows_enclave*.py','windows_protection*.py'):
        for path in (ROOT/'scripts/cryptography').glob(pattern):
            before[path.relative_to(ROOT).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
    def check_sources():
        require(all(hashlib.sha256((ROOT/path).read_bytes()).hexdigest()==value for path,value in before.items()),'unchanged built/capture sources')
    check_sources(); digest=hashlib.sha256(image.read_bytes()).hexdigest()
    result=subprocess.run([sys.executable,__file__,str(image),str(args.build_record),'--child'],
        capture_output=True,text=True,timeout=600)
    require(result.returncode==0 and not result.stderr and 0<len(result.stdout)<8*1024*1024,
            f'SIMD native worker failed ({result.returncode}): {result.stderr[-6000:]}')
    record=json.loads(result.stdout)
    validate_completion(record)
    check_sources(); require(digest==hashlib.sha256(image.read_bytes()).hexdigest(),'unchanged image')
    record.update(schema=1,source_sha256=before,image_sha256=digest,
        build_sha256=hashlib.sha256(args.build_record.read_bytes()).hexdigest(),windows_build=sys.getwindowsversion().build)
    print(json.dumps(record,indent=2,sort_keys=True))

if __name__=='__main__': main()
