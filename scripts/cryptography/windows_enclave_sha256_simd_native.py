#!/usr/bin/env python3
"""Public synthetic vectors in a development-signed eight-lane VBS worker."""
import argparse
import ctypes as c
import hashlib
import importlib.util
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

def cases():
    spec=importlib.util.spec_from_file_location('simd_native_bits',ROOT/'scripts/sha2/check-sha2-bit-differential.py')
    oracle=importlib.util.module_from_spec(spec); spec.loader.exec_module(oracle)
    layouts=[[(identity,size,8)]*8 for identity in (224,256)
             for size in (64,65,119,120,127,128,129,255,1023,1024)]
    lengths=(65,119,120,127,128,129,1023,1024)
    layouts += [[(256 if (n*7)&(1<<lane) else 224,lengths[(n+lane*3)%8],1+(n+lane)%8)
                 for lane in range(8)] for n in range(32)]
    rows=[]
    for layout in layouts:
        data=[]; output=bytearray()
        for lane,(identity,length,last) in enumerate(layout):
            message=bytearray((i*17+lane*29)%256 for i in range(length))
            message[-1]&=(255<<(8-last))&255
            bits=(length-1)*8+last
            name={224:'sha224',256:'sha256'}[identity]
            result=bytes.fromhex(oracle.digest32(message,bits,*oracle.CONFIG[name]))
            if last==8: require(result==hashlib.new(name,message).digest(),'hashlib oracle cross-check')
            output.extend(result.ljust(32,b'\0')); data.append(bytes(message))
        rows.append((layout,data,bytes(output)))
    require(len(rows)==52,'complete selected VBS vector catalog')
    return rows

def words_for(op,sequence,layout,pointers):
    words=[21,sequence,1000 if op==DIGEST else 0,2]
    for (identity,length,last),pointer in zip(layout,pointers,strict=True):
        words.extend([identity if op!=CANCEL else 0,length if op==DIGEST else 0,
                      last if op==DIGEST else 0,pointer if op==DIGEST else 0])
    require(len(words)==36,'eight complete lane descriptors')
    return words

def copy_counts(op,fault):
    payload=0
    if op==DIGEST and (fault is None or fault in ('budget','bits')): payload=8
    elif fault and fault.startswith('payload-'): payload=int(fault[-1])
    return [int(fault!='header-copy'),payload,int(op==EXPORT and fault is None),
            int(fault=='header-copy' or fault=='output-copy' or bool(fault and fault.startswith('payload-')))]

def exercise(api,host,image):
    require(api.machine=='0x8664' and host.geometry()==(4096,65536),'native x64 geometry')
    rows=cases(); base=api.create(); initialized=False; calls=[]; comparisons=0
    resident=storage.Retained(host,base,False); output=(c.c_ubyte*256)()
    try:
        loaded,error=api.load(base,image); require(loaded,f'image load: {error}')
        count=api.initialize_worker(base); initialized=True
        require(count==1,'exactly one serialized enclave thread')
        for name in (b'RetainedWork',b'PublicRustBody',b'PublicSha256SimdInput',b'PublicSha256SimdOutput'):
            require(not api.GetProcAddress(base,name),'no exported specialized-entry bypass')
        def export(name): return api.check(api.GetProcAddress(base,name.encode()),name)
        routine=export('PublicRetained'); window=export('PublicLockedWindow'); register=export('PublicLockedHost')
        control=export('PublicRetainedControl'); guards=export('PublicGuardControl')
        out_register=export('PublicRetainedOutput'); in_register=export('PublicSha256SimdInputSource')
        input_control=export('PublicSha256SimdControl'); cpu=export('PublicCpuInventory')
        inventory=interpret([api.call(cpu,i) for i in range(11)])
        require(inventory['observed_prerequisites']['avx2_batch_or_keccak'],'AVX2/OS bundle inside VBS')
        protocol=export('PublicSha256SimdProtocol')
        require(api.call(protocol,0)==0x42524234 and api.call(protocol,1)==0,'distinct version-21 protocol')
        def operation(op,sequence=0,row=None,fault=None):
            layout,data,expected=row if row is not None else rows[0]
            payload=[(c.c_ubyte*len(message)).from_buffer_copy(message) for message in data]
            words=words_for(op,sequence,layout,[c.addressof(p) for p in payload])
            if fault=='version': words[0]=20
            elif fault=='sequence': words[1]=0
            elif fault=='route': words[3]=1
            elif fault=='identity': words[32]=512
            elif fault=='length': words[33]=1025
            elif fault=='last': words[34]=9
            elif fault=='budget': words[2]=0
            elif fault=='bits':
                # First lane has 65 bytes/1 last bit for this rejection row.
                payload[0][-1]|=1
            elif fault=='wrong-plan': words[4]=256
            elif fault=='replay': words[1]=1
            elif fault=='export-budget': words[2]=1
            elif fault and fault.startswith('payload-'): words[7+4*int(fault[-1])]=1
            header=(c.c_ubyte*288).from_buffer_copy(struct.pack('<36Q',*words))
            source=1 if fault=='header-copy' else c.addressof(header)
            require(api.call(in_register,source if op>=100 else 0)==1,'register bounded request')
            require(api.call(out_register,1 if fault=='output-copy' else c.addressof(output))==1,'register explicit public output')
            c.memset(output,0xcc,256)
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
                require(values[1]<=raw[0] and raw[0]+288<=values[2] and
                        values[1]<=raw[1] and raw[1]+8192<=values[2] and raw[2]==1,'cleared protected copy buffers')
                require(raw[3:]==copy_counts(op,fault),f'exact per-lane OS copy receipts: {raw}, fault={fault}')
                raw[:2]=[x-base for x in raw[:2]]
            else: require(raw==[0]*7,'no stale copy receipts')
            require(bytes(output)==(expected if op==EXPORT and fault is None else b'\xcc'*256),
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
                'payload-0','payload-1','payload-2','payload-3','payload-4','payload-5','payload-6','payload-7','budget','bits')
        for fault in faults:
            operation(0); operation(DIGEST,1,rows[20],fault); operation(CANCEL,2,fault='quarantined'); operation(3)
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
        comparisons=comparisons,lane_comparisons=comparisons*8,native_machine=api.machine,
        deleted=True,inventory=inventory,calls=calls,events=resident.events)

def validate_completion(record):
    require(record.get('comparisons')==53 and record.get('lane_comparisons')==424 and
        len(record.get('calls',[]))==302 and record.get('deleted') is True and
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
    worker_path=args.build_record.parent/'sha256-simd-worker-results.json'
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
