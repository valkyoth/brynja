#!/usr/bin/env python3
"""PUBLIC-vector private AVX2 worker experiment, not production qualification."""
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
LENGTHS=(0,1,135,136,168,1025)


def exercise(api,host,image):
    require(api.machine=='0x8664' and host.geometry()==(4096,65536),'native x64 geometry')
    base=api.create();initialized=False;calls=[];comparisons=0
    resident=storage.Retained(host,base,False)
    output=(c.c_ubyte*1024)()
    try:
        loaded,error=api.load(base,image);require(loaded,f'image load: {error}')
        count=api.initialize_worker(base);initialized=True;require(count==1,'one serialized enclave worker')
        for private in (b'RetainedWork',b'PublicRustBody',b'PublicSha3Input',b'PublicSha3Output'):
            require(not api.GetProcAddress(base,private),'no exported bypass of the baseline C entry')
        def export(name):return api.check(api.GetProcAddress(base,name.encode()),name)
        routine=export('PublicRetained');window=export('PublicLockedWindow');register=export('PublicLockedHost')
        control=export('PublicRetainedControl');guards=export('PublicGuardControl')
        out_register=export('PublicRetainedOutput');in_register=export('PublicSha3InputSource')
        input_control=export('PublicSha3Control');cpu=export('PublicCpuInventory')
        inventory=interpret([api.call(cpu,i) for i in range(11)])
        require(inventory['observed_prerequisites']['avx2_batch_or_keccak'],'complete specialized bundle')
        protocol=export('PublicSha3Avx2Protocol')
        require(api.call(protocol,0)==0x42524b31 and api.call(protocol,1)==0,'distinct AVX2 image protocol')
        require(api.call(out_register,c.addressof(output))==1,'register public output')
        def operation(op,sequence=0,identity=0,data=b'',last=0,width=0,terminal=False,name_bits=0,custom_bits=0,expected=None,fault=None):
            payload=(c.c_ubyte*max(1,len(data)))()
            if data:c.memmove(payload,data,len(data))
            words=[14,sequence,identity,len(data),last,c.addressof(payload) if data else 0,width,int(terminal),
                   name_bits & ((1<<64)-1),name_bits>>64,custom_bits & ((1<<64)-1),custom_bits>>64,1,0]
            if fault=='version':words[0]=7
            elif fault=='sequence':words[1]=0
            elif fault=='route':words[12]=0
            elif fault=='reserved':words[13]=1
            elif fault=='length':words[3]=1025
            elif fault=='payload-copy':words[5]=1
            header=(c.c_ubyte*112).from_buffer_copy(struct.pack('<14Q',*words))
            source=1 if fault=='header-copy' else c.addressof(header)
            require(api.call(in_register,source if op>=21 else 0)==1,'register metadata')
            c.memset(output,0xcc,1024)
            resident.window=storage.Handshake(host,base);trampoline=storage.guard.callback(resident)
            require(api.call(register,c.cast(trampoline,c.c_void_p).value)==1,'register scoped callback')
            values=[api.call(routine,op)]+[api.call(window,x) for x in range(2,9)]
            report=[api.call(control,x) for x in range(16,26)]
            if resident.error or resident.window.error:
                raise RuntimeError(f'retained AVX2 callback failed: {report}') from (resident.error or resident.window.error)
            item=storage.validate(values,base,False,False,False,resident.window.trace,resident.window.snapshots,resident.window.locked)
            item['guards']=storage.guard.validate_guards([api.call(guards,x) for x in range(16,29)],base,values[1],values[2],'normal',False)
            status=206 if fault else 1 if op==0 else 4 if op==3 else op
            require(report[0]==status and report[3:]==[int(op!=3),int(op>=21 and not fault),
                    4096 if op==3 else 0,int(op==3),0,1,op],f'exact worker outcome: {report}, expected {status}')
            require(report[2]==report[1]+4096 and report[1]%4096==0,'retained page geometry')
            require(report[1]+12288<=values[1]-4096 or report[1]>=values[2]+4096,'disjoint page and worker')
            raw=[api.call(input_control,x) for x in range(16,23)]
            if op>=21:
                require(values[1]<=raw[0] and raw[0]+112<=values[2] and
                        values[1]<=raw[1] and raw[1]+1024<=values[2] and raw[2]==1,'cleared protected copy buffers')
                require(raw[3]==int(fault!='header-copy'),'header copy receipt')
                require(raw[4]==int(bool(data) and fault in (None,'quarantined')),'payload copy receipt')
                require(raw[5]==int(op==25 and not fault),'explicit output receipt')
                require(raw[6]==int(fault in ('header-copy','payload-copy')),'OS copy failure receipt')
                raw[:2]=[x-base for x in raw[:2]]
            else:require(raw==[0]*7,'no stale copy observations')
            require(bytes(output)==(expected+b'\xcc'*(1024-len(expected)) if expected is not None else b'\xcc'*1024),
                    'independent digest or unchanged destination')
            item.update(retained=report[:1]+[x-base for x in report[1:3]]+report[3:],
                        input=raw,output=bytes(output).hex(),fault=fault,
                        retained_flags=resident.snapshot() if resident.locked else [])
            calls.append(item)
            require(api.call(register,0)==api.call(in_register,0)==1,'revoke scoped addresses')
            c.memset(payload,0,len(payload));c.memset(header,0,112)
        names=('sha3_224','sha3_256','sha3_384','sha3_512','shake_128','shake_256','shake_128','shake_256')
        for identity,name in enumerate(names,1):
            for length in LENGTHS:
                data=bytes((i*17)%256 for i in range(length))
                operation(0);operation(21,1,identity);sequence=1
                chunks=[data[i:i+1024] for i in range(0,length,1024)]
                for chunk in chunks[:-1]:
                    sequence+=1;operation(22,sequence,data=chunk,last=8)
                tail=chunks[-1] if chunks else b''
                sequence+=1;operation(23,sequence,data=tail,last=8 if tail else 0)
                h=hashlib.new(name,data)
                expected=h.digest() if identity<=4 else h.digest(333)
                if identity>4:
                    sequence+=1;operation(27,sequence,width=len(expected),last=8,terminal=True)
                output_identity=identity
                if length==135:
                    sequence+=1;operation(24,sequence,2)
                    expected=hashlib.sha3_256(expected).digest();output_identity=2
                sequence+=1;operation(25,sequence,output_identity,width=len(expected),last=8,expected=expected)
                comparisons+=1;operation(3)
        # Eight existing independently generated SP 800-185 cases, selected to
        # include both strengths and nonempty fractional N/S. No new crypto oracle.
        vectors=ROOT/'crates/brynja-hash-sha3/tests/vectors/cshake-execution.txt'
        selected=[]
        for identity,algorithm in ((7,'cshake128'),(8,'cshake256')):
            candidates=[line.split() for line in vectors.read_text().splitlines()
                        if line.startswith(algorithm+' ')]
            candidates=[row for row in candidates if int(row[1])%8 and int(row[3])%8]
            require(len(candidates)>=4,'fractional prefix oracle coverage')
            selected.extend((identity,row) for row in candidates[-4:])
        for identity,row in selected:
            _,nb,nh,sb,sh,mb,mh,ob,oh=row
            nb,sb,mb,ob=map(int,(nb,sb,mb,ob))
            name,custom,data,expected=[b'' if h=='-' else bytes.fromhex(h) for h in (nh,sh,mh,oh)]
            operation(0);operation(28,1,identity,name_bits=nb,custom_bits=sb);sequence=1
            for op,blob,bits in ((29,name,nb),(30,custom,sb)):
                whole=bits//8
                for i in range(0,whole,1024):
                    sequence+=1;operation(op,sequence,data=blob[i:min(i+1024,whole)],last=8)
                if bits%8:
                    sequence+=1;operation(op,sequence,data=blob[whole:],last=bits%8)
            sequence+=1;operation(31,sequence)
            whole=mb//8
            for i in range(0,whole,1024):
                sequence+=1;operation(22,sequence,data=data[i:min(i+1024,whole)],last=8)
            sequence+=1;operation(23,sequence,data=data[whole:],last=mb%8)
            sequence+=1;operation(27,sequence,width=len(expected),last=(ob-1)%8+1 if ob else 0,terminal=True)
            sequence+=1;operation(25,sequence,identity,width=len(expected),
                                  last=(ob-1)%8+1 if ob else 0,expected=expected)
            comparisons+=1;operation(3)
        for fault in ('version','sequence','route','reserved','length','header-copy','payload-copy'):
            operation(0);operation(21,1,2)
            operation(23,2,data=b'abc',last=8,fault=fault)
            operation(25,3,2,width=32,last=8,fault='quarantined');operation(3)
        operation(0);operation(21,1,2);operation(22,2,data=b'abc',last=8)
        operation(26,3);operation(21,4,1);operation(23,5)
        operation(25,6,1,width=28,last=8,expected=hashlib.sha3_224(b'').digest());comparisons+=1;operation(3)
        require(not resident.locked,'all retained pages released')
        require(api.call(out_register,0)==1,'revoke public destination')
    finally:
        try:
            if initialized:api.terminate(base)
        finally:api.delete(base)
    return dict(status='PUBLIC_VECTOR_DEVELOPMENT_PASS',production_qualified=False,
                strict_api_acceleration_enabled=False,private_worker_enclave_execution=True,
                native_machine=api.machine,deleted=True,inventory=inventory,
                comparisons=comparisons,calls=calls,events=resident.events)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image',type=Path);parser.add_argument('build_record',type=Path)
    parser.add_argument('--child',action='store_true',help=argparse.SUPPRESS);args=parser.parse_args()
    image=args.image.resolve(strict=True)
    require(image.suffix.lower()=='.dll' and 0<image.stat().st_size<=8*1024*1024,'bounded DLL image')
    if args.child:
        print(json.dumps(exercise(storage.WorkerNative(),storage.Windows(),image)));return
    build=json.loads(args.build_record.read_text())
    before=build['source_sha256'].copy()
    vector=ROOT/'crates/brynja-hash-sha3/tests/vectors/cshake-execution.txt'
    before[vector.relative_to(ROOT).as_posix()]=hashlib.sha256(vector.read_bytes()).hexdigest()
    for pattern in ('windows_enclave*.py','windows_protection*.py'):
        for path in (ROOT/'scripts/cryptography').glob(pattern):
            before[path.relative_to(ROOT).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
    def check_sources():
        require(all(hashlib.sha256((ROOT/path).read_bytes()).hexdigest()==digest
                    for path,digest in before.items()),'unchanged built/capture source closure')
    check_sources();digest=hashlib.sha256(image.read_bytes()).hexdigest()
    result=subprocess.run([sys.executable,__file__,str(image),str(args.build_record),'--child'],
                          capture_output=True,text=True,timeout=600)
    require(result.returncode==0 and not result.stderr and 0<len(result.stdout)<8*1024*1024,
            f'bounded AVX2 worker failed ({result.returncode}): {result.stderr[-6000:]}')
    record=json.loads(result.stdout)
    require(record.get('comparisons')==57 and record.get('deleted') is True and
            record.get('production_qualified') is False,'complete public-vector campaign')
    check_sources();require(digest==hashlib.sha256(image.read_bytes()).hexdigest(),'unchanged image')
    record.update(schema=1,source_sha256=before,image_sha256=digest,
                  build_sha256=hashlib.sha256(args.build_record.read_bytes()).hexdigest(),
                  windows_build=sys.getwindowsversion().build)
    print(json.dumps(record,indent=2,sort_keys=True))


if __name__=='__main__':main()
