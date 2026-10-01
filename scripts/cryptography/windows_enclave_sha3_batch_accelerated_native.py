#!/usr/bin/env python3
"""PUBLIC-vector private AVX2 worker experiment, not production qualification."""
import argparse
import ctypes as c
import hashlib
import json
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys

import windows_enclave_persistent as storage
from windows_enclave_cpu_inventory import interpret
from windows_protection_probe import require

ROOT=Path(__file__).resolve().parents[2]



def exercise(api,host,image,corpus):
    require(api.machine=='0x8664' and host.geometry()==(4096,65536),'native x64 geometry')
    base=api.create();initialized=False;calls=[];comparisons=0
    resident=storage.Retained(host,base,False)
    output=(c.c_ubyte*1024)()
    try:
        loaded,error=api.load(base,image);require(loaded,f'image load: {error}')
        count=api.initialize_worker(base);initialized=True;require(count==1,'one serialized enclave worker')
        for private in (b'RetainedWork',b'PublicRustBody',b'PublicSha3BatchInput',b'PublicSha3BatchOutput'):
            require(not api.GetProcAddress(base,private),'no exported bypass of the baseline C entry')
        def export(name):return api.check(api.GetProcAddress(base,name.encode()),name)
        routine=export('PublicRetained');window=export('PublicLockedWindow');register=export('PublicLockedHost')
        control=export('PublicRetainedControl');guards=export('PublicGuardControl')
        out_register=export('PublicRetainedOutput');in_register=export('PublicSha3BatchInputSource')
        input_control=export('PublicSha3BatchControl');cpu=export('PublicCpuInventory')
        inventory=interpret([api.call(cpu,i) for i in range(11)])
        require(inventory['observed_prerequisites']['avx2_batch_or_keccak'],'complete specialized bundle')
        protocol=export('PublicSha3BatchAvx2Protocol')
        require(api.call(protocol,0)==0x42524233 and api.call(protocol,1)==0,'distinct AVX2 image protocol')
        require(api.call(out_register,c.addressof(output))==1,'register public output')
        def operation(op,sequence=0,slot=0,data=b'',last=0,plan=None,name_bits=0,custom_bits=0,expected=None,fault=None):
            payload=(c.c_ubyte*max(1,len(data)))()
            if data:c.memmove(payload,data,len(data))
            words=[17,sequence,slot,len(data),last,c.addressof(payload) if data else 0,
                   (1<<64)-1 if op==90 else 0,0,name_bits & ((1<<64)-1),name_bits>>64,
                   custom_bits & ((1<<64)-1),custom_bits>>64]+[0]*24+[1,0]
            if op in (90,98):
                require(plan is not None and len(plan)==8,'complete declared batch plan')
                for index,triple in enumerate(plan):words[12+3*index:15+3*index]=triple
            if fault=='version':words[0]=11
            elif fault=='sequence':words[1]=0
            elif fault=='route':words[36]=0
            elif fault=='reserved':words[37]=1
            elif fault=='length':words[3]=1025
            elif fault=='payload-copy':words[5]=1
            header=(c.c_ubyte*304).from_buffer_copy(struct.pack('<38Q',*words))
            source=1 if fault=='header-copy' else c.addressof(header)
            require(api.call(in_register,source if op>=90 else 0)==1,'register metadata')
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
            require(report[0]==status and report[3:]==[int(op!=3),int(op>=90 and not fault),
                    4096 if op==3 else 0,int(op==3),0,1,op],f'exact worker outcome: {report}, expected {status}')
            require(report[2]==report[1]+4096 and report[1]%4096==0,'retained page geometry')
            require(report[1]+12288<=values[1]-4096 or report[1]>=values[2]+4096,'disjoint page and worker')
            raw=[api.call(input_control,x) for x in range(16,23)]
            if op>=90:
                require(values[1]<=raw[0] and raw[0]+304<=values[2] and
                        values[1]<=raw[1] and raw[1]+1024<=values[2] and raw[2]==1,'cleared protected copy buffers')
                require(raw[3]==int(fault!='header-copy'),'header copy receipt')
                require(raw[4]==int(bool(data) and fault in (None,'quarantined')),'payload copy receipt')
                require(raw[5]==int(op == 98 and not fault),'explicit output receipt')
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
            c.memset(payload,0,len(payload));c.memset(header,0,304)

        # Source-bound independent corpus already cross-checked against NIST and
        # hashlib by the builder. All data below is PUBLIC qualification input.
        rows=[line.split() for line in corpus.read_text().splitlines()]
        require(len(rows)==604,'complete independent batch corpus')
        def decode(value):return b'' if value=='-' else bytes.fromhex(value)
        def tail(bits):return (bits-1)%8+1 if bits else 0
        def feed(op,seq,slot,data,bits):
            offset=0
            for width in (3,8192,7,4096)*((bits//4096)+2):
                if offset==bits:break
                n=min(width,bits-offset);fragment=bytearray((n+7)//8)
                for bit in range(n):
                    fragment[bit//8]|=((data[(offset+bit)//8]>>((offset+bit)%8))&1)<<(bit%8)
                seq+=1;operation(op,seq,slot,bytes(fragment),tail(n));offset+=n
            require(offset==bits,'complete setup fragments')
            return seq
        def plan_for(selected):
            return [(int(row[0]),(int(row[7])+7)//8,tail(int(row[7]))) if row else (0,0,0) for row in selected]
        def batch(selected,seq=0):
            plan=plan_for(selected);seq+=1;operation(90,seq,plan=plan);expected=b''
            for slot,row in enumerate(selected):
                if row is None:continue
                identity,nb,sb,mb,ob=(int(row[index]) for index in (0,1,3,5,7))
                name,custom,message,result=(decode(row[index]) for index in (2,4,6,8))
                seq+=1;operation(91,seq,slot,name_bits=nb,custom_bits=sb)
                if identity>=7:
                    seq=feed(92,seq,slot,name,nb);seq=feed(93,seq,slot,custom,sb)
                seq+=1;operation(94,seq,slot)
                split=max(0,len(message)-1)
                for offset in range(0,split,113):
                    seq+=1;operation(95,seq,slot,message[offset:min(offset+113,split)],8)
                seq+=1;operation(96,seq,slot,message[split:],tail(mb))
                expected+=result
            seq+=1;operation(97,seq)
            seq+=1;operation(98,seq,plan=plan,expected=expected+bytes(1024-len(expected)))
            return seq
        for identity in range(1,9):
            matching=[r for r in rows if int(r[0])==identity]
            for index in (0,1,2,len(matching)//2,len(matching)-2,len(matching)-1):
                selected=[matching[index]]+[None]*7
                operation(0);batch(selected);comparisons+=1;operation(3)
        # One fully populated mixed-identity batch and sparse batch on the same
        # authority, with an explicit cancelled batch between them.
        mixed=[next(r for r in rows if int(r[0])==i and 0<int(r[7])<=512) for i in range(1,9)]
        operation(0);seq=batch(mixed);comparisons+=1
        plan=plan_for(mixed);seq+=1;operation(90,seq,plan=plan)
        seq+=1;operation(99,seq)
        seq=batch([r if i in (0,3,7) else None for i,r in enumerate(mixed)],seq);comparisons+=1
        operation(3)
        plan=plan_for([mixed[1]]+[None]*7)
        for fault in ('version','sequence','route','reserved','length','header-copy','payload-copy'):
            operation(0);operation(90,1,plan=plan);operation(91,2);operation(94,3)
            operation(95,4,data=b'abc',last=8,fault=fault)
            operation(99,4,fault='quarantined');operation(3)
        require(not resident.locked,'all retained pages released')
        require(api.call(out_register,0)==1,'revoke public destination')
    finally:
        try:
            if initialized:api.terminate(base)
        finally:api.delete(base)
    return dict(status='PUBLIC_VECTOR_DEVELOPMENT_PASS',production_qualified=False,
                strict_api_acceleration_enabled=False,private_worker_enclave_execution=True,multi_message_simd=False,
                native_machine=api.machine,deleted=True,inventory=inventory,
                comparisons=comparisons,calls=calls,events=resident.events)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image',type=Path);parser.add_argument('build_record',type=Path)
    parser.add_argument('--child',action='store_true',help=argparse.SUPPRESS);args=parser.parse_args()
    image=args.image.resolve(strict=True)
    require(image.suffix.lower()=='.dll' and 0<image.stat().st_size<=8*1024*1024,'bounded DLL image')
    if args.child:
        print(json.dumps(exercise(storage.WorkerNative(),storage.Windows(),image,args.build_record.parent/'sha3-batch-oracle.txt')));return
    build=json.loads(args.build_record.read_text())
    before=build['source_sha256'].copy()
    for name in ('scripts/cryptography/windows_enclave_sha3_batch_oracle.py','scripts/sha3/check-cshake-differential.py',
                 'scripts/sha3/check-sha3-bit-differential.py'):
        before[name]=hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
    for pattern in ('windows_enclave*.py','windows_protection*.py'):
        for path in (ROOT/'scripts/cryptography').glob(pattern):
            before[path.relative_to(ROOT).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
    def check_sources():
        require(all(hashlib.sha256((ROOT/path).read_bytes()).hexdigest()==digest
                    for path,digest in before.items()),'unchanged built/capture source closure')
    corpus=args.build_record.parent/'sha3-batch-oracle.txt'
    require(hashlib.sha256(corpus.read_bytes()).hexdigest()==build['generated_sha256']['sha3-batch-oracle.txt'],
            'unchanged independently generated corpus')
    check_sources();digest=hashlib.sha256(image.read_bytes()).hexdigest()
    result=subprocess.run([sys.executable,__file__,str(image),str(args.build_record),'--child'],
                          capture_output=True,text=True,timeout=600)
    require(result.returncode==0 and not result.stderr and 0<len(result.stdout)<8*1024*1024,
            f'bounded AVX2 worker failed ({result.returncode}): {result.stderr[-6000:]}')
    record=json.loads(result.stdout)
    require(record.get('comparisons')==50 and record.get('deleted') is True and
            record.get('production_qualified') is False,'complete public-vector campaign')
    check_sources();require(digest==hashlib.sha256(image.read_bytes()).hexdigest(),'unchanged image')
    record.update(schema=1,source_sha256=before,image_sha256=digest,
                  build_sha256=hashlib.sha256(args.build_record.read_bytes()).hexdigest(),
                  windows_build=sys.getwindowsversion().build)
    print(json.dumps(record,indent=2,sort_keys=True))


if __name__=='__main__':main()
