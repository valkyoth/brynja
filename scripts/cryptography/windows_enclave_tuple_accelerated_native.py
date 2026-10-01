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



def exercise(api,host,image):
    require(api.machine=='0x8664' and host.geometry()==(4096,65536),'native x64 geometry')
    base=api.create();initialized=False;calls=[];comparisons=0
    resident=storage.Retained(host,base,False)
    output=(c.c_ubyte*1024)()
    try:
        loaded,error=api.load(base,image);require(loaded,f'image load: {error}')
        count=api.initialize_worker(base);initialized=True;require(count==1,'one serialized enclave worker')
        for private in (b'RetainedWork',b'PublicRustBody',b'PublicTupleInput',b'PublicTupleOutput'):
            require(not api.GetProcAddress(base,private),'no exported bypass of the baseline C entry')
        def export(name):return api.check(api.GetProcAddress(base,name.encode()),name)
        routine=export('PublicRetained');window=export('PublicLockedWindow');register=export('PublicLockedHost')
        control=export('PublicRetainedControl');guards=export('PublicGuardControl')
        out_register=export('PublicRetainedOutput');in_register=export('PublicTupleInputSource')
        input_control=export('PublicTupleControl');cpu=export('PublicCpuInventory')
        inventory=interpret([api.call(cpu,i) for i in range(11)])
        require(inventory['observed_prerequisites']['avx2_batch_or_keccak'],'complete specialized bundle')
        protocol=export('PublicTupleAvx2Protocol')
        require(api.call(protocol,0)==0x42525432 and api.call(protocol,1)==0,'distinct AVX2 image protocol')
        require(api.call(out_register,c.addressof(output))==1,'register public output')
        def operation(op,sequence=0,identity=0,data=b'',last=0,width=0,terminal=False,item_bits=0,custom_bits=0,expected=None,fault=None):
            payload=(c.c_ubyte*max(1,len(data)))()
            if data:c.memmove(payload,data,len(data))
            words=[16,sequence,identity,len(data),last,c.addressof(payload) if data else 0,width,int(terminal),
                   item_bits & ((1<<64)-1),item_bits>>64,custom_bits & ((1<<64)-1),custom_bits>>64,1,0]
            if fault=='version':words[0]=7
            elif fault=='sequence':words[1]=0
            elif fault=='route':words[12]=0
            elif fault=='reserved':words[13]=1
            elif fault=='length':words[3]=1025
            elif fault=='payload-copy':words[5]=1
            header=(c.c_ubyte*112).from_buffer_copy(struct.pack('<14Q',*words))
            source=1 if fault=='header-copy' else c.addressof(header)
            require(api.call(in_register,source if op>=60 else 0)==1,'register metadata')
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
            require(report[0]==status and report[3:]==[int(op!=3),int(op>=60 and not fault),
                    4096 if op==3 else 0,int(op==3),0,1,op],f'exact worker outcome: {report}, expected {status}')
            require(report[2]==report[1]+4096 and report[1]%4096==0,'retained page geometry')
            require(report[1]+12288<=values[1]-4096 or report[1]>=values[2]+4096,'disjoint page and worker')
            raw=[api.call(input_control,x) for x in range(16,23)]
            if op>=60:
                require(values[1]<=raw[0] and raw[0]+112<=values[2] and
                        values[1]<=raw[1] and raw[1]+1024<=values[2] and raw[2]==1,'cleared protected copy buffers')
                require(raw[3]==int(fault!='header-copy'),'header copy receipt')
                require(raw[4]==int(bool(data) and fault in (None,'quarantined')),'payload copy receipt')
                require(raw[5]==int(op == 68 and not fault),'explicit output receipt')
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

        # Existing independent SP 800-185 bit oracle; all inputs are PUBLIC fixtures.
        path=ROOT/'scripts/tuplehash/check-tuplehash-differential.py'
        spec=importlib.util.spec_from_file_location('tuple_oracle',path)
        oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
        oracle.verify_oracle()
        def reference(identity,items,custom,cb,ob):
            return oracle.tuple_hash(168 if identity in (1,3) else 136,
                [oracle.oracle.byte_bits(data)[:bits] for data,bits in items],
                oracle.oracle.byte_bits(custom)[:cb],ob,identity>2)
        def feed(op,seq,data,bits):
            # Start with a fractional fragment then cross snapshot/rate boundaries.
            offset=0
            for width in (3,8192,7,4096)*((bits//4096)+2):
                if offset==bits:break
                n=min(width,bits-offset)
                fragment=bytearray((n+7)//8)
                for bit in range(n):
                    fragment[bit//8]|=((data[(offset+bit)//8]>>((offset+bit)%8))&1)<<(bit%8)
                seq+=1;operation(op,seq,data=bytes(fragment),last=(n-1)%8+1)
                offset+=n
            require(offset==bits,'complete generated fragments')
            return seq
        def setup(identity,custom=b'',cb=0,seq=0):
            seq+=1;operation(60,seq,identity,custom_bits=cb)
            seq=feed(61,seq,custom,cb)
            seq+=1;operation(62,seq)
            return seq
        def items(seq,values):
            for data,bits in values:
                seq+=1;operation(63,seq,item_bits=bits)
                seq=feed(64,seq,data,bits)
                seq+=1;operation(65,seq)
            return seq
        def finish(identity,seq,ob):
            seq+=1;operation(66,seq,width=(ob+7)//8 if identity<=2 else 0,
                last=(ob-1)%8+1 if identity<=2 and ob else 0)
            if identity>2:
                seq+=1;operation(67,seq,width=(ob+7)//8,last=(ob-1)%8+1 if ob else 0,terminal=True)
            return seq
        def export_result(identity,seq,expected,ob):
            seq+=1;operation(68,seq,identity,width=len(expected),last=(ob-1)%8+1 if ob else 0,expected=expected)
            return seq
        for identity in range(1,5):
            for index in range(8):
                cb=(0,1,7,8,9,1083,16391,3)[index]
                mb=(0,1,7,8,9,1087,1344,8201)[index]
                ob=(256,257,511,512,1347,256,259,0)[index]
                custom=oracle.oracle.canonical(0x200000+index,cb)
                message=oracle.oracle.canonical(0x300000+index,mb)
                values=[] if index==0 else [(message,mb),(b'',0),(bytes([5]),3)]
                expected=reference(identity,values,custom,cb,ob)
                operation(0);seq=setup(identity,custom,cb)
                seq=items(seq,values);seq=finish(identity,seq,ob)
                export_result(identity,seq,expected,ob);comparisons+=1;operation(3)
        # All sixteen cross-identity retained compositions, no intermediate export.
        for identity in range(1,5):
            for target in range(1,5):
                retained=reference(identity,[(b'abc',24)],b'',0,259)
                expected=reference(target,[(retained,259)],bytes([5]),3,256)
                operation(0);seq=setup(identity);seq=items(seq,[(b'abc',24)])
                seq=finish(identity,seq,259)
                seq+=1;operation(69,seq,target,custom_bits=3)
                seq+=1;operation(61,seq,data=bytes([5]),last=3)
                seq+=1;operation(62,seq)
                seq=finish(target,seq,256)
                export_result(target,seq,expected,256);comparisons+=1;operation(3)
        # Nonterminal XOF chunks and partial final output across both rate widths.
        for identity in (3,4):
            expected=reference(identity,[(b'abc',24)],b'',0,1603)
            operation(0);seq=setup(identity);seq=items(seq,[(b'abc',24)])
            seq+=1;operation(66,seq)
            offset=0
            for width,last,terminal in ((0,0,False),(17,8,False),(183,8,False),(1,3,True)):
                seq+=1;operation(67,seq,width=width,last=last,terminal=terminal)
                seq+=1;operation(68,seq,identity,width=width,last=last,expected=expected[offset:offset+width])
                offset+=width
            require(offset==len(expected),'full incremental XOF output')
            comparisons+=1
            seq=setup(identity,seq=seq);seq+=1;operation(70,seq);operation(3)
        for fault in ('version','sequence','route','reserved','length','header-copy','payload-copy'):
            operation(0);seq=setup(1)
            seq+=1;operation(63,seq,item_bits=24)
            operation(64,seq+1,data=b'abc',last=8,fault=fault)
            operation(70,seq+1,fault='quarantined');operation(3)
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
    for name in ('scripts/tuplehash/check-tuplehash-differential.py','scripts/sha3/check-cshake-differential.py',
                 'scripts/sha3/check-sha3-bit-differential.py'):
        before[name]=hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
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
    require(record.get('comparisons')==50 and record.get('deleted') is True and
            record.get('production_qualified') is False,'complete public-vector campaign')
    check_sources();require(digest==hashlib.sha256(image.read_bytes()).hexdigest(),'unchanged image')
    record.update(schema=1,source_sha256=before,image_sha256=digest,
                  build_sha256=hashlib.sha256(args.build_record.read_bytes()).hexdigest(),
                  windows_build=sys.getwindowsversion().build)
    print(json.dumps(record,indent=2,sort_keys=True))


if __name__=='__main__':main()
