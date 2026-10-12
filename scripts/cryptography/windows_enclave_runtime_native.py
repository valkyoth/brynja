"""Execute ONLY pinned CRT init/copy/fill bodies in a disposable Windows child.

This maps reviewed file bytes, not a DLL through the loader: no DllMain, enclave
entry, imports or secret data are executed. It is a guarded ordinary-process
component test, never evidence of loaded enclave identity or cleanup coverage.
"""
import argparse
import ctypes as C
import json
from pathlib import Path
import subprocess
import sys

import windows_enclave_runtime_catalog as review

require=review.require
LENGTHS=tuple(range(34))+(63,64,65,127,128,129,255,256,257,511,512,513,
    2047,2048,2049,8191,8192,8193,32767,32768,32769,65535,65536,0x180001)
MODES=('detected','sse','sse_rep','avx','avx_rep','avx_streaming')


def modes(level):
    require(type(level) is int and level in (1,2,3,5,6),'actual initializer ISA level')
    return MODES if level>=3 else MODES[:3]


class Api:
    def __init__(self):
        require(sys.platform=='win32' and C.sizeof(C.c_void_p)==8,'native Windows x64 process')
        self.dll=C.WinDLL('kernel32',use_last_error=True)
        signatures={
            'VirtualAlloc':([C.c_void_p,C.c_size_t,C.c_uint32,C.c_uint32],C.c_void_p),
            'VirtualProtect':([C.c_void_p,C.c_size_t,C.c_uint32,C.POINTER(C.c_uint32)],C.c_int),
            'VirtualFree':([C.c_void_p,C.c_size_t,C.c_uint32],C.c_int),
            'FlushInstructionCache':([C.c_void_p,C.c_void_p,C.c_size_t],C.c_int),
            'GetSystemInfo':([C.c_void_p],None),
        }
        for name,(args,result) in signatures.items():
            f=getattr(self.dll,name);f.argtypes=args;f.restype=result;setattr(self,name,f)
        info=C.create_string_buffer(48);self.GetSystemInfo(info)
        self.page=int.from_bytes(info.raw[4:8],'little')
        require(self.page==4096,'reviewed x64 page geometry')

    def protect(self,address,size,flags):
        old=C.c_uint32()
        require(self.VirtualProtect(address,size,flags,C.byref(old))!=0,'memory protection succeeds')


class Region:
    def __init__(self,api,size):
        self.api=api;self.size=((max(1,size)+api.page-1)//api.page)*api.page
        self.base=api.VirtualAlloc(None,self.size+2*api.page,0x3000,1)
        require(bool(self.base),'guarded allocation succeeds')
        self.address=self.base+api.page
        try:api.protect(self.address,self.size,4)
        except BaseException:
            self.close();raise

    def close(self):
        if self.base:
            address=self.base;self.base=0
            require(self.api.VirtualFree(address,0,0x8000)!=0,'guarded allocation released')

    def __enter__(self):return self
    def __exit__(self,*_):self.close()


def settings(mode,initial):
    isa,favor,low,high=initial
    require(mode in modes(isa),'never force unsupported AVX execution')
    if mode=='detected':return initial
    return (1 if mode.startswith('sse') else 3,
        2 if mode.endswith('_rep') else 0,
        0 if mode.endswith('_rep') else low,
        0 if mode=='avx_streaming' else high)


def check_case(copy,fill,src,dst,length,source_at,dest_at):
    payload=(bytes(range(256))*((src.size+255)//256))[:src.size]
    canary=b'\xa5'*dst.size
    C.memmove(src.address,payload,src.size);C.memmove(dst.address,canary,dst.size)
    target=dst.address+dest_at
    require(copy(target,src.address+source_at,length)==target,'copy returns original destination')
    expected=canary[:dest_at]+payload[source_at:source_at+length]+canary[dest_at+length:]
    require(C.string_at(dst.address,dst.size)==expected,'copy byte oracle and both canaries')
    require(C.string_at(src.address,src.size)==payload,'copy source not modified')
    C.memmove(dst.address,canary,dst.size)
    require(fill(target,0x173,length)==target,'fill returns original destination')
    expected=canary[:dest_at]+b'\x73'*length+canary[dest_at+length:]
    require(C.string_at(dst.address,dst.size)==expected,'fill low-byte oracle and both canaries')


def overlap_cases(api,copy):
    count=0
    for length in (1,16,33,128,257,4096,65536):
        with Region(api,length+128) as region:
            data=(bytes(range(251))*((region.size+250)//251))[:region.size]
            for delta in (-31,-7,-1,0,1,7,31):
                source=64;dest=source+delta
                C.memmove(region.address,data,region.size)
                expected=data[:dest]+data[source:source+length]+data[dest+length:]
                require(copy(region.address+dest,region.address+source,length)==region.address+dest,
                    'overlapping copy return identity')
                require(C.string_at(region.address,region.size)==expected,'overlap byte oracle')
                count+=1
    return count


def execute_image(api,data,report,abi_call=None):
    rows,_=review.shared.caller.pe.linked(data)
    with Region(api,max(r['rva']+r['virtual_size'] for r in rows)) as mapped:
        for row in rows:
            C.memmove(mapped.address+row['rva'],row['code'],min(len(row['code']),row['virtual_size']))
        api.protect(mapped.address,mapped.size,2)
        for row in rows:
            flags=0x20 if row['flags']&0x20000000 else 4 if row['flags']&0x80000000 else 2
            api.protect(mapped.address+row['rva'],row['virtual_size'],flags)
        require(api.FlushInstructionCache(C.c_void_p(-1),mapped.address,mapped.size)!=0,'flush mapped code')
        init=report['initializer'];targets={int(k,16):v for k,v in init['targets'].items()}
        read=lambda k:C.c_uint32.from_address(mapped.address+targets[k]).value
        read64=lambda k:C.c_uint64.from_address(mapped.address+targets[k]).value
        initializer=C.WINFUNCTYPE(C.c_int)(mapped.address+init['rva'])
        if abi_call is not None:
            initializer=lambda:abi_call(mapped.address+init['rva'],0,0,0)[0]
        require(initializer()==0,'actual pinned selector initializer returned normally')
        initial=(read(0x11060),read(0x118bc),read64(0x11068),read64(0x11070))
        runtime=report['runtime']['frames']
        copy=C.WINFUNCTYPE(C.c_void_p,C.c_void_p,C.c_void_p,C.c_size_t)(mapped.address+runtime['copy']['rva'])
        fill=C.WINFUNCTYPE(C.c_void_p,C.c_void_p,C.c_int,C.c_size_t)(mapped.address+runtime['fill']['rva'])
        if abi_call is not None:
            copy=lambda dst,src,size:abi_call(mapped.address+runtime['copy']['rva'],dst,src,size)[0]
            fill=lambda dst,value,size:abi_call(mapped.address+runtime['fill']['rva'],dst,value,size)[0]
        counts={}
        for mode in modes(initial[0]):
            values=settings(mode,initial)
            for key,value in zip((0x11060,0x118bc,0x11068,0x11070),values):
                kind=C.c_uint32 if key in (0x11060,0x118bc) else C.c_uint64
                kind.from_address(mapped.address+targets[key]).value=value
            count=0
            for length in LENGTHS:
                with Region(api,length+32) as src,Region(api,length+32) as dst:
                    # Include exact guard adjacency on either side, plus
                    # unaligned inputs. Zero length also receives the guard VA.
                    placements=sorted({0,1,31,src.size-length})
                    for index,source_at in enumerate(placements):
                        dest_at=placements[-1-index]
                        check_case(copy,fill,src,dst,length,source_at,dest_at);count+=2
            counts[mode]=dict(copy_and_fill_cases=count,overlap_cases=overlap_cases(api,copy))
        return dict(initial_isa_level=initial[0],initial_favor=initial[1],
            initial_fill_thresholds=list(initial[2:]),modes=counts,
            avx_executed=initial[0]>=3,guard_pages_used=True,secret_material_used=False,
            nonvolatile_sentinels_checked=abi_call is not None)


def exercise(base):
    api=Api();records=[]
    for row in review.catalog():
        data=(base/row['image']).read_bytes()
        require(review.digest(data)==row['sha256'],'only frozen original image bytes may execute')
        record=review.inspect(data)
        print('RUNTIME_COMPONENT_STEP: '+row['route'],file=sys.stderr,flush=True)
        records.append(dict(route=row['route'],image_sha256=row['sha256'],**execute_image(api,data,record)))
    return dict(schema=1,status='WINDOWS_PINNED_MEMORY_RUNTIME_COMPONENT_PASS',records=records,
        windows_build=sys.getwindowsversion().build,route_count=19,
        native_enclave_run=False,loaded_application_iat_proven=False,
        whole_image_qualified=False,release_gate_changed=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('saved_directory',type=Path)
    parser.add_argument('--child',action='store_true');args=parser.parse_args()
    if args.child:print(json.dumps(exercise(args.saved_directory),indent=2))
    else:
        result=subprocess.run([sys.executable,__file__,str(args.saved_directory),'--child'],
            capture_output=True,text=True,timeout=240)
        require(result.returncode==0 and 0<len(result.stdout)<1000000,
            'bounded isolated helper child completed: '+result.stderr[-4000:])
        record=json.loads(result.stdout)
        require(record['route_count']==19 and len(record['records'])==19,'all image probes completed')
        print(result.stdout,end='')
