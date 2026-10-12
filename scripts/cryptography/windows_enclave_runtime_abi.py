"""Windows-only public-data runtime oracle and nonvolatile sentinel checks.

No DLL loader, imports, enclave entry or secret material. The wrapper saves the
host's eight nonvolatile GPRs and ten XMM registers, allocates aligned home space,
seeds sentinels, calls one reviewed helper, captures RAX/XMM0, checks sentinels,
then restores the host. This is sampled ABI evidence, not a general ABI proof.
"""
import ctypes as C
import random
import sys

import windows_enclave_runtime_native as native
import windows_enclave_runtime_arithmetic as arithmetic

require=native.require
# 676-byte Win64 wrapper: 64 bytes of pushes + 232-byte allocation. Out pointer
# is incoming argument five (entry+40 => current+336), saved at current+192.
# Locals 32..191 save XMM6..15; 0..31 is the helper's exclusive outgoing home.
# All failure branches join the SAME restore epilogue; no early RET exists.
WRAPPER=bytes.fromhex(
    '5355565741544155415641574881ece8000000f30f7f742420f30f7f7c2430f3440f7f442440'
    'f3440f7f4c2450f3440f7f542460f3440f7f5c2470f3440f7fa42480000000f3440f7fac2490000000'
    'f3440f7fb424a0000000f3440f7fbc24b00000004c8b9424500100004c899424c00000004889c84889d1'
    '4c89c24d89c8bb03005713bd05005713be06005713bf0700571341bc0c00571341bd0d00571341be0e005713'
    '41bf0f005713660f76f6660f76ff66450f76c066450f76c966450f76d266450f76db66450f76e466450f76ed'
    '66450f76f666450f76ffffd04c8b9424c0000000498902f3410f7f420849c74218000000004881fb03005713'
    '0f853d0100004881fd050057130f85300100004881fe060057130f85230100004881ff070057130f8516010000'
    '4981fc0c0057130f85090100004981fd0d0057130f85fc0000004981fe0e0057130f85ef0000004981ff0f005713'
    '0f85e2000000660f76c9660f6fc6660f74c1660fd7c03dffff00000f85c7000000660f6fc7660f74c1660fd7c0'
    '3dffff00000f85b000000066410f6fc0660f74c1660fd7c03dffff00000f859800000066410f6fc1660f74c1660f'
    'd7c03dffff00000f858000000066410f6fc2660f74c1660fd7c03dffff0000756c66410f6fc3660f74c1660fd7c0'
    '3dffff0000755866410f6fc4660f74c1660fd7c03dffff0000754466410f6fc5660f74c1660fd7c03dffff0000'
    '753066410f6fc6660f74c1660fd7c03dffff0000751c66410f6fc7660f74c1660fd7c03dffff0000750849c74218'
    '01000000f30f6f742420f30f6f7c2430f3440f6f442440f3440f6f4c2450f3440f6f542460f3440f6f5c2470'
    'f3440f6fa42480000000f3440f6fac2490000000f3440f6fb424a0000000f3440f6fbc24b00000004881c4e800'
    '0000415f415e415d415c5f5e5d5bc3')


def executable(api,region,code):
    require(len(code)<=region.size,'bounded test code allocation')
    C.memmove(region.address,code,len(code));api.protect(region.address,region.size,0x20)
    require(api.FlushInstructionCache(C.c_void_p(-1),region.address,len(code))!=0,'flush test helper code')


def call(wrapper,address,a,b,c=0):
    output=C.create_string_buffer(32)
    wrapper(address,a,b,c,C.addressof(output))
    require(int.from_bytes(output.raw[24:32],'little')==1,'all nonvolatile ABI sentinels preserved')
    return int.from_bytes(output.raw[:8],'little'),int.from_bytes(output.raw[8:24],'little')


def corruptions():
    # Deliberately wrong callees: zero each of RBX/RBP/RSI/RDI/R12..15 and
    # XMM6..15. They return normally so the wrapper must report rejection and
    # still restore Python's original nonvolatile state on every path.
    gprs=[bytes.fromhex(v) for v in ('31db','31ed','31f6','31ff','4531e4','4531ed','4531f6','4531ff')]
    xmm=[bytes.fromhex('660fef')+bytes([0xc0+9*n]) for n in (6,7)]
    xmm += [bytes.fromhex('66450fef')+bytes([0xc0+9*(n-8)]) for n in range(8,16)]
    return [v+b'\xc3' for v in gprs+xmm]


def self_test(api,wrapper):
    with native.Region(api,4096) as region:
        executable(api,region,b'\xc3');call(wrapper,region.address,0,0)
    count=0
    for code in corruptions():
        with native.Region(api,len(code)) as region:
            executable(api,region,code)
            try:call(wrapper,region.address,0,0)
            except ValueError:count+=1
            else:raise AssertionError('ABI register-clobber mutant escaped')
    require(count==18,'all eight GPR and ten XMM clobbers rejected')
    return count


def operands():
    boundaries=(0,1,7,8,135,136,167,168,(1<<32)-1,1<<32,(1<<64)-1)
    pairs=[(a,b) for a in boundaries for b in boundaries if b]
    rng=random.Random(0x4252594e4a41)
    pairs += [(rng.getrandbits(64),rng.getrandbits(64) or 1) for _ in range(256)]
    # Exercise the general branches too, but label these differential samples,
    # not a proof that every caller satisfies the narrower reviewed contract.
    full=(1<<64,(1<<64)+1,(1<<127)-1,1<<127,(1<<128)-1)
    pairs += [(a,b) for a in (*boundaries,*full) for b in full]
    pairs += [(rng.getrandbits(128),rng.getrandbits(128) or 1) for _ in range(256)]
    return pairs


def division(api,wrapper,address,name):
    pairs=operands()
    with native.Region(api,4096) as left,native.Region(api,4096) as right:
        a=left.address+left.size-16;b=right.address+right.size-16
        for numerator,divisor in pairs:
            x=numerator.to_bytes(16,'little');y=divisor.to_bytes(16,'little')
            C.memmove(a,x,16);C.memmove(b,y,16)
            _,actual=call(wrapper,address,a,b)
            expected=divmod(numerator,divisor)[name=='__umodti3']
            require(actual==expected,'actual runtime division/remainder matches independent Python integer oracle')
            require(C.string_at(a,16)==x and C.string_at(b,16)==y,'public arithmetic operands unchanged')
    return len(pairs)


def comparison(api,wrapper,address):
    count=0
    with native.Region(api,8192) as left,native.Region(api,8192) as right:
        for size in (*range(34),63,64,65,127,128,129,255,256,257,4095,4096):
            for offset in (0,1,left.size-size):
                a=left.address+offset;b=right.address+offset
                data=bytes((i*17+33)%256 for i in range(size))
                for at in sorted({-1,0,size//2,size-1}):
                    if at>=size:continue
                    other=bytearray(data)
                    if at>=0:other[at]^=0xff
                    C.memmove(a,data,size);C.memmove(b,bytes(other),size)
                    value,_=call(wrapper,address,a,b,size);signed=C.c_int32(value&0xffffffff).value
                    require((signed>0)-(signed<0)==(data>other)-(data<other),'memcmp unsigned-byte lexical oracle')
                    require(C.string_at(a,size)==data and C.string_at(b,size)==bytes(other),
                        'compare inputs unchanged')
                    count+=1
    return count


def exercise(base):
    api=native.Api();records=[]
    with native.Region(api,len(WRAPPER)) as wrapper_region:
        executable(api,wrapper_region,WRAPPER)
        wrapper=C.WINFUNCTYPE(None,C.c_void_p,C.c_void_p,C.c_void_p,C.c_size_t,C.c_void_p)(wrapper_region.address)
        mutants=self_test(api,wrapper)
        for route in arithmetic.r.catalog():
            data,image=arithmetic.workers.load(base,route)
            functions,bound=arithmetic.workers.bind(data,image)
            reviewed=arithmetic.inspect(image,functions,bound)
            counts={}
            for name,record in reviewed.items():
                if name=='__chkstk':continue  # Real OS-stack context, never call on a fake stack.
                code=arithmetic.BODIES[name]
                with native.Region(api,len(code)) as region:
                    executable(api,region,code)
                    counts[name]=(comparison(api,wrapper,region.address) if name=='memcmp' else
                        division(api,wrapper,region.address,name))
            print('RUNTIME_ARITHMETIC_STEP: '+route['route'],file=sys.stderr,flush=True)
            memory=native.execute_image(api,image,native.review.inspect(image),
                lambda target,a,b,c:call(wrapper,target,a,b,c))
            records.append(dict(route=route['route'],image_sha256=route['sha256'],cases=counts,memory=memory))
    return dict(schema=1,status='WINDOWS_PUBLIC_RUNTIME_ARITHMETIC_COMPONENT_PASS',records=records,
        windows_build=sys.getwindowsversion().build,abi_clobber_mutants_rejected=mutants,
        native_enclave_run=False,stack_probe_executed=False,whole_image_qualified=False,
        secret_material_used=False,wrapper_sha256=arithmetic.digest(WRAPPER),
        general_u128_correctness_proven=False,release_gate_changed=False)
