"""Exact saved arithmetic, compare and probe bodies across nineteen images.

These are ordinary runtime helpers, not constant-time or erasing primitives.
Probe geometry is conditional on the real OS stack limit and mapped window.
No release gate, admission rule or production implementation is changed.
"""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_runtime_workers as workers
import windows_enclave_caller_unwind as unwind

r=workers.catalog
require,digest=r.require,r.digest
BODIES={
    '__chkstk': '4883ec104c8914244c895c24084d33db4c8d5424184c2bd04d0f42d3'
        '654c8b1c25100000004d3bd37316664181e200f04d8d9b00f0ffff41c603004d3bd375f0'
        '4c8b14244c8b5c24084883c410c3',
    '__umodti3': '56574c8b014c8b49084c8b12488b7a084885ff74754c0fbddf4489d883f03fb140'
        '28c14c89d0480fadf84889fe48d3eef6c140480f44f04c89c84c0fa4c03f4c89ca48d1ea'
        '48f7f64889c64489d948d3ee4883fe014883d6ff4889f94c89d048f7e6480fafce4801ca'
        '4929c04919d131c04d39d04c89c94819f9480f42f84c0f42d04d29d04919f9eb3a4d39d1'
        '730b4c89c04c89ca49f7f2eb244c89c84c09d048c1e820740a4c89c831d249f7f2eb08'
        '4489c831d241f7f24c89c049f7f24531c94989d066490f6ec066490f6ec9660f6cc15f5ec3',
    '__udivti3': '56574c8b094c8b51084c8b02488b7a084885ff74664c0fbddf4489d883f03fb140'
        '28c14c89c0480fadf84889fe48d3eef6c140480f44f04c89d04c0fa4c83f4c89d248d1ea'
        '48f7f64889c64489d948d3ee4883fe014883d6ff4989fb4c0fafde4c89c048f7e64c01da'
        '4929c14919d24d39c14919fa4883deffeb114d39c2731f4c89c84c89d249f7f04889c6'
        '31c966480f6ec666480f6ec9660f6cc15f5ec34c89d04c09c048c1e820740d4c89d031d2'
        '49f7f04889c1eb0a4489d031d241f7f089c14c89c849f7f04889c6ebc1',
    'memcmp': '482bd14983f8087222f6c107741466908a013a0411752c48ffc149ffc8f6c10775ee'
        '4d8bc849c1e903751f4d85c0740f8a013a0411750c48ffc149ffc875f14833c0c31bc083d8ff'
        'c39049c1e9027437488b01483b0411755b488b4108483b441108754c488b4110483b441110'
        '753d488b4118483b441118752e4883c12049ffc975cd4983e01f4d8bc849c1e903749b488b01'
        '483b0411751b4883c10849ffc975ee4983e007eb834883c1084883c1084883c108488b0c0a'
        '480fc8480fc9483bc11bc083d8ffc3',
}
BODIES={n:bytes.fromhex(v) for n,v in BODIES.items()}


def check_body(name,code):
    require(name in BODIES and code==BODIES[name],'complete runtime body: '+name)


def probe_pages(caller_sp,allocation,stack_limit,window_low):
    """Exact page-touch projection of this body, with explicit OS prerequisites.

    caller_sp is RSP immediately before CALL, after any prologue pushes. The
    helper reconstructs it using its own 8-byte return + 16-byte save area.
    The wrapper must already have committed/locked the complete private window.
    """
    require(all(type(v) is int and 0<=v<1<<64 for v in
        (caller_sp,allocation,stack_limit,window_low)),'probe unsigned domain')
    require(window_low%4096==stack_limit%4096==0 and
        stack_limit<=caller_sp and window_low<=caller_sp<=window_low+65536 and
        window_low+65536<1<<64 and allocation<=caller_sp-window_low,
        'probe OS limit and requested extent inside admitted window')
    require(caller_sp-24>=window_low,'probe return and saved R10/R11 inside window')
    target=caller_sp-allocation
    if target>=stack_limit:return []
    target &= ~4095
    require(target>=window_low,'page rounding remains inside admitted window')
    return list(range(stack_limit-4096,target-1,-4096))


def divide_low(numerator,divisor):
    """Arithmetic projection for the actually admitted high-zero operand domain.

    Long-division/general-u128 paths are NOT inferred from this projection.
    Both input pointers refer to readable little-endian 16-byte public operands.
    """
    require(type(numerator) is int and 0<=numerator<1<<64 and
        type(divisor) is int and 0<divisor<1<<64,'nonzero public u64 division domain')
    return divmod(numerator,divisor)


def inspect(image,functions,records):
    rows,table=r.sdk.pe.linked(image);result={}
    for name,expected in BODIES.items():
        callers={n:v['reference_targets'][name] for n,v in records.items()
            if name in v['reference_targets']}
        if not callers:continue
        require(len(set(callers.values()))==1,'one linked helper identity per image')
        address=next(iter(callers.values()))
        code=r.memory.prior.session.executable(rows,address,len(expected));check_body(name,code)
        frames=unwind.extent(rows,table,address,len(code))
        require(len(frames)==1 and frames[0]['stack_bytes']==(0 if name=='memcmp' else 16),
            'runtime local frame agrees with emitted instructions')
        sites=[]
        for caller in callers:
            raw,refs,_=functions[caller]
            selected=[v for v in refs if v['symbol']==name]
            require(selected,'nonvacuous actual COFF runtime references')
            for ref in selected:
                at=ref['offset']
                require(ref['addend']==ref['trailing']==0 and at>=1 and
                    raw[at-1:at+4]==b'\xe8'+bytes(4),'direct runtime CALL, not data/address reference')
                site=dict(caller=caller,offset=at-1)
                if name=='__chkstk':
                    require(at>=6 and raw[at-6]==0xb8 and raw[at+4:at+7]==b'\x48\x29\xc4',
                        'constant EAX probe immediately followed by matching RSP subtraction')
                    size=int.from_bytes(raw[at-5:at-1],'little')
                    require(0<size<65536,'bounded positive worker probe allocation')
                    site['requested_bytes']=size
                sites.append(site)
        result[name]=dict(rva=address,bytes=len(code),sha256=digest(code),frames=frames,sites=sites,
            fixed_stack_bytes=0 if name=='memcmp' else 16,
            nested_calls=False,constant_time=False,individually_erasing=False)
    return result


def collect(base):
    result=[]
    for row in r.catalog():
        data,image=workers.load(base,row);functions,records=workers.bind(data,image)
        result.append(dict(route=row['route'],image_sha256=digest(image),object_sha256=digest(data),
            worker_count=len(records),helpers=inspect(image,functions,records)))
    return dict(schema=1,status='AUTHOR_SAVED_RUNTIME_ARITHMETIC_AND_PROBE_REVIEW',records=result,
        whole_image_qualified=False,cumulative_stack_bound_proven=False,
        os_stack_limit_and_operand_lifetimes_required=True,
        general_u128_correctness_qualified=False,new_native_enclave_run=False,
        release_gate_changed=False,independently_verified=False,
        source_sha256={p.name:digest(p.read_bytes()) for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}|{Path(__file__)})})


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('saved_directory',type=Path)
    print(json.dumps(collect(parser.parse_args().saved_directory),indent=2))
