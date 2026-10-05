"""Selected saved session/kernel and public arithmetic/probe review, not a gate."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

import windows_enclave_root_setup as setup
from windows_enclave_frame_geometry import Frame, Window, require

engine = setup.construction.engine
slot = setup.slot
cleanup = setup.cleanup
ROUND_TABLE = 'anon.886b1edfcdffe7c13102d1d0ad2ffa3f.1'
BODIES = {
    'session': (engine.SESSION,107,'6249e31d1445bc78afcee97aee5489b3712d193f5fb90acc4affd11bf3e6ae13'),
    'kernel': (engine.KERNEL,1142,'967732a334f2d893eb84fdeeab0d0c47dab8a73fbce4409322faca357edc01e5'),
    '__umodti3': (0x6f70,213,'60856d8bee3328cb0530ddcdb4c4711a6778f54c71829adb17578e7b398160df'),
    '__chkstk': (0x8550,78,'24ba2f8e6f97e3f8dec9771f775f11294b7da43ba09efabbb1bd3c079ac25b6e'),
}
CALLS = {'session': {0x5b:engine.KERNEL,0x63:cleanup.SCRATCH}, 'kernel': {0x51:ROUND_TABLE}}
ANCHORS = (
    ('session',0,'564883ec204c8b8140020000410fb6400885c0'),
    ('session',0x15,'83f801'), ('session',0x1a,'4d8b08b0054c3b8948020000'),
    ('session',0x28,'450fb64009b00141b92c000000450fa3c1'),
    ('session',0x3b,'31c0'), ('session',0x3f,'b003'), ('session',0x43,'b004'),
    ('session',0x45,'4883c4205ec3'), ('session',0x4b,'41b903000000450fa3c1'),
    ('session',0x57,'4889ce'), ('session',0x5f,'4889f1'), ('session',0x67,'b0ff'),
    ('kernel',0,'4881eca8000000c57829bc2490000000c57829b42480000000c578296c2470'
                   'c57829642460c578295c2450c57829542440c578294c2430c57829442420c5f8297c2410c5f8293424'),
    ('kernel',0x48,'4989d14989ca'),
    ('kernel',0x55,'31c9498b04094989040a4883c1084881f9c8000000'),
    ('kernel',0x3cb,'4b8b04034931024983c0084981f8c0000000'),
    ('kernel',0x3e3,'31c9498b040a498904094883c1084881f9c8000000'),
    ('kernel',0x3fa,'31c031c94989040a4883c1084881f940020000'),
    ('kernel',0x40f,'c5fdefc0c5f5efc9c5edefd2c5e5efdb31c031c931d24531c039c0c5f877'),
    ('kernel',0x42d,'c5f8283424c5f8287c2410c57828442420c578284c2430c57828542440'
                       'c578285c2450c57828642460c578286c2470c57828b42480000000'
                       'c57828bc24900000004881c4a8000000c3'),
    ('__umodti3',0,'56574c8b014c8b49084c8b12488b7a084885ff'),
    ('__umodti3',0x8a,'4d39d1'), ('__umodti3',0x8f,'4c89c04c89ca49f7f2'),
    ('__umodti3',0xbe,'4531c94989d066490f6ec066490f6ec9660f6cc15f5ec3'),
    ('__chkstk',0,'4883ec104c8914244c895c24084d33db4c8d5424184c2bd04d0f42d3'
                    '654c8b1c25100000004d3bd3'),
    ('__chkstk',0x2a,'664181e200f04d8d9b00f0ffff41c603004d3bd3'),
    ('__chkstk',0x40,'4c8b14244c8b5c24084883c410c3'),
)
BRANCHES = (
    ('session',0x13,b'\x74',0x3f), ('session',0x18,b'\x75',0x43),
    ('session',0x26,b'\x75',0x45), ('session',0x39,b'\x73',0x4b),
    ('session',0x3d,b'\xeb',0x45), ('session',0x41,b'\xeb',0x45),
    ('session',0x55,b'\x72',0x45), ('session',0x69,b'\xeb',0x45),
    ('kernel',0x6a,b'\x75',0x57), ('kernel',0x3dd,b'\x0f\x85',0x6f),
    ('kernel',0x3f8,b'\x75',0x3e5), ('kernel',0x40d,b'\x75',0x3fe),
    ('__umodti3',0x13,b'\x74',0x8a), ('__umodti3',0x8d,b'\x73',0x9a),
    ('__umodti3',0x98,b'\xeb',0xbe),
    ('__chkstk',0x28,b'\x73',0x40), ('__chkstk',0x3e,b'\x75',0x30),
)
ROUND_CONSTANTS = (
    0x0000000000000001,0x0000000000008082,0x800000000000808a,0x8000000080008000,
    0x000000000000808b,0x0000000080000001,0x8000000080008081,0x8000000000008009,
    0x000000000000008a,0x0000000000000088,0x0000000080008009,0x000000008000000a,
    0x000000008000808b,0x800000000000008b,0x8000000000008089,0x8000000000008003,
    0x8000000000008002,0x8000000000000080,0x000000000000800a,0x800000008000000a,
    0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008,
)


def check_bodies(bodies):
    require(set(bodies)==set(BODIES),'session/runtime body population')
    for n,(_,size,digest) in BODIES.items():
        require(len(bodies[n])==size and hashlib.sha256(bodies[n]).hexdigest()==digest,
                'reviewed session/runtime body: '+n)


def check_instructions(bodies,refs):
    require(set(bodies)==set(BODIES) and set(refs)==set(CALLS),'session/runtime inputs')
    for n,calls in CALLS.items():
        require(len(refs[n])==len(calls) and {r['offset']:r['symbol'] for r in refs[n]}==calls,
                'session/kernel relocation population')
        for r in refs[n]:
            o=r['offset']; op=b'\x4c\x8d\x1d' if n=='kernel' else b'\xe8'
            require(r['addend']==r['trailing']==0 and bodies[n][o-len(op):o+4]==op+bytes(4),
                    'session/kernel reference operand')
    for n,o,h in ANCHORS:
        code=bytes.fromhex(h)
        require(bodies[n][o:o+len(code)]==code,'session/runtime semantic landmark')
    for n,o,op,target in BRANCHES:
        width=4 if len(op)==2 else 1
        end=o+len(op)+width
        require(bodies[n][o:o+len(op)]==op and
                end+int.from_bytes(bodies[n][end-width:end],'little',signed=True)==target,
                'session/runtime branch')


def executable(rows,rva,size):
    # Check all overlapping mappings, not just one conveniently matching span.
    require(type(rva) is int and type(size) is int and rva>=0 and 0<size<=65536,
            'bounded runtime range')
    matches=[r for r in rows if r['rva']<rva+size and rva<r['rva']+r['virtual_size']]
    require(len(matches)==1,'single runtime code mapping')
    r=matches[0]; offset=rva-r['rva']
    require(r['flags'] & 0x20000000 and not r['flags'] & 0x80000000 and
            0<=offset and offset+size<=min(len(r['code']),r['virtual_size']),
            'complete nonwritable runtime code')
    return r['code'][offset:offset+size]


def check_frames(records,frames):
    require(set(frames)==set(CALLS),'session/kernel frame population')
    for n,size in (('session',40),('kernel',168)):
        require(records[n]['handler'] is None and len(frames[n])==1 and
                frames[n][0]['stack_bytes']==size,'selected no-handler fixed frame')
    require(frames['kernel'][0]['saved_registers']==[
        dict(register_class='xmm',register=r,offset=16*(r-6)) for r in range(6,16)],
        'kernel exact nonvolatile vector saves')


def session_path(health,generation_matches,kernel):
    """Emitted static-build branch model, valid enum inputs only; not execution."""
    require(type(health) is int and health in range(3) and type(generation_matches) is bool
            and type(kernel) is int and kernel in range(6),'valid authority model domain')
    if health==0: return 'NotReady'
    if health!=1: return 'Quarantined'
    if not generation_matches: return 'StaleGeneration'
    if 0x2c & (1<<kernel): return 'WrongArchitecture'
    if 3 & (1<<kernel): return 'MissingTargetFeatures'
    return 'kernel_then_wipe'


def prefix_remainder(numerator,divisor):
    """Only the admitted root's high-zero public division path, not all u128."""
    require(type(numerator) is int and 0<=numerator<1<<64 and divisor in (136,168),
            'public prefix remainder domain')
    return divmod(numerator,divisor)[1]


def geometry():
    w=Window(0,65536)
    session=Frame.enter(w,65504,40)
    kernel=Frame.enter(w,session.current,168)
    scratch=Frame.enter(w,session.current,40)
    body=Frame.enter(w,65504,168)
    root=Frame.enter(w,body.current,11160,32)
    new=Frame.enter(w,root.current,7736,32)
    # __umodti3 is a leaf: two pushes, no aligned call-site requirement.
    remainder_entry=new.current-8
    # Probe runs BEFORE the constructor allocates/alignment-rounds its frame.
    new_entry=root.current-8
    probe_entry=new_entry-64-8
    spans=[session.slot('session saved RSI',-8,8,'entry'),
           kernel.slot('kernel saved caller XMM6-XMM15',0,160),
           scratch.slot('scratch wipe saved RSI',-8,8,'entry'),
           w.span('public remainder RSI/RDI saves',remainder_entry-16,16),
           w.span('probe R10/R11 saves',probe_entry-16,16)]
    return dict(relative_session_frame_bytes=40,relative_kernel_frame_bytes=168,
                spans=spans,kernel_saves_individually_erased=False,
                probe_page_addresses_qualified=False,transitive_depth_qualified=False,
                kernel_and_scratch_calls_are_sequential=True)


def inspect(data,image,mutate=False):
    prior=setup.inspect(data,image)  # Pins both originals before parsing.
    operations=engine.inspect(data,image)
    selected={n:cleanup.caller.function(data,BODIES[n][0]) for n in CALLS}
    bodies={n:v[0] for n,v in selected.items()}
    records={n:slot.binding.bind(data,image,BODIES[n][0]) for n in CALLS}
    rows,functions=cleanup.caller.pe.linked(image)
    frames={n:cleanup.caller.unwind.extent(rows,functions,r['rva'],r['size']) for n,r in records.items()}
    check_frames(records,frames)
    for n in ('__umodti3','__chkstk'):
        rva,size,_=BODIES[n]
        require(prior['entries']['new']['reference_targets'][n]==rva,'constructor runtime edge')
        bodies[n]=executable(rows,rva,size)
        unwind=cleanup.caller.unwind.extent(rows,functions,rva,size)
        require(len(unwind)==1 and unwind[0]['stack_bytes']==16,'reviewed runtime frame')
        records[n]=dict(rva=rva,bytes=size,unwind=unwind)
    check_bodies(bodies)
    check_instructions(bodies,{n:v[1] for n,v in selected.items()})
    known={r['entry']:r['rva'] for r in records.values() if 'entry' in r}
    direct=cleanup.inspect(data,image)
    known.update({r['entry']:r['rva'] for r in direct['entries'].values()})
    for r in [*operations['entries'].values(),*records.values()]:
        for s,t in r.get('reference_targets',{}).items():
            if s in known: require(t==known[s],'session/kernel/cleanup exact linked edge')
    constants=setup.construction.constant(rows,records['kernel']['reference_targets'][ROUND_TABLE],
                                         b''.join(v.to_bytes(8,'little') for v in ROUND_CONSTANTS))
    count=0
    if mutate:
        for n,body in bodies.items():
            for i in range(len(body)):
                changed=bytearray(body); changed[i]^=1
                try: check_bodies(bodies|{n:bytes(changed)})
                except ValueError: count+=1
                else: raise AssertionError('session/runtime byte mutation escaped')
    return dict(schema=1,date='2026-10-05',status='AUTHOR_SELECTED_SESSION_AND_RUNTIME_REVIEW',
                object_sha256=slot.OBJECT,image_sha256=slot.IMAGE,entries=records,
                round_constants=constants,geometry=geometry(),frames=frames,body_byte_mutations_rejected=count,
                reviewed_body_sha256={n:s[2] for n,s in BODIES.items()},
                session_rejections_precede_state_mutation=True,
                saved_session_has_exception_cleanup_handler=False,
                kernel_work_registers_cleared_before_abi_restores=True,
                public_remainder_general_u128_correctness_qualified=False,
                remaining_runtime_callees=['memcpy','memset'],native_run_added=False,
                whole_image_qualified=False,arbitrary_exception_cleanup_qualified=False,
                release_gate_changed=False,independently_verified=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('object',type=Path); parser.add_argument('image',type=Path)
    parser.add_argument('--mutate',action='store_true'); parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    result=inspect(args.object.read_bytes(),args.image.read_bytes(),args.mutate)
    sources={Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    sources.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-session-runtime.py')))
    result['source_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(sources)}
    text=json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
