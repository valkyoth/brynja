"""Finite boundary models and actual operand-derived caller composition.

Models supplement the bound machine-code review; they are not execution of the
Windows image. Shared stack/OS/runtime prerequisites remain explicit.
"""
import windows_enclave_parallel_sequential as review
import windows_enclave_parallel_lifecycle_models as lifecycle

require=review.require
MASK=(1<<64)-1
LIMIT=(1<<128)-1


def left_encode(value):
    require(type(value) is int and 0<=value<=LIMIT,'public u128 length')
    raw=value.to_bytes(16,'big');first=0
    while first<15 and raw[first]==0:first+=1
    payload=raw[first:]
    return bytes([16-first])+payload


def bit_admission(length,last,tail=0):
    require(type(length) is int and 0<=length<=MASK and type(last) is int and
        0<=last<=255 and type(tail) is int and 0<=tail<=255,'machine bit-string domains')
    if not ((length==0 and last==0) or (length>0 and 1<=last<=8)):
        return dict(error='shape',tail_read=False)
    if not length:return dict(error=None,bits=0,tail_read=False)
    if length>1<<61 or (length-1)*8+last>MASK:
        return dict(error='overflow',tail_read=False)
    if last<8 and tail&((255<<last)&255):return dict(error='tail',tail_read=True)
    return dict(error=None,bits=(length-1)*8+last,tail_read=last<8)


def add128(left,right):
    require(all(type(v) is int and 0<=v<=LIMIT for v in (left,right)),'u128 inputs')
    lo=(left&MASK)+(right&MASK)
    hi=(left>>64)+(right>>64)+(lo>>64)
    require(hi<=MASK,'checked high-word carry')
    return (hi<<64)|(lo&MASK)


def prefix_extent(custom,rate):
    require(type(custom) is int and 0<=custom<=LIMIT and rate in (136,168),
        'declared customization and selected rate')
    fixed=8*(len(left_encode(rate))+len(left_encode(96))+len(left_encode(custom)))+96
    bits=add128(custom,fixed)
    used=add128(bits>>3,int(bits%8!=0))
    return add128(used,(-used)%rate)


def modulo136(value):
    require(type(value) is int and 0<=value<=LIMIT,'u128 modulo input')
    # Actual scalar strength256 lowering: reduce the two words of value/8
    # modulo17 using 2**64 == 1 (mod17), then restore the low three bits.
    lo,hi=(value>>3)&MASK,value>>67
    folded=lo+hi
    folded=(folded&MASK)+(folded>>64)
    quotient=(folded*0xf0f0f0f0f0f0f0f1)>>68
    rest=folded-quotient*17
    require(0<=rest<17,'magic divide has a canonical remainder')
    return rest*8+(value&7)


def prefix_complete(remaining,phase,emitted,pending,expected,rate):
    require(all(type(v) is int and 0<=v<=LIMIT for v in (remaining,emitted,expected)) and
        type(pending) is int and 0<=pending<8 and phase in (0,1,2) and rate in (136,168),
        'prefix domains')
    if remaining or phase!=1:return dict(phase=phase,emitted=emitted,pending=pending,complete=False)
    count=add128(emitted,int(pending!=0))
    count=add128(count,(-count)%rate)
    require(count==expected,'no premature or mismatched prefix completion')
    return dict(phase=2,emitted=count,pending=0,complete=True)


def charge_update(budget,total,length):
    require(type(length) is int and 0<=length<=1024,'receiver-established private length bound')
    require(type(budget) is int and 0<=budget<=MASK and budget>=length,'checked byte budget')
    return budget-length,add128(total,length*8)


def xor_domain(source_offset,count,destination_offset):
    require(all(type(v) is int and 0<=v<=255 for v in (source_offset,count,destination_offset)),
        'byte arguments')
    return 1<=count<=8 and source_offset<=8-count and destination_offset<=8-count


def ranges(regions,limit):
    require(all(type(a) is int and type(b) is int and 0<=a<b<=limit for a,b in regions),
        'each live allocation fits its parent')
    require(all(a[1]<=b[0] or b[1]<=a[0] for i,a in enumerate(regions) for b in regions[i+1:]),
        'simultaneously live source/destination allocations are disjoint')
    return [list(r) for r in regions]


def anchor(code,at,hexadecimal):
    value=bytes.fromhex(hexadecimal)
    require(code[at:at+len(value)]==value,'original caller/authority/guard operand')


def compose(bodies,lane):
    """Join typed relative geometry with original placed storage/guard operands.

    The predecessor entry, lifecycle, leaf and framing inspectors are replayed
    by the orchestrator. This function checks the remaining connecting operands
    and independently bounded copies; it does not infer caller safety merely
    from an exhaustive body inventory.
    """
    op=lifecycle.operand
    geometry=review.framing.geometry(lane)
    owner_size=0xd60 if lane=='scalar' else 0xc60
    regions=ranges([geometry[r] for r in ('root','input','output','metadata')],owner_size)
    custom=bodies['custom'];squeeze=bodies['squeeze'];begin=bodies['begin'];update=bodies['update']
    custom_at,squeeze_at=(0x48,0x4b) if lane=='scalar' else (0x53,0x58)
    require(op(custom,custom_at,'483d',4)==1024 and
        op(squeeze,squeeze_at,'4881ff',4)==1024,'both remaining explicit 1024-byte bounds')
    if lane=='scalar':
        anchor(update,0x5a,'488d14f5000000004d8b8608090000490396000900004983d000')
        anchor(update,0x76,'498d8e70040000498996000900004d8986080900004c89f24989f84989f1')
        anchor(squeeze,0x93,'488d9120090000')
        anchor(squeeze,0xd4,'488d9120090000')
        anchor(squeeze,0x110,'4889bb400d00004088b3510d00008883500d0000')
        src=op(begin,0x102,'488d5424',1);tmp=op(begin,0x107,'4c8dbc24',4)
        size=op(begin,0x10f,'41b8',4);frame=op(begin,0xc,'4881ec',4)
        require((src,tmp,size,frame)==(0x32,0x4aa,0x46e,0x918),'exact root transfer temporaries')
        copies=ranges([(src,src+size),(tmp,tmp+size)],frame)
        anchor(begin,0x125,'44882344887301488d4b02')
        require(size+2==geometry['root'][1],'copied root payload stays before Input')
        stage=bodies['state_squeeze']
        anchor(stage,0x5c,'488d7c245841b800040000')
        anchor(stage,0x503,'488d4c2458ba0004000089c3e800000000')
        # No new secret written on the shape-rejection branch before stage is
        # created. Every later ordinary return goes through the full-stage wipe.
        stage_region=ranges([(0x58,0x458)],0x458)
        authority=[];guard_slots={}
    else:
        anchor(update,0x67,'4c8d04f5000000004d8b8e080800004d0386000800004983d100')
        anchor(update,0x86,'498d8e00040000498d96400800004d8986000800004c8975e84d898e08080000')
        anchor(squeeze,0xbc,'498d9f4008000044887424204889d94c897df04c89fa')
        anchor(squeeze,0x114,'4989bf400c00004188b7580c00004188875a0c0000')
        src=op(begin,0x1a2,'488d93',4);tmp=op(begin,0x1a9,'488d8b',4)
        size=op(begin,0x1b0,'41b8',4);frame=op(begin,0xc,'4881ec',4)
        require((src,tmp,size,frame)==(0x81,0x479,0x3af,0x838),'AVX2 transfer frames')
        copies=ranges([(src,src+size),(tmp,tmp+size)],frame)
        anchor(begin,0x113,'4c897338498b96500c0000')
        anchor(begin,0x1f7,'498d8d41080000488d9379040000')
        require(0x841+size==0xbf0<0xc20,'payload ends at root discriminant, before metadata')
        # The source of the embedded authority is original RDX, saved separately
        # from scratch; subsequent payload moves preserve that pointer value.
        initial=bodies['initial']
        anchor(initial,0x45,'48899424800300004889b42488030000')
        anchor(initial,0x251,'4c8ba42480030000')
        anchor(initial,0x2b7,'4c89a424e0050000')
        stage_region=[]
        authority=[0x810,0xc50]
        guard_slots={'begin':(0x37,0x38),'custom':(-9,-24),'update':(-9,-24),'squeeze':(-1,-16)}
        for role,at,code in [('begin',0xf3,'44887b37'),('begin',0x113,'4c897338'),
                ('custom',0xbd,'8855f74c8975e8'),('update',0x83,'8855f7'),
                ('update',0x9b,'4c8975e8'),('squeeze',0xb8,'448845ff'),
                ('squeeze',0xcb,'4c897df0')]:anchor(bodies[role],at,code)
        for role,at,code in [('begin_handler',0x23,'f6433701752f488b4338'),
                ('custom_handler',0x13,'f645f701752f488b45e8'),
                ('update_handler',0x13,'f645f701752f488b45e8'),
                ('squeeze_handler',0x15,'f645ff01752f488b45f0'),
                ('setup_handler',0x23,'488d8b400a0000')]:anchor(bodies[role],at,code)
    return dict(owner_bytes=owner_size,typed_regions=regions,begin_copy_regions=copies,
        separate_scalar_squeeze_frame=stage_region,
        private_length_limit=1024,leaf_cv_limit=64,framing_suffix_limit=17,
        update_length_bound_from_receiver=True,original_authority_cells=authority,
        parent_guard_slots={k:list(v) for k,v in guard_slots.items()},
        original_backing_lifetime='placed once before publication, typed borrowers retired before normal page clear',
        source_lifetime='fixed payload buffer lives through synchronous absorption; never stored as borrowed payload',
        output_lifetime='distinct resident output lives until export/rehash/cancel, full1024 bytes cleared',
        failure='all post-admission owner errors retain armed guard; typed clear/quarantine precedes return',
        panic='terminating bridge is not a successful returning cleanup path',
        earlier_moved_copies_erased_here=False,whole_window_qualification_package=8)
