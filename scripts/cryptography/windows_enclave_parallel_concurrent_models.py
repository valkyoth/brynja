"""Bounded concurrent composition models, not a universal concurrency proof.

Atomic transitions model the linearization points in the bound x86 code. Native
thread join, OS transport, exceptions and whole-window cleanup remain package08.
"""
import windows_enclave_parallel_concurrent as review
import windows_enclave_parallel_sequential_models as sequential

require=review.require
MASK=(1<<64)-1
OPEN=0x20000
CLOSED=0x40000
LIVE=0xf0


def word(value):
    require(type(value) is int and 0<=value<=MASK,'u64 gate word')
    return value


def reserve(value,lanes):
    word(value)
    require(type(lanes) is int and 1<=lanes<=4,'bounded active workers')
    require(value&0xffffffff==0 and value>>32<0xffffffff,'idle nonwrapping generation')
    return ((value>>32)+1)<<32 | 0x10000 | ((1<<lanes)-1)<<12


def enter(value,generation,lane):
    word(value)
    require(type(generation) is int and 0<=generation<1<<32 and
        type(lane) is int and 0<=lane<=MASK,'public ticket domain')
    if not generation or lane>=4:return None
    bit=1<<lane
    if value>>32!=generation or not value&OPEN or value&bit or not value&(bit<<12):return None
    return value|bit|(bit<<4)


def leave(value,lane,success):
    word(value)
    require(type(lane) is int and 0<=lane<4 and type(success) is bool,'worker completion')
    bit=1<<lane
    require(value&bit and value&(bit<<4),'only a live unique ticket may leave')
    # A failed worker never publishes a success receipt.
    return (value | (bit<<8 if success else 0)) & ~(bit<<4)


def close(value):
    return (word(value)&~0x60000)|CLOSED


def quiescent(value):
    return word(value)&0x600f0==CLOSED


def all_succeeded(value,lanes):
    require(type(lanes) is int and 1<=lanes<=4,'active count')
    expected=(1<<lanes)-1
    return quiescent(value) and value&15==expected and (value>>8)&15==expected


def retire(value,publication_cleared,slots_cleared,native_joined):
    require(quiescent(value) and publication_cleared is True and slots_cleared is True and
        native_joined is True,'join, publication clear and reduction/slot retirement before reuse')
    return value&0xffffffff00000000


def shape(identity,block,total,custom,output):
    require(all(type(v) is int and 0<=v<=MASK for v in (identity,block,total,custom,output)),
        'public machine shape')
    require(1<=identity<=4 and 1<=block<=1024 and custom<=8192 and output<=8192,
        'request and Waves admission')
    leaves=(total+8*block-1)//(8*block)
    require(leaves<=65536,'fixed work bound')
    return dict(leaves=leaves,waves=(leaves+3)//4,cv=32 if identity in (1,3) else 64,
        bytes=(output+7)//8,last=(output-1)%8+1 if output else 0)


def leaf_range(lane,block,bits,width):
    require(all(type(v) is int and 0<=v<=MASK for v in (lane,block,bits,width)),
        'published metadata domain')
    require(lane<4 and 1<=block<=1024 and 1<=bits<=block*8,'ticket and bounded leaf shape')
    start=lane*block;end=start+(bits+7)//8
    require(end<=width<=4096,'all leaf bytes inside published private wave')
    return start,end


def ordered_reduce(rows,plan,leaves):
    require(type(leaves) is int and 0<=leaves<=4 and len(rows)==4,'four fixed slots')
    order=[]
    for i,(p,index,phase,cv_nonzero) in enumerate(rows):
        if i<leaves:
            require(p==plan and index==i and phase==1,'complete same-plan indexed CV')
            order.append(i)
        else:require(phase==0 and not cv_nonzero,'unused slots remain pending and zero')
    return order


def exact_finish(consumed,total,merged,expected,phase):
    require(all(type(v) is int and 0<=v<=MASK for v in (consumed,total,merged,expected)),
        'completion counters')
    return phase==1 and consumed==total and merged==expected


def right_encode(value):
    require(type(value) is int and 0<=value<=MASK,'actual concurrent encoder u64 domain')
    left=sequential.left_encode(value)
    return left[1:]+left[:1]


def transfer_chunks(length):
    require(type(length) is int and 0<=length<1<<61,'reviewed widened copy ABI')
    # Closed-form induction: the loop consumes eight bytes while remaining>=8,
    # then exactly remaining%8 scalar bytes; neither counter can wrap.
    words,tail=divmod(length,8)
    require(words*8+tail==length and words*8<=length and tail<8,'complete bounded transfer')
    return words,tail


def compose(functions,n,ir):
    c=review.c;anchor=sequential.anchor;operand=sequential.lifecycle.operand
    bodies={r:functions[name][0] for r,name in n.items()}
    root=functions['PrivateWaveRoot'][0];leaf=bodies['leaf_entry']
    dispatch=functions[review.retirement.CLOSURE][0]
    finish=functions[review.terminal.BODIES['finish'][0]][0]
    # Actual allocation/copy operands, not just struct sizes read from source.
    require(operand(root,0xc,'b8',4)==0x2b58,'original fixed root frame')
    for at,value in ((0xb7,'488d8c2458120000bad0140000'),
            (0x40c,'48c744247002000000884c2478c644247904'),
            (0x473,'488d542470'),(0x494,'488d8c24000a0000488d9424c001000041b840080000'),
            (0x7a4,'c68424b100000001'),(0x800,'488d842480000000'),
            (0x854,'4883f804'),(0x872,'4c8d8424800000004c8d8c24c0010000'),
            (0x8c6,'488d8c24c0010000488d9424000e00004c8d8424800000004531c9')):
        anchor(root,at,value)
    live=sequential.ranges([(0x70,0x80),(0x80,0xb8),(0x1c0,0x320),
        (0xa00,0x1240),(0x1258,0x2728)],0x2b58)
    owner=sequential.ranges([(0,0x400),(0x400,0x7e0),(0x7e0,0x840)],0x840)
    root_payload=sequential.ranges([(0x1298,0x1318),(0x1318,0x1718),
        (0x1718,0x2718)],0x2b58)
    # The returned owner temporary becomes slots only AFTER the owner is moved
    # to a disjoint live allocation. Public staging reuses it only AFTER joins.
    require(0x1c0+0x840==0xa00 and 0xa00+0x840<0x1258,'construction move is nonoverlapping')
    anchor(root,0xcdb,'4c8db424c0010000488d94242827000041b800040000')
    for at,value in ((0x62,'81e100000200'),(0x8c,'f0480fb10d0000000075b9'),
            (0x97,'488d0500000000488b3cf0'),
            (0xb0,'48c744242002000000884c2428c644242904'),
            (0x185,'488d5424204c8d4424504889f9'),
            (0x118,'b81000000089f148d3e048f7d0f048210500000000'),
            (0x1a2,'b80001000089f148d3e0f048090500000000')):
        anchor(leaf,at,value)
    leaf_regions=sequential.ranges([(0x20,0x30),(0x30,0x50),(0x50,0x70)],0x78)
    # Publisher admits the original Plan/slots/private input before release;
    # callee references bind these instructions to the selected native helper.
    for at,value in ((0xee,'ba38000000'),(0x108,'486bd658'),
            (0x11e,'4c89f14c89fa'),(0x1a6,'f04c0fb129'),
            (0x1c0,'488d4c2420e800000000'),
            (0x521,'4989d84c39d14c0f42d14c8d5b58'),
            (0x575,'498d90b0000000'),(0x5bd,'4881c308010000')):anchor(dispatch,at,value)
    # The emitted unwind map points to dtor55; it must use the parent slot
    # written before the possibly-unwinding finish_xof/squeeze calls.
    anchor(finish,0x253,'4c8965f0')
    anchor(bodies['finish_handler'],0x13,'488d6a70488d4dd0e800000000488b4df031d2e800000000')
    anchor(bodies['input_guard'],0x40,'48c7060000000048c786c014000000000000c686c814000002')
    # All optimized private ranges are caller obligations, not runtime tests.
    for role,token in (('bits','i8 noundef range(i8 0, 9) %3'),
            ('state_update','i64 noundef range(i64 0, 256) %2'),
            ('right_encode','i128 noundef range(i128 0, 18446744073709551616) %1')):
        require(token in c.reuse.abi(ir,n[role]),'actual specialized ABI: '+role)
    return dict(root_local_frame_bytes=0x2b58,simultaneous_root_regions=live,
        waves_owner_regions=owner,input_payload_regions=root_payload,leaf_authority_descriptor_regions=leaf_regions,
        slot_bytes=88,slots=4,slot_cv_bytes=64,root_authority_offset=0x70,leaf_authority_offset=0x20,
        plan_offset=0x80,root_owner_offset=0xa00,input_frame_offset=0x1258,
        scratch_copy_limit=4096,update_call_limits=dict(cv=64,framing=17),
        squeeze_call_limits=dict(cv=64,root=1024),
        normal_order=['admit/copy private wave','publish release','unique worker acquire',
            'local authority and Slot run','success receipt then release LIVE',
            'close/acquire quiescence','clear publication','reduce indexed CVs',
            'drop all slots','retire Rust generation','retire native generation','next input copy'],
        errors='dispatch joins before returning; failed receipts reject reduction; armed guards clear typed state',
        partial_input='copy failure clears full fixed input regions; already copied host data is not a full-message snapshot',
        output='exact completion then typed declassification; OS-copy failure is not transactional',
        reuse='no slot/input/frame reuse while a Rust ticket or native worker remains live',
        earlier_moved_values_erased_here=False,exception_runtime_qualified=False,
        full_private_window_qualification_package=8)
