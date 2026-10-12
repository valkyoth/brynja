"""Finite root-return graph and arithmetic models; not native execution.

Models are paired with independently pinned actual instructions in the framing
review. Shared callee behavior and runtime unwinding are conditional contracts.
"""
from collections import deque

import windows_enclave_parallel_framing as framing

require=framing.require
MASK=(1<<64)-1


def output_bits(width,last):
    require(type(width) is int and 0<=width<=MASK and type(last) is int and
        0<=last<=255,'machine width and byte domains')
    if width==0:return 0
    # Actual lea/shr/add/adc widens BEFORE multiplying by eight.
    low=(((width-1)<<3)&MASK)+last
    high=((width-1)>>61)+(low>>64)
    return (high<<64)|(low&MASK)


def admitted_output(identity,width,last):
    require(type(identity) is int and 1<=identity<=4,'previously admitted identity')
    require(type(width) is int and 0<=width<=1024 and type(last) is int and
        ((width==0 and last==0) or (width>0 and 1<=last<=8)),'caller output shape')
    require(identity<=2 or width==0,'XOF finish and rehash require zero width')
    return output_bits(width,last)


def left_block(block):
    require(type(block) is int and 0<block<=MASK,'positive u64 B')
    width=1
    if block>=256:
        value=block;counter=0
        while True:
            before=value;value>>=8;previous=counter;counter+=1
            if before<=65535:break
        width=previous+2
    require(1<=width<=8,'u64 left encoding width')
    out=bytearray(17);out[0]=width
    index=0;destination=2;shift=(width-1)*8
    while True:
        require(0<=shift<128 and destination!=18,'first left-encoding store/shift')
        out[destination-1]=(block>>shift)&255
        if index|1==width:break
        second=(((index^((1<<61)-2))+width)<<3)&MASK
        require(0<=second<128 and destination<17,'second left-encoding store/shift')
        out[destination]=(block>>second)&255
        index+=2;destination+=2;shift-=16
        if index==width:break
    return bytes(out[:width+1])


def relative_regions(lane):
    g=framing.geometry(lane)
    regions=[g[n] for n in ('root','input','output','metadata')]
    ordered=sorted(regions)
    require(ordered[0][0]==0 and all(a<b for a,b in ordered) and
        all(a[1]==b[0] for a,b in zip(ordered,ordered[1:])),
        'relative root, input, output, metadata are disjoint and adjacent')
    require(g['output'][1]-g['output'][0]==1024,'full retained output capacity')
    fields=[(g['width'],8),(g['last'],1),(g['next_width'],8),(g['next_last'],1)]
    require(all(g['metadata'][0]<=at<at+size<=g['metadata'][1] for at,size in fields),
        'shape fields stay outside mutable crypto/output regions')
    require(all(a+sa<=b or b+sb<=a for i,(a,sa) in enumerate(fields)
        for b,sb in fields[i+1:]),'current and next shape fields do not overlap')
    return g


def scalar_setup_copy_geometry():
    # Addresses from the actual finish_custom operand windows. The 0x3dc-byte
    # payload moves owner+0x84 -> branch frame -> common frame -> owner+0x32.
    # Header/tail fields are scalar/vector copies in the same pinned windows.
    # This does NOT establish destruction of earlier frame copies.
    branches={'narrow':(0x4c8,0x8a4),'wide':(0x8a4,0xc80)}
    common=(0xe8,0x4c4);source=(0x84,0x460);destination=(0x32,0x40e)
    require(all(end-start==0x3dc for start,end in [*branches.values(),common,source,destination]),
        'all scalar setup payload copies preserve 988 bytes')
    require(common[1]<=min(a for a,_ in branches.values()) and
        all(0<=a<b<=0xc80 for a,b in [*branches.values(),common]),
        'branch and common temporaries are disjoint inside allocated frame')
    require(0x54<=source[0]<source[1]<=0x54+0x410 and destination[1]<0x470,
        'original setup erased after copy, completed payload inside root region')
    return dict(payload_bytes=0x3dc,branch_frames={k:list(v) for k,v in branches.items()},
        common_frame=list(common),source_in_owner=list(source),destination_in_owner=list(destination),
        original_setup_clear=[0x54,0x54+0x410],allocated_frame_bytes=0xc80,
        original_setup_clear_after_first_copy=True,old_variant_drop_before_destination_write=True,
        earlier_frame_copies_cleared_here=False,full_window_retirement_package=8,
        assumes_live_disjoint_owner_and_frame=True)


def root_return_graph(code,lane,branches=None,events=None):
    """Explore every conditional branch, including infeasible ones, to a return.

This checks order/cleanup, not instruction execution or exception semantics.
Loops are finite over (instruction landmark, event-set). Bytes and branch
destinations must first match the actual-body contract. Calls return according
to their separately reviewed contract; the panic call is nonreturning.
"""
    contract=framing.TABLES[lane]['finish_root']
    framing.leaf.finish.windows(code,[(at,text) for _,at,text in contract['regions']],
        contract['branches'])
    require(len(code)==contract['size'],'root graph extent')
    if lane=='scalar':
        start,ret,panic=0x83,0x1fe,0x2e5
        expected={0x1c2:'update',0x20c:'update',0x244:'finish',0x254:'finish',
            0x270:'budget',0x2a4:'squeeze',0x2b6:'drop_root',0x2be:'publish_fixed',
            0x2cd:'publish_phase',0x1da:'clear17',0x1e7:'clear1',0x2d8:'drop_suffix'}
    else:
        start,ret,panic=0x8d,0x1f5,0x2c3
        expected={0x1b5:'update',0x21b:'finish',0x231:'budget',0x270:'squeeze',
            0x292:'disarm_root',0x29d:'publish_fixed',0x2ac:'publish_phase',
            0x1cf:'clear17',0x1dd:'clear1',0x2b6:'drop_suffix'}
    branches=contract['branches'] if branches is None else branches
    events=expected if events is None else events
    require(branches==contract['branches'] and events==expected,'complete root graph assignment')
    require(code[ret]==0xc3 and code[panic]==0xe8,'actual terminal instructions')
    edges={at:(op,target) for at,op,target in branches if at>=start}
    nodes=sorted(set(edges)|set(events)|{start,ret,panic})
    successors={at:nodes[i+1] for i,at in enumerate(nodes[:-1])}
    pending=deque([(start,frozenset())]);seen=set();returns=0;panic_paths=0
    while pending:
        at,done=pending.popleft()
        if (at,done) in seen:continue
        seen.add((at,done))
        if at==panic:panic_paths+=1;continue
        event=events.get(at)
        if event=='finish':require('update' in done,'suffix absorption precedes finalization')
        if event=='budget':require('finish' in done,'finalization precedes budget clear')
        if event=='squeeze':require('budget' in done,'terminal squeeze follows finalization')
        if event=='publish_fixed':
            require({'squeeze','drop_root' if lane=='scalar' else 'disarm_root'}<=done,
                'fixed metadata published only after output and root retirement')
        if event=='publish_phase':require('budget' in done,'phase commit follows finalization')
        if event:done=done|{event}
        if at==ret:
            require({'clear17','clear1'}<=done or 'drop_suffix' in done,
                'every ordinary return clears all 17+1 suffix bytes')
            returns+=1;continue
        if at in edges:
            op,target=edges[at]
            # A destination may start between event landmarks. Jump to the
            # first subsequent event/branch, never skip one at the destination.
            choices=[target]
            if op not in ('eb','e9'):choices.append(successors[at])
            for target in choices:
                require(start<=target<=panic,'root graph stays inside reviewed suffix lifetime')
                nxt=next((n for n in nodes if n>=target),None)
                require(nxt is not None,'root branch reaches a reviewed landmark')
                pending.append((nxt,done))
        else:pending.append((successors[at],done))
    require(returns>0 and panic_paths>0,'nonvacuous returning and panic graph population')
    return dict(explored_states=len(seen),return_states=returns,panic_states=panic_paths,
        all_condition_edges_explored=True,panic_cleanup_claimed=False,
        calls_assume_separately_reviewed_contracts=True)
