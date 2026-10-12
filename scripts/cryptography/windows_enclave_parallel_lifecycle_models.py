"""Operand-derived placement/erase checks and finite lifecycle models.

These are not CPU execution, exception proofs or original allocation admission.
Literal body contracts separately bind the inspected instruction semantics.
"""
from collections import deque

import windows_enclave_parallel_lifecycle as lifecycle

require=lifecycle.require
MASK=(1<<64)-1


def operand(code,at,prefix,width):
    prefix=bytes.fromhex(prefix)
    require(code[at:at+len(prefix)]==prefix,'exact operand instruction/register')
    start=at+len(prefix)
    require(start+width<=len(code),'complete machine operand')
    return int.from_bytes(code[start:start+width],'little')


def placement(code):
    # Actual constructor: rdi is the admitted page, rsi the disjoint result.
    # The new Owner borrows the authority at page+0, not a constructor temporary.
    owner=operand(code,0x39,'4c8d7f',1)
    input_cell=operand(code,0x170,'4889bf',4)
    owner_cell=operand(code,0x1ba,'4889bf',4)
    input_tag=operand(code,0x132,'48c787',4)
    root_tag=operand(code,0x185,'48c787',4)
    phase=operand(code,0x1ca,'c687',4)
    require(owner==32 and input_cell==owner+0x810 and owner_cell==owner+0xc50,
        'both embedded references point at the original already-placed authority')
    require(input_tag==owner+0x7b0 and root_tag==owner+0xbf0 and phase==owner+0xc5a,
        'inactive owner variants and phase are in their declared regions')
    require(code[0x1d1:0x1dc]==bytes.fromhex('48893e48897e084c897e10'),
        'published handle contains page/page/page+32, not moved self-reference')
    frame=operand(code,7,'b8',4)
    src=operand(code,0x53,'488d9c24',4)
    intermediate=operand(code,0x8e,'4c8db424',4)
    width=operand(code,0x96,'41b8',4)
    target=operand(code,0x11d,'488d4f',1)
    second_width=operand(code,0x121,'41b8',4)
    require(width==second_width==0x7af and target==owner+1,
        'complete public empty-owner payload copy')
    require(0<=src<src+width<=intermediate<intermediate+width<=frame,
        'constructor copy temporaries do not overlap and fit the allocated frame')
    require(0<=0<16<=owner<owner+0xc60<=4096 and target+width==input_tag,
        'authority and complete owner are aligned, disjoint and page bounded')
    return dict(authority=[0,16],owner=[owner,owner+0xc60],page_bytes=4096,
        authority_pointer_cells=[input_cell,owner_cell],
        constructor_frame=frame,public_copy_source=[src,src+width],
        public_copy_temporary=[intermediate,intermediate+width],
        public_copy_destination=[target,target+width],
        original_allocation_admission_proved=False,exclusive_page_is_caller_precondition=True,
        constructor_temporaries_are_empty_state_and_public_KAT=True,
        earlier_private_frame_copies_cleared_here=False)


def page_loop(code,start,sib):
    """Decode the real unrolled byte-store loop, independently of whole-body pins."""
    require(sib in (6,7),'reviewed backing register, not an arbitrary address')
    require(type(start) is int and 0<=start and start+53<=len(code),'complete bounded page loop')
    require(code[start:start+2]==b'\x31\xc0','zero initial page index')
    at=start+2;loop=at;offsets=[]
    for index in range(8):
        if index==0:
            require(code[at:at+4]==bytes((0xc6,4,sib,0)),
                'first byte store targets original page plus index')
            offsets.append(0);at+=4
        else:
            require(code[at:at+3]==bytes((0xc6,0x44,sib)) and code[at+4:at+5]==b'\0',
                'unrolled byte store uses same page/index and zero value')
            offsets.append(code[at+3]);at+=5
    step=operand(code,at,'4883c0',1);at+=4
    limit=operand(code,at,'483d',4);at+=6
    require(code[at:at+1]==b'\x75' and at+2+int.from_bytes(code[at+1:at+2],
        'little',signed=True)==loop,'inequality loop returns to first page store')
    require(offsets==list(range(8)) and step==8 and limit==4096,
        'all page bytes once, no gap, duplicate, overrun or nonterminating stride')
    visited=[base+offset for base in range(0,limit,step) for offset in offsets]
    require(visited==list(range(4096)),'exact normal-path 4096-byte erase footprint')
    return dict(bytes_cleared=len(visited),iterations=limit//step,
        lowest_offset=min(visited),highest_offset=max(visited),
        derived_from_actual_operands=True,exception_cleanup_claimed=False)


def retirement_graph(code,events=None,branches=None):
    contract=lifecycle.TABLES['avx2']['drop']
    lifecycle.framing.leaf.finish.windows(code,[(at,text) for _,at,text in contract['regions']],
        contract['branches'])
    require(len(code)==contract['size'],'retirement body extent')
    expected={0x37:'clear_owner',0x4f:'root_drop',0x67:'active_leaf_drop',
        0x83:'counter0',0x94:'counter1',0xa5:'counter2',0xb9:'leaf_drop',
        0xbe:'begin_page_clear',0xf3:'page_loop_completed'}
    events=expected if events is None else events
    branches=contract['branches'] if branches is None else branches
    require(events==expected and branches==contract['branches'],'complete retirement event/edge assignment')
    page_loop(code,0xbe,6)
    # The loop at c0..f3 is proven finite by page_loop, then summarized once.
    edges={at:(op,target) for at,op,target in branches if at<0xbe}
    nodes=sorted(set(events)|set(edges)|{0,0xfb})
    successors={at:nodes[i+1] for i,at in enumerate(nodes[:-1])}
    queue=deque([(0,frozenset())]);seen=set();returns=0
    while queue:
        at,done=queue.popleft()
        if (at,done) in seen:continue
        seen.add((at,done));event=events.get(at)
        if event=='root_drop':require('clear_owner' in done,'owner clear before root destruction')
        if event=='begin_page_clear':
            require({'clear_owner','root_drop','leaf_drop','counter0','counter1','counter2'}<=done,
                'every ordinary path destroys typed borrowers before raw page reuse')
        if event:done=done|{event}
        if at==0xfb:
            require(code[at]==0xc3 and 'page_loop_completed' in done,'no ordinary return bypasses full page clear')
            returns+=1;continue
        if at in edges:
            _,target=edges[at]
            queue.append((next(n for n in nodes if n>=target),done))
        queue.append((successors[at],done))
    require(returns==2,'both active/inactive leaf paths accounted for')
    return dict(explored_states=len(seen),return_states=returns,
        all_normal_paths_clear_page_after_typed_destructors=True,
        callee_contracts_assumed=True,exceptional_full_page_erasure=False)


def admission(lane,phase,allowed,previous,requested,health=1,kernel=4):
    """Model the specialized 1..6-entry phase scan and checked next sequence."""
    require(lane in ('scalar','avx2') and type(phase) is int and 0<=phase<=255,
        'valid lane and phase byte')
    require(1<=len(allowed)<=6 and all(type(x) is int and 0<=x<=255 for x in allowed),
        'compiled phase scan requires a real slice of one through six entries')
    require(all(type(x) is int and 0<=x<=MASK for x in (previous,requested)),
        'u64 sequence inputs')
    require(all(type(x) is int and 0<=x<=255 for x in (health,kernel)),
        'authority bytes')
    matched=False
    for index in range(6):
        if phase==allowed[index]:matched=True;break
        if len(allowed)==index+1:break
    # Mirrors inc/setne/compare/sete; the oracle uses unbounded previous+1.
    next_sequence=(previous+1)&MASK
    error=(2 if not matched else 1 if not (next_sequence and requested==next_sequence)
        else 7 if lane=='avx2' and ((health^1)|(kernel^4)) else None)
    return dict(error=error,phase=7 if error is not None else phase,
        sequence=previous if error is not None else requested,
        cleared=error is not None,authority_revoked=lane=='avx2' and error is not None,
        armed=error is None)


def cancel(lane,phase,previous,requested,health=1,kernel=4):
    result=admission(lane,phase,(1,2,3,4,5,6),previous,requested,health,kernel)
    if result['error'] is None:result.update(phase=0,cleared=True,armed=False)
    return result
