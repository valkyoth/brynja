"""All-predecessor direct wipe-pointer origins for the saved Keccak executor.

This is conditional on Win64 nonvolatile preservation and the separately tracked
indirect memory/callee effects. It does not infer physical alias freedom from a
symbolic pointer name, nor qualify allocation lifetimes or exceptional cleanup.
"""
from collections import deque
import re
import windows_enclave_sha3_simd_reconcile as reconcile
import windows_enclave_sha2_slot_origins as registers
s,life=reconcile.s,reconcile.life
REGS=registers.REGS
ALIASES=registers.ALIASES
VOLATILE=registers.VOLATILE
SLOTS=(448,456,1104,1112)
UNKNOWN=frozenset({'unknown'})
ROOTS={1104:'workspace',1112:'staging'}
READ={'cmpb','cmpl','cmpq','testb','testl','testq'}
PLAIN={'nop','vzeroupper','retq','ud2'}
WRITE={'movq','movl','movb','movw','movabsq','movzbl','movslq','leaq','leal',
    'adcq','addb','addl','addq','andl','andq','bswapq','cmovaeq','cmovbl','cmovbq',
    'cmoveq','cmovnel','decq','imulq','incb','incl','incq','notb','orb','orq',
    'sbbq','setae','setb','sete','setne','shlb','shll','shrb','shrq','subl','subq',
    'vmovups','vxorps','xorl'}


def instruction(line):
    op,_,rest=line.partition(' ')
    s.require(line.endswith(':') or op in READ|PLAIN|WRITE|{'callq','divl','divq','pushq','popq'} or
        op in ('je','jne','ja','jae','jb','jbe','jmp','jmpq'),
        'closed wipe-origin instruction effects: '+op)
    return op,rest.split(', ') if rest else []


def frame_writes(code,edges):
    """Bound the sole indexed RBP store with its actual unsigned guard edge."""
    span={};indirect=[];calls=[];frames=[]
    for at,line in enumerate(code):
        op,args=instruction(line)
        if op=='callq':calls.append(at);continue
        if op in READ|PLAIN|{'divl','divq'} or op.startswith('j') or line.endswith(':'):continue
        if op in ('pushq','popq'):
            s.require(at in (*range(8),*range(577,585)),'push/pop confined to bound frame envelope')
            continue
        if not args:continue
        if args[-1] in ('%rbp','%rsp','%ebp','%esp','%bp','%sp','%bpl','%spl'):
            frames.append(at)
            s.require((at,line) in ((8,'subq $1128, %rsp'),(9,'leaq 128(%rsp), %rbp'),
                (576,'addq $1128, %rsp')),'fixed frame base throughout pointer lifetime')
        if op in ('leaq','leal') or '(' not in args[-1]:continue
        width=1 if op.startswith('set') else (32 if args[0].startswith('%ymm') else 16) if op=='vmovups' else {
            'b':1,'w':2,'l':4,'q':8}.get(op[-1])
        s.require(width is not None,'assigned memory write width')
        operand=args[-1]
        if not re.search(r'%(?:rbp|rsp)\b',operand):indirect.append(at);continue
        if ',' in operand:
            s.require(at==1045 and line=='movq %r8, 176(%rbp,%rcx,8)' and
                code[1042:1045]==['cmpq $4, %rcx','jae .B214','movq 520(%rbp), %r8'],
                'bounded four-entry compaction store')
            # Every entry into this three-instruction suffix must cross the
            # unsigned RCX < 4 edge. No hidden edge may enter after the guard.
            predecessors={v:{i for i,dests in edges.items() if v in dests} for v in (1043,1044,1045)}
            s.require(predecessors=={1043:{1042},1044:{1043},1045:{1044}} and
                edges[1043]==[code.index('.B214:'),1044], 'guard dominates actual compaction store')
            span[at]=(176,208);continue
        match=re.fullmatch(r'(-?\d*)\(%(rbp|rsp)\)',operand)
        s.require(match is not None,'assigned direct frame write')
        begin=int(match[1] or 0)-(128 if match[2]=='rsp' else 0)
        span[at]=(begin,begin+width)
    s.require(frames==[8,9,576] and 1045 in span,'complete fixed-frame/indexed-store population')
    return span,indirect,calls


def analyse(code,edges,spans):
    keys=(*REGS,*SLOTS);initial={k:UNKNOWN for k in keys}
    initial.update({k:frozenset({v}) for k,v in ROOTS.items()})
    states={0:initial};queue=deque([0])
    def value(operand,state):
        if operand.startswith('%') and operand[1:] in REGS:return state[operand[1:]]
        match=re.fullmatch(r'(\d+)\(%rbp\)',operand)
        return state.get(int(match[1]),UNKNOWN) if match else UNKNOWN
    while queue:
        at=queue.popleft();before=states[at];after=before.copy();op,args=instruction(code[at])
        if op=='callq':
            for reg in VOLATILE:after[reg]=UNKNOWN
        elif op in ('divl','divq'):
            after['rax']=after['rdx']=UNKNOWN
        elif op in WRITE|{'popq'} and args:
            reg=ALIASES.get(args[-1])
            if reg:
                incoming=value(args[0],before) if op=='movq' else UNKNOWN
                after[reg]=before[reg]|incoming if op.startswith('cmov') else incoming
            if at in spans:
                lo,hi=spans[at]
                for slot in SLOTS:
                    if lo<slot+8 and slot<hi:
                        after[slot]=value(args[0],before) if op=='movq' and (lo,hi)==(slot,slot+8) else UNKNOWN
        for dest in edges[at]:
            merged=after if dest not in states else {k:states[dest][k]|after[k] for k in keys}
            if states.get(dest)!=merged:states[dest]=merged;queue.append(dest)
    return states


def inspect(bodies,assembly,aggregate,vector):
    n=reconcile.terminal.shape.names(bodies);code=life.code(bodies[n['executor']])
    s.require(aggregate['function']==vector['function']==n['executor'] and
        aggregate['all_executor_positions_have_replayed_region_review'] and
        aggregate['normal_cfg_workspace_then_staging_wipe_order_checked'] and
        vector['selected_indices']=='ascending ready==1 and eligible==1, complete width only',
        'replayed complete executor and compaction prerequisites')
    edges,_=reconcile.graph(code,assembly)
    spans,indirect,calls=frame_writes(code,edges);states=analyse(code,edges,spans)
    s.require(len(states)==len(code)==1676,'all executor positions enter the origin analysis')
    for slot,root in ROOTS.items():
        s.require(all(state[slot]=={root} for state in states.values()),
            'incoming pointer slots survive every direct frame write')
    uses={'workspace':(73,530,1588,1598),'staging':(533,1591,1601)}
    for root,sites in uses.items():
        for at in sites:
            s.require(states[at]['rcx']=={root},'every wipe receiver has only its original incoming root')
            expected=n['workspace_wipe'] if root=='workspace' else life.ZERO
            s.require(code[at]=='callq '+expected,'actual assigned wipe callee')
    for slot,root in ((448,'workspace'),(456,'staging')):
        s.require(states[26][slot]=={root},'original pointers captured in the operation guard')
    return dict(function=n['executor'],reachable_positions=len(states),
        original_stack_argument_slots={str(k):v for k,v in ROOTS.items()},
        operation_guard_pointer_slots={'448':'workspace','456':'staging'},
        wipe_receiver_origins={root:list(sites) for root,sites in uses.items()},
        direct_frame_write_spans={str(k):list(v) for k,v in spans.items()},
        indexed_compaction_store_span=[176,208],
        non_frame_store_sites_pending=indirect,call_sites_pending_memory_effects=calls,
        all_normal_predecessor_direct_pointer_origins_checked=True,
        partial_register_and_overlapping_slot_writes_kill_origin=True,
        win64_nonvolatile_preservation_required=True,indirect_effects_and_physical_aliases_still_required=True,
        original_allocation_lifetimes_qualified=False,private_frame_and_exception_cleanup_qualified=False)
