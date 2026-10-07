"""Normal-path private stack bounds for the tracked SIMD finish callees.

This checks actual stack-pointer operations, accesses and nested/tail calls.
Argument-reachable memory uses the separate call-effect contracts. Resolved
indirect targets, external allocation lifetimes and OS unwind remain explicit
parent preconditions; these are not whole-image or individual-erasure claims.
"""
import re
import windows_enclave_kmac_shapes as s

SAVED={'rbx','rbp','rsi','rdi','r12','r13','r14','r15'}
STACK_REG=re.compile(r'%(?:rsp|rbp|esp|ebp|sp|bp|spl|bpl)\b')


def height(chunks):return -sum(8 if kind=='save' else value for kind,value in chunks)


def local_span(chunks,span):
    offset=0
    for kind,value in chunks:
        start=offset-(8 if kind=='save' else value)
        if kind=='local' and start<=span[0]<span[1]<=offset:return True
        offset=start
    return False


def frame_memory(line,chunks,bp):
    """All explicit RSP/RBP operands must stay inside a live local allocation.

Register saves and the return address cannot be read/written via these operands;
only their matched POP/RET operations may consume them. No stack alias escapes.
"""
    if not STACK_REG.search(line):return []
    op,_,rest=line.partition(' ');args=rest.split(', ')
    s.require(op in ('movq','movl','movw','movb','cmpq','cmpl','cmpw','cmpb','testq','testb'),
              'assigned direct stack access instruction')
    width={'q':8,'l':4,'w':2,'b':1}[op[-1]];result=[]
    for i,arg in enumerate(args):
        if not STACK_REG.search(arg):continue
        match=re.fullmatch(r'(-?\d*)\(%(rsp|rbp)\)',arg)
        s.require(match is not None,'no escaping, indexed or partial stack-base operand')
        base=height(chunks) if match[2]=='rsp' else bp
        s.require(base is not None,'RBP initialized before local access')
        low=base+int(match[1] or 0);span=[low,low+width]
        s.require(local_span(chunks,span),'direct access inside live locals, not saves/return/home area')
        result.append(dict(kind='write' if i==len(args)-1 and op.startswith('mov') else 'read',span=span))
    return result


def inspect_body(body,name,known,indirect):
    lines=s.lines(body);labels={v[:-1]:i for i,v in enumerate(lines) if v.endswith(':')}
    s.require(name in labels and len(labels)==sum(v.endswith(':') for v in lines),'unique callee labels')
    todo=[(labels[name],(),None)];seen=set();states={};calls=set();returns=set();tails=set();accesses=set();minimum=0
    while todo:
        at,chunks,bp=todo.pop();state=(at,chunks,bp)
        if state in seen:continue
        s.require(0<=at<len(lines),'no escaped callee control flow')
        seen.add(state)
        # No branch may reinterpret an existing local/save area under a different
        # stack state. This also prevents unbounded stack-growth loops.
        prior=states.setdefault(at,(chunks,bp));s.require(prior==(chunks,bp),'consistent callee stack state at CFG joins')
        line=lines[at];op,_,operand=line.partition(' ')
        sp=height(chunks);minimum=min(minimum,sp)
        if line.endswith(':') or line.startswith('.'):
            todo.append((at+1,chunks,bp));continue
        if op=='pushq':
            s.require(operand.startswith('%') and operand[1:] in SAVED,'only matched nonvolatile register saves')
            chunks=chunks+(('save',operand[1:]),)
        elif op=='popq':
            s.require(chunks and chunks[-1]==('save',operand.removeprefix('%')),'matching last register save')
            chunks=chunks[:-1]
            if operand=='%rbp':bp=None
        elif op in ('subq','addq') and operand.endswith(', %rsp'):
            match=re.fullmatch(r'\$(\d+), %rsp',operand)
            s.require(match is not None and 0<int(match[1])<=4096,'bounded immediate local stack adjustment')
            size=int(match[1])
            if op=='subq':chunks=chunks+(('local',size),)
            else:
                s.require(chunks and chunks[-1]==('local',size),'exact local allocation release')
                chunks=chunks[:-1]
        elif op=='leaq' and operand.endswith(', %rbp'):
            match=re.fullmatch(r'(\d+)\(%rsp\), %rbp',operand)
            s.require(match is not None and bp is None and any(v==('save','rbp') for v in chunks),
                      'one frame-base setup after saving incoming RBP')
            bp=sp+int(match[1]);s.require(sp<=bp<0,'frame base inside allocated stack')
        elif op=='callq':
            target=indirect.get((name,operand)) if operand.startswith('*') else operand
            s.require(target in known,'all normal callee calls resolve to reviewed bodies')
            s.require((8+sp)%16==0 and local_span(chunks,[sp,sp+32]),'aligned call with owned 32-byte home area')
            calls.add((at,target,sp-8))
        elif op in ('retq','jmp','jmpq'):
            if op=='retq' or operand not in labels:
                s.require(not chunks and sp==0 and bp is None,'balanced stack on return or tail transfer')
                if op=='retq':s.require(not operand,'plain reviewed return');returns.add(at)
                else:
                    s.require(operand in known and not operand.startswith('*'),'reviewed direct tail target')
                    tails.add((at,operand,0))
                continue
            todo.append((labels[operand],chunks,bp));continue
        elif op.startswith('j'):
            s.require(operand in labels,'direct in-function conditional branch')
            todo.append((labels[operand],chunks,bp))
        else:
            s.require(not op.startswith(('leave','enter','push','pop','loop','call','ret','iret','lcall','lret'))
                      and op not in ('syscall','sysenter','sysexit','sysret','int','int3','ud2'),
                      'no unassigned stack/control instruction')
            for access in frame_memory(line,chunks,bp):accesses.add((at,access['kind'],*access['span']))
        minimum=min(minimum,height(chunks));todo.append((at+1,chunks,bp))
    s.require(returns or tails,'nonvacuous normal callee exit population')
    return dict(local_low=minimum,normal_returns=sorted(returns),tail_calls=[list(v) for v in sorted(tails)],
        calls=[list(v) for v in sorted(calls)],direct_stack_accesses=[list(v) for v in sorted(accesses)],
        reachable_states=len(seen),normal_stack_balanced=True,
        incoming_home_and_return_address_not_explicitly_accessed=True,stack_alias_escape_rejected=True)


def depth(name,frames,active=()):
    s.require(name not in active,'acyclic normal callee graph')
    frame=frames[name];low=frame['local_low']
    for _,target,offset in frame['calls']+frame['tail_calls']:
        low=min(low,offset,offset+depth(target,frames,active+(name,)))
    return low


def inspect(bodies,lane,frame,primitive,transfer,control):
    s.require(lane in ('simd256','simd512'),'assigned tracked-call lane')
    roots={v['target'] for group in (primitive,transfer,control) for v in group['calls']
           if not v['target'].startswith('*')}
    roots.update(control['leaf_targets'].values())
    padding=s.one(bodies,r'engine7padding$')
    indirect={(padding,'*32(%rax)'):control['leaf_targets']['callback']}
    if lane=='simd512':indirect[(s.one(bodies,r'Executor5check$'),'*8(%rdx)')]=control['leaf_targets']['compiled']
    frames={};pending=list(roots)
    while pending:
        name=pending.pop()
        if name in frames:continue
        s.require(name in bodies and not name.startswith('?'),'normal private callee, not implicit OS funclet')
        result=inspect_body(bodies[name],name,set(bodies),indirect);frames[name]=result
        pending.extend(row[1] for row in result['calls']+result['tail_calls'])
    s.require(len(frames)==(10 if lane=='simd256' else 11),'complete returning-callee closure')
    depths={name:depth(name,frames) for name in sorted(roots)}
    # Root CALL's own return-address store is included. All descendant private
    # stack accesses are below root entry; none explicitly access incoming home.
    sp=0 if lane=='simd256' else -128
    low=sp-8+min(depths.values());high=sp
    s.require(high<=frame['cell'][0] or frame['cell'][1]<=low,'entire normal callee stack extent excludes saved cell')
    return dict(functions=frames,root_relative_low=depths,caller_frame_relative_stack_span=[low,high],
        normal_callee_count=len(frames),tracked_returning_call_sites=sum(len(v['calls']) for v in (primitive,transfer,control)),
        normal_private_stack_effects_exclude_saved_pointer=True,
        resolved_indirect_targets_and_argument_effects_required=True,
        original_pointer_slot_lifetimes_pending=True,arbitrary_unwind_qualified=False,
        other_family_frames_and_whole_window_cleanup_pending=True,whole_frame_qualified=False)
