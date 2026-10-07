"""Remaining conditional SIMD finish call effects, not a whole-frame proof.

Image-bound callback targets and reviewed helper contracts are composed with
actual argument slices. Original live objects, non-aliasing and private callee
frames remain caller obligations. A fail-stop is never assigned empty effects.
"""
import re
import windows_enclave_kmac_shapes as s
import windows_enclave_sha2_store_effects as e
import windows_enclave_sha2_call_effects as c
import windows_enclave_sha2_simd_authority as authority


def val(offset,object):return e.Value(object,offset,offset)


def leaf(bodies,name,expected):
    code=[line for line in s.lines(bodies[name]) if not line.endswith(':')]
    s.require(code==expected,'complete memory-free callback instructions')


def targets(bodies,lane,tables):
    s.require(len(tables)==1,'one image-bound cancellation table')
    table=next(iter(tables.values()))
    callback=s.one(bodies,r'^_RNC.*Owner6digests2_0')
    compiled=s.one(bodies,r'Kernel8compiled$')
    s.require(table['slots'].get('32')==callback and table['metadata']==[0,0,1],
              'actual readonly slot 32 is the stateless private callback')
    leaf(bodies,callback,['xorl %eax, %eax','retq'])
    leaf(bodies,compiled,['movl %ecx, %eax','xorb $1, %al','retq'])
    constructor=s.one(bodies,r'Resident3new$')
    s.sequences(bodies[constructor],['leaq '+compiled+'(%rip), %rax|'
        'movq %rax, 8(%rdi)|movw $1, 16(%rdi)'])
    # These checks bind the emitted constructor/owner/control transfer paths.
    # They do not prove that all intervening aliases preserve the fields.
    authority.digest_callers(bodies,lane)
    return dict(callback=callback,compiled=compiled)


def footprint(role,args,lane):
    narrow=lane=='simd256'
    if role=='padding':
        work,control,report=(args.get(r) for r in ('rcx','rdx','r8'))
        block,pad,state,scratch=(4872,5000,5128,4232) if narrow else (5348,5476,5604,4708)
        width=64 if narrow else 128
        r=c.region
        return dict(reads=[r(work,pad,width),r(work,state,32 if narrow else 64),
                           r(control,0,32),r(report,16,8)],
            writes=[r(work,block,128),r(work,state,32 if narrow else 64),r(work,scratch,640),
                    r(control,16,16),r(report,16,8)])
    if role=='check':
        return dict(reads=[c.region(args.get('rcx'),0,8),c.region(args.get('rcx'),16,1),
                           dict(object='authority',span=[8,18])],
                    writes=[dict(object='authority',span=[16,17])])
    s.require(role in ('cancel','compiled'),'assigned memory-free call role')
    return dict(reads=[],writes=[])


def jobs(lines,lane,names):
    narrow=lane=='simd256';jobs=[]
    assigned={'*32(%rax)':'cancel',names['padding']:'padding'}
    assigned['*8(%rax)' if narrow else names['check']]='compiled' if narrow else 'check'
    counts={'cancel':0,'padding':0,'compiled' if narrow else 'check':0}
    prefixes={'cancel':[2,3] if narrow else [2,5],'padding':[3,3] if narrow else [2,2],
              'compiled':[3],'check':[1]}
    for at,line in enumerate(lines):
        if not line.startswith('callq ') or line[6:] not in assigned:continue
        role=assigned[line[6:]];ordinal=counts[role]
        s.require(ordinal<len(prefixes[role]),'bounded control call population')
        count=prefixes[role][ordinal];counts[role]+=1
        s.require(at>=count,'bounded control argument slice')
        jobs.append(dict(role=role,ordinal=ordinal,line=at,begin=at-count,target=line[6:]))
    s.require(counts=={'cancel':2,'padding':2,'compiled' if narrow else 'check':1},
              'complete control-call population')
    return jobs


def seed(lane,role,ordinal):
    narrow=lane=='simd256';frame=val(0,'frame');work=val(6688,'frame') if narrow else val(0,'workspace')
    control=val(240,'frame') if narrow else val(0,'control')
    report=val(2912 if narrow else 784,'frame');callback=val(0,'callback-table')
    data=val(70,'frame') if narrow else val(0,'callback-data');owner=val(0,'authority')
    regs={'rbx' if narrow else 'rbp':frame};memory={}
    if role=='padding':
        if not narrow:regs.update(rdi=work,rdx=control)
        expected=dict(rcx=work,rdx=control,r8=report)
    elif role=='cancel':
        if narrow:
            a,b=(56,104) if ordinal==0 else (240,248)
            memory={('frame',a):data,('frame',b):callback}
        elif ordinal==0:memory={('frame',920):data,('frame',1032):callback}
        else:memory={('frame',1176):control,('control',0):data,('control',8):callback}
        expected=dict(rcx=data,rax=callback)
    elif role=='compiled':
        memory={('frame',88):owner,('authority',17):e.Value(None,0,0)}
        expected=dict(rax=owner,rcx=e.Value(None,0,0))
    else:
        s.require(role=='check','assigned control seed')
        memory={('frame',1048):val(0,'executor')};expected=dict(rcx=val(0,'executor'))
    return regs,memory,expected


def replay(lines,lane,job):
    regs,memory,expected=seed(lane,job['role'],job['ordinal']);seen=[]
    stores=e.evaluate(lines[job['begin']:job['line']+1],regs,memory,job['target'],seen)
    s.require(not stores and len(seen)==1 and seen[0][0]==job['target'],
              'one control call without hidden argument-slice writes')
    args=seen[0][1]
    s.require(all(args.get(reg)==value for reg,value in expected.items()),
              'exact conditional control arguments')
    return job|footprint(job['role'],args,lane)


def failstop(bodies,lane,lines):
    if lane=='simd512':
        s.require(not any('panic_const' in line for line in lines),'no unassigned wide fail-stop')
        return []
    name=s.one(bodies,r'Resident6digest$');full=s.lines(bodies[name]);panic='.B190'
    incoming=[(i,l) for i,l in enumerate(full) if re.fullmatch(r'j\w+ '+re.escape(panic),l)]
    s.require(len(incoming)==2,'complete narrow overflow-block incoming edges')
    s.require([full[i-1] for i,_ in incoming]==['cmpq $-1, %rax','cmpb $7, %dil']
              and [l.split()[0] for _,l in incoming]==['je','ja'],
              'exact compact-count and partial-bit overflow guards')
    at=lines.index(panic+':')
    s.require(lines[at+1].startswith('callq ') and lines[at+1].endswith('panic_const_add_overflow')
              and lines[at+2]=='ud2','nonreturning guarded overflow path')
    return [dict(line=at+1,target=lines[at+1][6:],role='failstop',
        effects='not assigned: terminal path must be unreachable for admitted input',
        compact_count_precondition=[0,8],partial_bits_precondition=[0,7],
        independent_compaction_replay_required=True,input_field_lifetime_pending=True)]


def inspect(bodies,lane,frame,prior,tables):
    leaves=targets(bodies,lane,tables)
    authority.padding(bodies,lane);authority.checks(bodies,lane)
    names={'padding':authority.role(bodies,'padding')}
    if lane=='simd512':names['check']=authority.role(bodies,'executor_check')
    lines=s.lines(bodies[frame['function']]);lines=lines[lines.index(frame['begin']+':'):lines.index(frame['end']+':')]
    results=[replay(lines,lane,job) for job in jobs(lines,lane,names)]
    terminal=failstop(bodies,lane,lines)
    selected=sorted([dict(line=v['line'],target=v['target']) for v in results+terminal],key=lambda v:v['line'])
    s.require(selected==prior['remaining_call_effects'],'all remaining calls assigned exactly once')
    return dict(calls=results,failstop_paths=terminal,leaf_targets=leaves,
        conditional_control_call_count=len(results),unassigned_call_effects=[],
        returning_calls_have_conditional_effects=True,
        parent_complete_padding_primitive_and_callback_table_reviews_required=True,
        original_live_slot_and_physical_alias_preconditions_required=True,
        callee_stack_and_home_space_composition_pending=True,whole_frame_qualified=False)
