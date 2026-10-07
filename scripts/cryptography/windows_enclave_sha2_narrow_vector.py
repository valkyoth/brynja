"""Join six narrow vector calls to original pointers and live caller storage.

Only public lane/block geometry is replayed. The linked primitive and complete
loop reviews remain required; this is not private-frame erasure qualification.
"""
import windows_enclave_sha2_narrow_admission as a
import windows_enclave_sha2_early_calls as copies
import windows_enclave_sha2_compact_lifetimes as compact
p,n,o,s=a.p,a.n,a.o,a.s
e,v=copies.e,copies.v
PREFIX=(6,6,7)
PREREQUISITES=(*a.PREREQUISITES,
    ('simd_compact_pointer_lifetimes','current_phase_definitions_checked'),
    ('simd_primitive_contracts','prior_semantic_review_replayed'),
    ('simd_primitive_contracts','current_image_references_rebound_by_parent'),
    ('simd_narrow_admission_interfaces','original_admission_authority_and_tail_arguments_joined'),
    ('simd_narrow_setup_interfaces','setup_arguments_and_temporal_noninterference_checked'))


def cases(ordinal):
    s.require(ordinal in (0,1,2),'three narrow vector copy roles')
    for width in (4,8):
        for packed in range(width):
            for index in range(16 if ordinal==1 else 8):
                regs={'rbx':v(0,'frame')};memory={}
                if ordinal==0:
                    src,dst,size=v(7200+32*index,'frame'),v(7456+32*packed,'frame'),32
                    regs.update(r8=v(index),rdi=dst)
                elif ordinal==1:
                    src,dst,size=v(64*index,'input'),v(6688+64*packed,'frame'),64
                    regs.update(rax=v(0,'descriptor'),rdi=dst)
                    memory={('frame',136):v(index),('descriptor',0):v(0,'input')}
                else:
                    src,dst,size=v(7456+32*packed,'frame'),v(7200+32*index,'frame'),32
                    regs.update(r15=v(index));memory={('frame',72):src}
                yield regs,memory,dict(rcx=dst,r8=src,rdx=v(size),r9=v(size))


def replay(lines,call,ordinal):
    effects=set();count=0
    for regs,memory,expected in cases(ordinal):
        snapshots=[]
        stores=e.evaluate(lines[call['line']-PREFIX[ordinal]:call['line']+1],regs,memory,
                          call['target'],snapshots,precise=True)
        s.require(not stores and len(snapshots)==1 and snapshots[0][0]==call['target'],
                  'one narrow copy and no hidden argument-slice store')
        actual=snapshots[0][1]
        s.require(all(actual.get(k)==value for k,value in expected.items()),'exact narrow vector copy arguments')
        for direction,regions in copies.transfer.effects('copy',actual).items():
            for region in regions:effects.add((direction,region['object'],*region['span']))
        count+=1
    s.require(count==(192 if ordinal==1 else 96),'complete bounded narrow copy geometry')
    return call|dict(role=('pack_states','pack_blocks','unpack_states')[ordinal],cases=count,
                     footprints=[list(row) for row in sorted(effects)])


def arguments(bodies,assembly):
    name,lines,states,edges=a.prepare(bodies,assembly)
    first,last=o.unique(lines,'.B102:'),o.unique(lines,'.B142:')
    calls=[dict(line=i,target=line[6:]) for i,line in enumerate(lines)
           if first<i<last and line.startswith('callq ')]
    copy=s.one(bodies,r'secret_memory18copy_secret_region$')
    poll=s.one(bodies,r'^_RNC.*Owner6digests2_0');session=copies.vector.authority.role(bodies,'session')
    s.require([row['target'] for row in calls]==[poll,copy,copy,poll,session,copy],
              'complete ordered six narrow vector interfaces')
    results=[replay(lines,row,j) for j,row in enumerate(v for v in calls if v['target']==copy)]
    # Full loop geometry bounds R13/width. All reaching destination definitions
    # must nevertheless be the current initializer or this loop's exact stride.
    for row,offset,stride in ((results[0],7456,32),(results[1],6688,64)):
        at=row['line'];seed=o.unique(lines,f'leaq {offset}(%rbx), %rdi');step=at+1
        s.require(lines[step]==f'addq ${stride}, %rdi' and states[at]['rdi']=={seed,step},
                  'narrow packed destination retains original base and bounded stride')
        n.g.dominates(edges,0,seed,at)
    # Slot 72 previously held a counter. Only this packed-state initializer and
    # advancement may reach the unpack copy; an earlier counter is not a pointer.
    _,_,spans=n.prepare(lines,assembly,name);probe=o.unique(lines,'callq __chkstk')
    extended=o.definitions(lines,name,o.source.paths.jump_tables(assembly,lines),(*n.SLOTS,72),spans,
                           bases=n.BASES,call_clobbers={probe:{'rax'}})
    at=results[2]['line'];seed=at-14;step=at+5
    s.require(lines[seed-1:seed+1]==['leaq 7456(%rbx), %rax','movq %rax, 72(%rbx)'] and
              extended[seed]['rax']=={seed-1} and lines[step]=='addq $32, 72(%rbx)',
              'unpack cursor current base and exact advancement')
    compact.cursor(lines,extended,edges,72,seed,step,[at-1,step])
    original=a.life.authority(lines,states,edges,bodies)
    at=calls[4]['line'];load=original['authority_field_load']
    n.trace(lines,states,at,'rcx',lambda site,loc:site==load and loc=='r15',(88,))
    roots={}
    for reg,offset in (('rdx',7456),('r8',6688),('r9',8032)):
        roots[reg]=n.trace(lines,states,at,reg,lambda site,loc:site>=0 and isinstance(loc,str) and
                          lines[site]==f'leaq {offset}(%rbx), %{loc}')
    results.append(calls[4]|dict(role='session',pointer_roots=roots,footprints=[
        ['reads','frame',6688,7200],['reads','frame',7456,7712],['reads','frame',8032,10784],
        ['writes','frame',7456,7712],['writes','frame',8032,10784],
        ['reads','authority',0,18],['writes','authority',0,8],['writes','authority',16,17]]))
    # This exact linked closure ignores its data and returns false. This does
    # not generalize to caller-supplied callbacks or unknown callback bodies.
    copies.vector.control.leaf(bodies,poll,['xorl %eax, %eax','retq'])
    for row in (calls[0],calls[3]):
        at=row['line'];n.trace(lines,states,at,'rcx',lambda site,loc:site==at-1 and loc=='rcx' and
                              lines[site]=='leaq 70(%rbx), %rcx')
        n.straight(edges,at-1,at)
        results.append(row|dict(role='cancel',footprints=[]))
    return sorted(results,key=lambda row:row['line'])


def inspect(bodies,assembly,prior):
    s.require(all(prior[k][field] is True for k,field in PREREQUISITES),'fresh narrow vector prerequisites')
    copies.vector.vector.inspect(bodies,'simd256');copies.vector.authority.session(bodies,'simd256')
    calls=arguments(bodies,assembly);name,lines,_,_=a.prepare(bodies,assembly);p.bind_calls(lines,calls)
    normal=prior['simd_descriptor_normal_effects'];admission=prior['simd_narrow_admission_interfaces']
    setup=prior['simd_narrow_setup_interfaces'];lifetime=prior['simd_narrow_pointer_lifetimes']
    s.require(lifetime['input_consumers']['vector_gather_call']==calls[2]['line'] and
              lifetime['input_consumers']['argument_definitions_and_fresh_index_guards_checked'] is True,
              'same original bounded input gather')
    protected=[dict(root='resident-frame',span=span) for span in
               ([56,192],[240,272],[544,992],[2912,3040],[10784,10792])]
    layout={'frame':dict(root='resident-frame',offset=0,bounds=[0,11992]),
            'authority':dict(root='resident-page',offset=0,bounds=[0,18]),
            'input':dict(root='worker-input',offset=0,bounds=[0,1024])}
    mapped=p.exclude([effect for call in calls for effect in p.footprints(call)],protected,layout)
    stack=prior['simd_vector_callee_stack']
    s.require(stack['normal_stack_effects_disjoint'] is True and stack['normal_callee_count']==12 and
              stack['caller_frame_relative_stack_span']==[-288,0] and stack['outgoing_home_span']==[0,32],
              'same twelve-body narrow vector stack review')
    p.stack_exclude(stack['caller_frame_relative_stack_span'],protected)
    p.stack_exclude(stack['outgoing_home_span'],protected)
    s.require({(v['line'],v['target']) for v in calls}<=
              {(v['line'],v['target']) for v in setup['remaining_narrow_calls']},'six unassigned vector calls')
    assigned=normal['assigned']+admission['assigned']+setup['assigned']+calls
    remaining=p.inventory(lines,assigned+normal['terminal_calls'])
    return dict(function=name,assigned=calls,mapped_effects=mapped,protected_live_objects=protected,
        public_copy_cases=384,normal_callee_count=12,normal_stack_span=[-288,0],
        original_vector_arguments_and_normal_effects_joined=True,remaining_narrow_calls=remaining,
        assigned_narrow_returning_interfaces=len(assigned),shared_runtime_calls=setup['shared_runtime_calls'],
        shared_prerequisites=setup['shared_prerequisites'],shared_completion_package=8,
        arbitrary_unwind_qualified=False,individual_stack_erasure_qualified=False,whole_frame_qualified=False)
