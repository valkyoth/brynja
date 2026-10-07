"""Compose the final eighteen narrow returning-call interfaces and effects.

Existing exact descriptor construction/copy/lifetime contracts supply bounded
destinations. Shared runtime implementations and private-frame erasure remain
explicitly separate; exhausting the call inventory does not qualify them.
"""
import windows_enclave_sha2_narrow_exports as exports
import windows_enclave_sha2_simd_reuse as reuse
v,a,p,n,o,s=exports.vector,exports.a,exports.p,exports.n,exports.o,exports.s
PREREQUISITES=(*v.PREREQUISITES,
    ('simd_narrow_vector_interfaces','original_vector_arguments_and_normal_effects_joined'),
    ('simd_dynamic_clearing_descriptors','exact_pointer_length_pair_and_all_loop_indices_checked'))


def descriptor_reads(bodies,assembly,descriptors,calls):
    name,lines,_,edges=a.prepare(bodies,assembly)
    _,_,indexed=n.prepare(lines,assembly,name)
    forward,reverse=descriptors['copies'];end=descriptors['construction'][1]
    initializers={end:[('original',None)],forward['last_line']:[('returned','original')],
                  reverse['last_line']:[('original','returned')]}
    reads={forward['first_line']:['original'],reverse['first_line']:['returned']}
    for call in calls:
        role=call['role'];at=call['line']
        if role=='final_copy':
            for i in (*call['destination_loads'],*call['capacity_loads'],call['length_load'],at):
                reads[i]=['original']
        elif role=='owner_transfer':
            for i in (at-10,at-6,at):reads[i]=['returned']
        elif role=='output_drop':reads[at]=['original']
    for loop,root in zip(descriptors['loops'],('original','returned'),strict=True):
        reads[loop['read']]=[root]
    result,_=p.result.d.r.lifetime(lines,edges,n.BASES,{'original':(864,992),'returned':(2912,3040)},
                                  initializers,reads,indexed)
    return result|dict(final_transfer_reads_require_current_descriptors=True)


def cleanup(bodies,assembly,descriptors):
    name,lines,states,edges=a.prepare(bodies,assembly);names=p.storage.symbols(bodies)
    p.storage.wiping(bodies,'simd256');p.storage.output_drop(bodies,'simd256');reuse.zeroizer(bodies)
    actual=p.result.d.narrow(bodies,assembly)
    s.require(actual['loops']==descriptors['loops'] and actual['normal_drop']==descriptors['normal_drop'] and
              actual['copies']==descriptors['copies'],'same actual dynamic clearing and descriptor handoffs')
    rows=[]
    for loop,offset in zip(actual['loops'],(864,2912),strict=True):
        at=loop['call']
        rows.append(dict(line=at,target=s.ZERO,role='dynamic_clear',index_offsets=loop['index_offsets'],
            footprints=[['reads','frame',offset,offset+128],['writes','frame',3936,4192]]))
        last=loop['exit'];identity=offset+128;tail=last+3 if offset==864 else last+4
        expected=([f'.B89:','movl $8, %edx','movq %r15, %rcx','callq '+s.ZERO] if offset==864 else
                  ['.B256:',f'leaq {identity}(%rbx), %rcx','movl $8, %edx','vzeroupper','callq '+s.ZERO])
        s.require(lines[last:tail+1]==expected,'exact dynamic-error identity clearing interface')
        n.straight(edges,last,tail)
        roots=n.trace(lines,states,tail,'rcx',lambda site,loc:site>=0 and isinstance(loc,str) and
                      lines[site]==f'leaq {identity}(%rbx), %{loc}')
        size=last+1 if offset==864 else last+2
        s.require(states[tail]['rdx']=={size},'identity clear keeps its exact eight-byte width')
        rows.append(dict(line=tail,target=s.ZERO,role='identity_clear',pointer_origins=roots,
                         footprints=[['writes','frame',identity,identity+8]]))
    scratch=[i for i,line in enumerate(lines) if line=='leaq 3936(%rbx), %rcx']
    s.require(len(scratch)==2,'both final scratch clear interfaces')
    for start in scratch:
        at=start+2
        s.require(lines[start:at+1]==['leaq 3936(%rbx), %rcx','movl $256, %edx','callq '+s.ZERO],
                  'actual complete scratch output clear')
        n.straight(edges,start,at)
        rows.append(dict(line=at,target=s.ZERO,role='scratch_clear',footprints=[['writes','frame',3936,4192]]))
    # Select the final two internal wipes after the complete workspace wipe;
    # the scalar finish helper has other legitimate direct scalar-wipe calls.
    start=o.unique(lines,'.B90:')
    for key,relative,offset,size in (('scalar',7,10792,1170),('cpu',9,8032,2752)):
        at=start+relative
        s.require(lines[at]=='callq '+names[key],'assigned final scalar/cpu wipe')
        roots=n.trace(lines,states,at,'rcx',lambda site,loc:site>=0 and isinstance(loc,str) and
                      lines[site]==f'leaq {offset}(%rbx), %{loc}')
        rows.append(dict(line=at,target=names[key],role=key+'_wipe',pointer_origins=roots,
                         footprints=[['writes','frame',offset,offset+size]]))
    at=actual['normal_drop']
    rows.append(dict(line=at,target=names['output'],role='output_drop',
        footprints=[['reads','frame',864,992],['writes','frame',992,1000],['writes','frame',3936,4192]]))
    s.require(len(rows)==9,'all nine remaining cleanup interfaces')
    return rows


def inspect(bodies,assembly,prior):
    s.require(all(prior[k][field] is True for k,field in PREREQUISITES),'fresh narrow output prerequisites')
    descriptors=prior['simd_dynamic_clearing_descriptors'];geometry=descriptors['geometry']
    s.require(geometry['exact_lane_pointers_and_widths'] is True and geometry['ordered_disjoint_in_bounds'] is True
              and geometry['maximum_slot_bytes']==32 and geometry['scratch_bytes']==256,
              'original nonnull narrow destinations and exact bounded disjoint widths')
    copied=exports.exports(bodies,assembly)
    calls=copied['calls']+[exports.owner_transfer(bodies,assembly,descriptors)]+cleanup(bodies,assembly,descriptors)
    lifetimes=descriptor_reads(bodies,assembly,descriptors,calls)
    name=copied['function'];lines=s.lines(bodies[name]);p.bind_calls(lines,calls)
    previous=prior['simd_narrow_vector_interfaces'];normal=prior['simd_descriptor_normal_effects']
    s.require(len(calls)==18 and {(v['line'],v['target']) for v in calls}==
              {(v['line'],v['target']) for v in previous['remaining_narrow_calls']},
              'exact final eighteen narrow interfaces without omission or addition')
    protected=[dict(root='resident-frame',span=span) for span in
               ([56,192],[224,312],[544,992],[2912,3040])]
    layout={'frame':dict(root='resident-frame',offset=0,bounds=[0,11992]),
            'owner':dict(root='resident-page',offset=24,bounds=[0,288])}
    mapped=p.exclude([effect for call in calls for effect in p.footprints(call)],protected,layout)
    frames={};todo=[v['target'] for v in calls]
    while todo:
        target=todo.pop()
        if target in frames:continue
        proof=p.stack.inspect_body(bodies[target],target,set(bodies),{})
        frames[target]=proof;todo.extend(row[1] for row in proof['calls']+proof['tail_calls'])
    s.require(len(frames)==6,'copy pair, zeroizer, scalar/cpu wipe and output-drop normal closure')
    span=[-8+min(p.stack.depth(v['target'],frames) for v in calls),0]
    p.stack_exclude(span,protected);p.stack_exclude([0,32],protected)
    assigned=normal['assigned']+calls
    for stage in ('admission','setup','vector'):assigned+=prior['simd_narrow_'+stage+'_interfaces']['assigned']
    s.require(len(assigned)==62 and not p.inventory(lines,assigned+normal['terminal_calls']),
              'all sixty-two returning narrow call interfaces assigned exactly once')
    return dict(function=name,assigned=sorted(calls,key=lambda v:v['line']),exports=copied,mapped_effects=mapped,
        final_descriptor_read_lifetimes=lifetimes,
        protected_live_objects=protected,normal_stack_span=span,normal_callee_count=len(frames),
        assigned_narrow_returning_interfaces=len(assigned),remaining_narrow_calls=[],
        all_narrow_returning_interfaces_assigned=True,output_arguments_and_normal_effects_joined=True,
        shared_runtime_calls=previous['shared_runtime_calls'],shared_prerequisites=previous['shared_prerequisites'],
        shared_completion_package=8,shared_runtime_implementations_qualified=False,
        individual_stack_erasure_qualified=False,arbitrary_unwind_qualified=False,whole_frame_qualified=False)
