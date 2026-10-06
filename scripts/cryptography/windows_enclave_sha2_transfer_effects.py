"""Conditional copy/mask argument regions in the saved SIMD finish callers.

Parent finish/variant-table and primitive reviews are required. Seeded pointer
origins and live-slot values are caller preconditions, not a physical alias or
lifetime proof. Only public geometry is replayed; no secret bytes are modeled.
"""
import windows_enclave_kmac_shapes as s
import windows_enclave_sha2_store_effects as e
import windows_enclave_sha2_simd_finish as finish


def val(value,object=None):return e.Value(object,value,value)


def span(pointer,length):
    s.require(pointer is not None and pointer.object is not None and pointer.low==pointer.high,
              'known exact transfer pointer')
    s.require(type(length) is int and 0<=length<(1<<63) and
              0<=pointer.low<=pointer.low+length<(1<<64),'bounded nonwrapping transfer extent')
    return dict(object=pointer.object,span=[pointer.low,pointer.low+length])


def effects(role,args):
    if role=='mask':
        region=span(args.get('rcx'),1)
        return dict(reads=[region],writes=[region])
    s.require(role=='copy','assigned transfer role')
    a,b=args.get('rdx'),args.get('r9')
    s.require(a is not None and a==b and a.object is None and a.low==a.high,
              'copy source/destination capacities exactly match')
    source,dest=span(args.get('r8'),a.low),span(args.get('rcx'),a.low)
    if a.low and source['object']==dest['object']:
        s.require(source['span'][1]<=dest['span'][0] or dest['span'][1]<=source['span'][0],
                  'same-object copy does not overlap')
    return dict(reads=[source] if a.low else [],writes=[dest] if a.low else [])


def cases(lane,role,ordinal):
    narrow=lane=='simd256';width=32 if narrow else 64;block=64 if narrow else 128
    obj='frame' if narrow else 'workspace';base=val(0,'frame')
    state=7200 if narrow else 512;scalar=11816 if narrow else 5604
    pad=11688 if narrow else 5476;buf=11560 if narrow else 5348;output=7712 if narrow else 1024
    initial={'rbx' if narrow else 'rbp':base}
    def copy(dst,src,n):return {'rcx':dst,'r8':src,'rdx':val(n),'r9':val(n)}
    if role=='mask':
        positions=range(block) if ordinal==0 else range(4*64)
        for pos in positions:
            pointer=val((pad if ordinal==0 else output)+pos,obj)
            reg='r15' if narrow else 'rdi' if ordinal==0 else 'rax'
            yield initial|{reg:pointer,'rdx':val(0)}, {}, {'rcx':pointer}
    elif ordinal==0:
        for index in range(8 if narrow else 4):
            regs=initial|({} if narrow else {'r14':val(index)})
            memory={('frame',72):val(index)} if narrow else {
                ('frame',984):val(state,obj),('frame',1016):val(scalar,obj)}
            yield regs,memory,copy(val(scalar,obj),val(state+width*index,obj),width)
    elif ordinal==1:
        for size in range(1025):
            regs=initial if narrow else initial|{'r13':val(size),'rax':val(0,'input')}
            memory={('frame',168):val(size),('frame',112):val(0,'input')} if narrow else {
                ('frame',928):val(pad,obj)}
            yield regs,memory,copy(val(pad,obj),val(size-size%block,'input'),size%block)
    elif ordinal==2:
        for offset in range(0,1024,block):
            regs=initial|{'rdi' if narrow else 'r15':val(offset,'input')}
            memory={} if narrow else {('frame',1024):val(buf,obj)}
            yield regs,memory,copy(val(buf,obj),val(offset,'input'),block)
    elif ordinal==3:
        for size in range(1,1025):
            pointer=val(pad+(size-1)%block,obj)
            regs=initial|({'r15':pointer} if narrow else {'r15':val(0,'input'),'r10':pointer})
            memory={('frame',120):val(size),('frame',112):val(0,'input')} if narrow else {('frame',936):val(size)}
            yield regs,memory,copy(pointer,val(size-1,'input'),1)
    else:
        s.require(ordinal==4,'five assigned copy roles')
        identities=[(tag,finish.wide_output(tag)[0]) for tag in range(4)]
        identities += [(4,finish.wide_output(4,t)[0]) for t in range(1,512) if t!=384]
        if narrow:identities=[(0,28),(1,32)]
        for index in range(8 if narrow else 4):
            for tag,size in identities:
                regs=initial|({} if narrow else {'rdx':val(size)})
                memory={('frame',128):val(tag),('frame',136):val(index*32)} if narrow else {
                    ('frame',992):val(index*64),('frame',976):val(output,obj),('frame',1016):val(scalar,obj)}
                yield regs,memory,copy(val(output+index*width,obj),val(scalar,obj),size)


def layout(lines,lane,names):
    prefix={'copy':[8,8,4,7,7],'mask':[1]} if lane=='simd256' else {
        'copy':[8,9,4,9,6],'mask':[2,2]}
    result=[]
    for role,lengths in prefix.items():
        sites=[i for i,line in enumerate(lines) if line=='callq '+names[role]]
        s.require(len(sites)==len(lengths),'complete transfer caller population')
        for ordinal,(at,count) in enumerate(zip(sites,lengths,strict=True)):
            s.require(at>=count,'bounded transfer argument slice')
            result.append(dict(role=role,ordinal=ordinal,line=at,begin=at-count))
    return sorted(result,key=lambda row:row['line'])


def replay(lines,lane,names,job,selected_cases=None):
    role=job['role'];ordinal=job['ordinal'];code=lines[job['begin']:job['line']+1]
    footprints=set();count=0
    allowed_stores=([[136,144]] if lane=='simd256' else [[952,960],[992,1000]]) if role=='copy' and ordinal==0 else []
    for regs,memory,expected in (cases(lane,role,ordinal) if selected_cases is None else selected_cases):
        snapshots=[];stores=e.evaluate(code,regs,memory,names[role],snapshots,precise=True)
        s.require([(v['object'],v['span']) for v in stores]==[('frame',v) for v in allowed_stores],
                  'only assigned public lane-offset frame stores in transfer slice')
        s.require(len(snapshots)==1 and snapshots[0][0]==names[role],'one assigned transfer call')
        actual=snapshots[0][1]
        s.require(all(actual.get(reg)==value for reg,value in expected.items()),
                  'exact emitted transfer arguments for public geometry')
        effect=effects(role,actual)
        for direction in ('reads','writes'):
            for region in effect[direction]:footprints.add((direction,region['object'],*region['span']))
        count+=1
    s.require(count>0,'nonvacuous transfer campaign')
    return job|dict(target=names[role],cases=count,footprints=[list(v) for v in sorted(footprints)])


def inspect(bodies,lane,frame,prior):
    s.require(lane in ('simd256','simd512'),'assigned transfer lane')
    names={role:s.one(bodies,pattern) for role,pattern in (
        ('copy',r'secret_memory18copy_secret_region$'),('mask',r'secret_memory22apply_secret_byte_mask$'))}
    lines=s.lines(bodies[frame['function']]);lines=lines[lines.index(frame['begin']+':'):lines.index(frame['end']+':')]
    jobs=layout(lines,lane,names);results=[replay(lines,lane,names,job) for job in jobs]
    selected=[dict(line=r['line'],target=r['target']) for r in results]
    inventory=prior['other_call_effects_pending']
    s.require(selected==[v for v in inventory if v['target'] in names.values()],
              'all remaining copy and mask sites have conditional argument effects')
    return dict(calls=results,conditional_transfer_call_count=len(results),
        remaining_call_effects=[v for v in inventory if v not in selected],
        complete_finish_variant_and_primitive_reviews_required=True,
        original_live_slot_and_physical_alias_preconditions_required=True,
        input_available_extent_and_block_loop_bounds_are_caller_preconditions=True,
        callee_stack_and_home_space_composition_pending=True,
        whole_frame_qualified=False)
