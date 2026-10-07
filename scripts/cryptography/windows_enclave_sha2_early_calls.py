"""Conditional earlier wide copy/session effects, with saved-base origins.

The emitted vector loop supplies the bounded lane/iteration geometry; actual
argument slices are replayed independently. Physical allocation separation,
input/compact-index lifetimes and the authority field's preservation remain
caller obligations rather than assumptions hidden in a successful replay.
"""
import windows_enclave_sha2_slot_origins as o
import windows_enclave_sha2_transfer_effects as transfer
import windows_enclave_sha2_vector_stack as vector
import windows_enclave_sha2_early_writes as writes
s=o.s
e=transfer.e
v=transfer.val


def copy_cases(ordinal):
    for width in (2,4):
        for packed in range(width):
            for value in range(8 if ordinal==1 else 4):
                regs={'rbp':v(0,'frame')};memory={('frame',984):v(512,'workspace')}
                if ordinal==0:
                    regs.update(rbx=v(768+64*packed,'workspace'),r8=v(value))
                    src,dst,n=v(512+64*value,'workspace'),regs['rbx'],64
                elif ordinal==1:
                    regs.update(rbx=v(128*packed,'workspace'),r15=v(value),rax=v(0,'descriptor'))
                    memory[('descriptor',0)]=v(0,'input')
                    src,dst,n=v(128*value,'input'),regs['rbx'],128
                else:
                    s.require(ordinal==2,'three earlier copy roles')
                    regs.update(rbx=v(768+64*packed,'workspace'),r15=v(value))
                    src,dst,n=regs['rbx'],v(512+64*value,'workspace'),64
                yield regs,memory,dict(rcx=dst,r8=src,rdx=v(n),r9=v(n))


def replay_copy(lines,site,ordinal):
    prefix=(6,7,7)[ordinal];snapshots=[];effects=set();cases=0
    for regs,memory,expected in copy_cases(ordinal):
        snapshots.clear()
        stores=e.evaluate(lines[site['line']-prefix:site['line']+1],regs,memory,
                          site['target'],snapshots,precise=True)
        s.require(not stores and len(snapshots)==1,'one earlier copy and no hidden argument-slice store')
        actual=snapshots[0][1]
        s.require(all(actual.get(reg)==value for reg,value in expected.items()),'exact earlier copy arguments')
        for direction,regions in transfer.effects('copy',actual).items():
            for region in regions:effects.add((direction,region['object'],*region['span']))
        cases+=1
    s.require(cases==(48 if ordinal==1 else 24),'complete public earlier-copy geometry')
    return site|dict(role=('pack_states','pack_blocks','unpack_states')[ordinal],cases=cases,
                     footprints=[list(row) for row in sorted(effects)])


def inspect(bodies,assembly,early,layout,stack):
    vector.vector.inspect(bodies,'simd512');vector.authority.session(bodies,'simd512')
    name=vector.authority.role(bodies,'executor');lines=s.lines(bodies[name])
    tables=o.source.paths.jump_tables(assembly,lines);initial=o.definitions(lines,name,tables)
    slots={984:512,1000:768,952:1280}
    states=o.definitions(lines,name,tables,(*slots,1048),o.indexed_effects(lines,initial,tables))
    copy=s.one(bodies,r'secret_memory18copy_secret_region$');session=vector.authority.role(bodies,'session')
    actual=[dict(line=at,target=line[6:]) for at,line in enumerate(lines)
            if early['begin']<=at<early['end'] and line.startswith('callq ')]
    s.require(len(actual)==6 and [v['target'] for v in actual]==[
        '*920(%rbp)',copy,copy,'*920(%rbp)',session,copy],'complete earlier-call roles')
    copies=[row for row in actual if row['target']==copy]
    results=[replay_copy(lines,row,ordinal) for ordinal,row in enumerate(copies)]
    # Original packed-state and CPU-scratch bases, including loop save/reloads.
    packed=[at for at in range(early['begin'],early['end']) if lines[at]=='movq 1000(%rbp), %rbx']
    s.require(len(packed)==2,'both packed-state loop base reloads')
    for at in packed:o.require_slot(lines,states,at,1000,768,slots)
    at=next(row['line'] for row in actual if row['target']==session)
    s.require(lines[at-7:at]==['movq 1048(%rbp), %rax','movq (%rax), %rcx','movq (%rcx), %rbx',
        '.Ltmp44:','movq 1000(%rbp), %rdx','movq 1168(%rbp), %r8','movq 952(%rbp), %r9'],
        'actual vector session authority/state/block/scratch argument slice')
    o.require_origin(lines,states,at-6,'rax','executor',0,{1048:('executor',0)})
    s.require(states[at]['rcx']=={at-6},'session uses authority loaded from the original executor')
    for reg,offset in (('rdx',768),('r8',0),('r9',1280)):
        o.require_workspace(lines,states,at,reg,offset,slots)
    # Includes every declared CPU workspace byte, including intermediate state;
    # the separately reviewed session/kernel/transpose contracts justify this
    # conservative envelope. Public kernel width selects two or four lanes.
    results.append(dict(line=at,target=session,role='session',footprints=[
        ['reads','workspace',0,512],['reads','workspace',768,1024],
        ['reads','workspace',1280,4544],['writes','workspace',768,1024],
        ['writes','workspace',1280,4544],['reads','authority',0,18],
        ['writes','authority',0,8],['writes','authority',16,17]]))
    for row in actual:
        if row['target']=='*920(%rbp)':results.append(row|dict(role='cancel',footprints=[]))
    results.sort(key=lambda row:row['line'])
    s.require([row['line'] for row in results]==[row['line'] for row in actual],'all early calls assigned once')
    protected=(920,960,984,1040,1048,1168,1176);origin=layout['frame']['offset'];mapped=[]
    s.require(origin==-1136 and stack['caller_frame_relative_stack_span']==[-416,-128]
              and stack['outgoing_home_span']==[-128,-96],'same reviewed earlier vector stack and home bounds')
    for row in results:
        for direction,root,low,high in row['footprints']:
            physical=writes.placement.place(dict(object=root,span=[low,high]),layout)
            s.require(direction in ('reads','writes'),'assigned earlier-call direction')
            if direction=='writes' and physical['root']=='resident-frame':
                s.require(all(not o.source.cells.overlaps(physical['span'],(origin+slot,origin+slot+8))
                              for slot in protected),'conditional earlier-call writes exclude live saved slots')
            mapped.append(dict(line=row['line'],direction=direction,**physical))
    return dict(calls=results,mapped_effects=mapped,public_copy_cases=96,
        packed_state_base_reload_sites=packed,session_argument_origins_checked=True,
        conditional_argument_effects_and_reviewed_stacks_disjoint=True,
        parent_callback_body_and_primitive_reviews_required=True,
        original_input_compact_index_and_authority_field_lifetimes_pending=True,
        external_allocations_disjoint_from_stack_required=True,whole_frame_qualified=False)
