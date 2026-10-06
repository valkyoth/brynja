"""Emitted private destination construction, under typed/live-frame preconditions.

Replays narrow enum combinations. The wide region admits only independent
register-to-frame stores, so per-lane width coverage composes without assuming
that sampled combinations establish arbitrary multi-variable behavior.
"""
import itertools
import windows_enclave_kmac_shapes as s
import windows_enclave_sha2_index_machine as machine
import windows_enclave_sha2_simd_digest as digest


def region(bodies,lane):
    s.require(lane in ('simd256','simd512'),'assigned descriptor route')
    narrow=lane=='simd256';offset=864 if narrow else 352
    body=bodies[s.one(bodies,r'Resident6digest$')];lines=s.lines(body)
    first=f'movq %r14, {offset}(%rbx)'
    last='movq %rax, 984(%rbx)' if narrow else 'movq %r8, 408(%rbx)'
    s.require(lines.count(first)==lines.count(last)==1,'unique descriptor construction region')
    start,end=lines.index(first),lines.index(last)
    s.require(start<=end,'ordered descriptor construction region')
    code=lines[start:end+1]
    if not narrow:
        # Establish separation before per-lane sampling: no instruction can
        # combine widths or use one lane to change another lane's destination.
        sources=('r14','rax','r9','rcx','r10','rdx','r11','r8')
        s.require(code==[f'movq %{reg}, {offset+8*i}(%rbx)' for i,reg in enumerate(sources)],
                  'independent wide descriptor fields without cross-lane computation')
    return machine.compile_region(['entry:']+code+['done:'],'entry','done')


def evaluate(bodies,lane,values,compiled=None):
    narrow=lane=='simd256';capacity=8 if narrow else 4
    s.require(len(values)==capacity and all(type(v) is int and
              (v in (0,1) if narrow else 0<=v<=64) for v in values),'typed bounded descriptor inputs')
    scratch,descriptor,stride=(3936,864,32) if narrow else (1376,352,64)
    registers={'rbx':0,'r14':scratch};memory={}
    widths=[28+4*v for v in values] if narrow else list(values)
    if narrow:
        for at,value in zip((96,104,56,80,72,128),values):memory[at]=value
        packed=sum(v<<(8*i) for i,v in enumerate(values))
        memory.update({312+i:b for i,b in enumerate(packed.to_bytes(8,'little'))})
    else:
        registers.update(dict(zip(('rax','rcx','rdx','r8'),widths)))
        registers.update(r9=scratch+64,r10=scratch+128,r11=scratch+192)
    # Distinct sentinels detect accidental mutation of inputs or scratch;
    # the only writable bytes in this phase are the destination descriptors.
    memory.update({scratch+i:i%251+1 for i in range(256)})
    memory.update({descriptor+i:0xa5 for i in range(16*capacity)})
    before=dict(memory)
    writable=set(range(descriptor,descriptor+16*capacity))
    result=machine.run(compiled or region(bodies,lane),registers,memory,writable,('no_call_allowed',0,[]))
    after=result['memory'];ranges=[]
    for i,width in enumerate(widths):
        pointer=int.from_bytes(bytes(after[descriptor+16*i+j] for j in range(8)),'little')
        actual=int.from_bytes(bytes(after[descriptor+16*i+8+j] for j in range(8)),'little')
        s.require((pointer,actual)==(scratch+stride*i,width),'original lane pointer and exact width retained')
        s.require(scratch<=pointer<=pointer+actual<=scratch+256 and actual<=stride,
                  'descriptor fits its assigned scratch slot')
        ranges.append((pointer,pointer+actual))
    s.require(all(a[1]<=b[0] for a,b in zip(ranges,ranges[1:])),'disjoint ordered destination regions')
    s.require(all(after[k]==v for k,v in before.items() if k not in writable),'only descriptors changed')
    return widths


def inspect(bodies,lane):
    # Recheck the emitted staging/width contracts that feed the bounded model.
    digest.staging(bodies,lane)
    if lane=='simd512':digest.wide_widths(bodies)
    compiled=region(bodies,lane);cases=0
    if lane=='simd256':
        inputs=itertools.product((0,1),repeat=8)
    else:
        inputs=[]
        for slot in range(4):
            for width in range(65):
                values=[1,17,33,64];values[slot]=width;inputs.append(values)
    for values in inputs:evaluate(bodies,lane,values,compiled);cases+=1
    return dict(construction_cases=cases,descriptor_bytes=128 if lane=='simd256' else 64,
        scratch_bytes=256,maximum_slot_bytes=32 if lane=='simd256' else 64,
        exact_lane_pointers_and_widths=True,ordered_disjoint_in_bounds=True,
        wide_cartesian_coverage_by_independent_field_stores=lane=='simd512',
        wide_zero_width_included_as_conservative_superset=lane=='simd512',
        original_typed_identity_and_live_frame_required=True,
        parent_wide_dispatch_table_binding_required=lane=='simd512',
        subsequent_machine_lifetimes_and_indirect_memory_effects_pending=True,
        whole_frame_qualified=False)
