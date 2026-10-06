"""Execute saved public lane compaction instructions under private layouts."""
import itertools
import windows_enclave_kmac_shapes as s
import windows_enclave_sha2_batch_iv as iv
import windows_enclave_sha2_simd_storage as storage
import windows_enclave_sha2_index_machine as machine


def program(bodies,lane):
    s.require(lane in ('simd256','simd512'),'assigned compaction route')
    narrow=lane=='simd256'
    name=s.one(bodies,r'Resident6digest$' if narrow else r'Executor13digest_secret$')
    lines=s.lines(bodies[name]); start,end,exit_label=('.B65','.B79','.B91') if narrow else ('.B59','.B68','.B68')
    for label in (start,end,exit_label): s.require(lines.count(label+':')==1,'unique compaction boundary')
    first,last=lines.index(start+':'),lines.index(end+':')
    s.require(first<last,'ordered compaction region')
    code=lines[first:last]
    if narrow:
        # These exits are unreachable for the reviewed fixed typed inputs.
        # They must not become a successful result in the interpreter.
        code+=['.B79:','callq rejected_index','.B190:','callq rejected_overflow']
        s.sequences(bodies[name],['leaq 2912(%rbx), %rdi',
            '.B91:|movq 80(%rbx), %r8|movb %r8b, 11962(%rbx)'])
    else:
        s.sequences(bodies[name],['.B68:|movq %rdx, 968(%rbp)|movb %dl, 5750(%rdi)'])
    code+=[exit_label+':']
    return name,code,machine.compile_region(code,start,exit_label)


def seed(lane,tags):
    narrow=lane=='simd256';capacity=8 if narrow else 4
    s.require(len(tags)==capacity and all(type(t) is int and t in
        ((0,1,2) if narrow else (0,1,2,3,4,65535)) for t in tags),'typed public lane identities')
    base=6688 if narrow else 65536;inputs=544 if narrow else 32768
    _,_,_,(_,_,size)=storage.regions(lane)
    declared=5275 if narrow else 5751
    memory={base+i:0xa5 for i in range(declared)}
    for i,tag in enumerate(tags):
        for j,b in enumerate(tag.to_bytes(1 if narrow else 2,'little')):memory[inputs+40*i+32+j]=b
    writable=set(range(base,base+declared))
    registers={'rbx':0,'rdi':2912} if narrow else {'rbp':0,'rdi':base}
    if narrow:
        for offset in (56,80,104,344,2912):writable.update(range(offset,offset+8))
    else:
        for i,b in enumerate(inputs.to_bytes(8,'little')):memory[1040+i]=b
    return registers,memory,writable,base,declared,size


def evaluate(bodies,lane,tags,compiled=None):
    narrow=lane=='simd256';regs,mem,writable,base,declared,_=seed(lane,tags)
    name=storage.symbols(bodies)['workspace']
    # The complete destructor review binds every declared field, including
    # inactive lanes. Alignment padding is deliberately not modeled as wiped.
    result=machine.run(compiled or program(bodies,lane)[2],regs,mem,writable,(name,base,[(0,declared)]))
    absent=2 if narrow else 65535
    expected_indices=[i for i,tag in enumerate(tags) if tag!=absent]
    offset=4096 if narrow else 4576
    expected=bytearray(declared)
    expected[offset:offset+len(expected_indices)]=bytes(expected_indices)
    if narrow:
        for i,tag in enumerate(tags):
            if tag!=absent:expected[512+32*i:544+32*i]=bytes.fromhex(iv.IVS[tag])
        for offset,value in ((56,7),(80,len(expected_indices)),(104,10784),(344,7424),(2912,0)):
            actual=int.from_bytes(bytes(result['memory'][offset+j] for j in range(8)),'little')
            s.require(actual==value,'compaction iterator/count/pointer slots')
        count=int.from_bytes(bytes(result['memory'][80+i] for i in range(8)),'little')
    else:count=result['registers']['rdx']
    s.require(count==len(expected_indices),'exact compact active count')
    s.require(bytes(result['memory'][base+i] for i in range(declared))==expected,
              'only expected compact indices and public narrow states written')
    return dict(indices=expected_indices,count=count,steps=result['steps'])


def inspect(bodies,lane):
    storage.wiping(bodies,lane)
    name,code,compiled=program(bodies,lane)
    values=(0,1,2) if lane=='simd256' else (0,1,2,3,4,65535)
    capacity=8 if lane=='simd256' else 4
    cases=0;maximum=0
    for tags in itertools.product(values,repeat=capacity):
        result=evaluate(bodies,lane,tags,compiled)
        maximum=max(maximum,result['steps']);cases+=1
    return dict(function=name,public_identity_combinations=cases,maximum_steps=maximum,
        indices_strictly_increasing_unique_and_bounded=True,active_count_exact=True,
        public_sha224_sha256_iv_placement_checked=lane=='simd256',
        inactive_index_and_state_storage_cleared=True,
        all_other_declared_workspace_bytes_remain_cleared=True,
        interpretation_scope='public lane compaction only; fixed private layout and reviewed wipe contract',
        original_input_identity_and_frame_setup_are_caller_preconditions=True,
        subsequent_index_lifetimes_and_indirect_memory_effects_pending=True,
        arbitrary_code_or_whole_frame_qualified=False)
