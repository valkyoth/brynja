"""Remaining scalar cSHAKE start blocks and typed retained-storage transfers.

Physical padding/inactive copies are tracked, not declared initialized or wiped.
"""
import windows_enclave_sha3_batch_cshake_flow as flow
import windows_enclave_sha3_batch_fixed_start as fixed
import windows_enclave_sha3_batch_shake_start as shake

life,s,L=flow.life,flow.s,flow.L


def construct(tag):
    s.require(type(tag) is int and tag in (7,8),'two cSHAKE setup variants')
    base=3408 if tag==7 else 4528;label=45 if tag==7 else 43
    lines=L(f'.B{label}:|leaq {base+3}(%rsp), %r12|leaq {base+19}(%rsp), %r15')
    for offset,slot in ((33,264),(233,272),(401,120),(569,56)):
        lines+=L(f'leaq {base+offset}(%rsp), %rax|movq %rax, {slot}(%rsp)')
    lines+=L(f'''leaq {base+737}(%rsp), %r14|leaq {base+777}(%rsp), %rbx
        leaq {base+817}(%rsp), %rax|movq %rax, 64(%rsp)|leaq {base+1026}(%rsp), %rdi
        leaq {base+1}(%rsp), %rcx|leaq 6061(%rsp), %rdx|movl $1107, %r8d|callq memcpy
        movq 128(%rsp), %rax|movq %rax, {base+1109}(%rsp)
        movl 135(%rsp), %eax|movl %eax, {base+1116}(%rsp)
        movb %bpl, {base}(%rsp)|movb %sil, {base+1108}(%rsp)
        movb ${tag}, 35(%rsp)|leaq {base}(%rsp), %rbp''')
    return lines+(['jmp .B46'] if tag==8 else [])


def empty_snapshot(tag):
    return L(f'''.B{44 if tag==7 else 42}:|leaq 1681(%rsp), %rdx
        leaq 6061(%rsp), %rcx|movl $1107, %r8d|callq memcpy|xorl %ebp, %ebp|xorl %esi, %esi''')


def staging():
    lines=L('''.B46:|movzbl (%rbp), %eax|movb %al, 301(%rsp)
        movzbl 1(%rbp), %eax|movl %eax, 48(%rsp)|movzbl 2(%rbp), %esi
        movq (%r12), %rax|movq 6(%r12), %rcx|movq %rcx, 254(%rsp)|movq %rax, 248(%rsp)
        movzbl 17(%rbp), %eax|movl %eax, 36(%rsp)|movzbl 18(%rbp), %eax|movl %eax, 40(%rsp)
        movq (%r15), %rax|movq 6(%r15), %rcx|movq %rcx, 238(%rsp)|movq %rax, 232(%rsp)''')
    for dest,slot,width in ((5861,264,200),(3240,272,168),(3072,120,168),(2904,56,168)):
        lines+=L(f'leaq {dest}(%rsp), %rcx|movl ${width}, %r8d|movq {slot}(%rsp), %rdx|callq memcpy')
    for reg,dest in (('r14',1296),('rbx',1248)):
        lines+=L(f'''movups (%{reg}), %xmm0|movups 16(%{reg}), %xmm1
            movaps %xmm0, {dest}(%rsp)|movaps %xmm1, {dest+16}(%rsp)
            movq 32(%{reg}), %rax|movq %rax, {dest+32}(%rsp)''')
    return lines+L('''leaq 5661(%rsp), %rcx|movl $200, %r8d|movq 64(%rsp), %rdx|callq memcpy
        movl 1017(%rbp), %r15d|movzbl 1021(%rbp), %r12d|movzbl 1022(%rbp), %r14d
        movzbl 1023(%rbp), %ebx|movzbl 1024(%rbp), %eax|movl %eax, 56(%rsp)
        movzbl 1025(%rbp), %eax|movb %al, 120(%rsp)
        movups 78(%rdi), %xmm0|movups %xmm0, 2878(%rsp)
        movups 64(%rdi), %xmm0|movaps %xmm0, 2864(%rsp)
        movups (%rdi), %xmm0|movups 16(%rdi), %xmm1|movups 32(%rdi), %xmm2|movups 48(%rdi), %xmm3
        movl %esi, %edi|movaps %xmm3, 2848(%rsp)|movaps %xmm2, 2832(%rsp)
        movaps %xmm1, 2816(%rsp)|movaps %xmm0, 2800(%rsp)
        movb $6, %bpl|movl %eax, 64(%rsp)|movq 280(%rsp), %rsi''')


def check_shapes(bodies,assembly):
    name,flow_positions=flow.check_shapes(bodies,assembly);lines=life.code(bodies[name])
    _,init_positions=flow.init.check_shapes(bodies,assembly);covered=set()
    for part in [empty_snapshot(8),construct(8),empty_snapshot(7),construct(7),staging()]:
        at=lines.index(part[0]);end=next(i for i in range(at+1,len(lines)) if lines[i].endswith(':'))
        s.require(lines[at:end]==part,'complete cSHAKE snapshot/temp/staging transfer block')
        covered.update(range(at,end))
    pred=flow.init.empty.predecessors(lines)
    for at in covered:
        s.require(pred[at]<=covered|set(flow_positions)|set(init_positions),'no unreviewed constructor-transfer entry')
    for before,after in ((42,43),(44,45),(45,46),(46,47)):
        at=lines.index(f'.B{before}:');end=next(i for i in range(at+1,len(lines)) if lines[i].endswith(':'))
        s.require(lines[end]==f'.B{after}:','complete cSHAKE transfer fallthrough')
    # Instruction coverage is not a substitute for lifetime or erasure proofs.
    _,_,admission=flow.init.empty.start.check_shapes(bodies,assembly,'scalar')
    _,fixed_positions=fixed.check_shapes(bodies,assembly);_,shake_positions=shake.check_shapes(bodies,assembly)
    _,empty_paths=flow.init.empty.check_caller(bodies,assembly)
    all_positions=covered|set(flow_positions)|set(init_positions)|set(admission)|set(fixed_positions)|set(shake_positions)
    for path in empty_paths.values():all_positions.update(path['caller_instruction_positions'])
    return name,sorted(covered),sorted(all_positions)


def schedule(tag,customized):
    s.require(type(tag) is int and tag in (7,8) and type(customized) is bool,'cSHAKE transfer variant and mode')
    base=3408 if tag==7 else 4528
    steps=[('setup',),('copy','frame',1681,'frame',6061,1107)]
    if customized:
        steps += [('copy','frame',1680,'saved',9,1),('copy','frame',2788,'saved',10,1),
            ('copy','frame',2789,'frame',128,8),('copy','frame',2796,'frame',135,4)]
    else:steps += [('literal',9,0),('literal',10,0)]
    steps += [('copy','frame',6061,'frame',base+1,1107),
        ('copy','frame',128,'frame',base+1109,8),('copy','frame',135,'frame',base+1116,4),
        ('copy','saved',9,'frame',base,1),('copy','saved',10,'frame',base+1108,1),('tag',tag)]
    steps += [('copy','frame',base,'frame',301,1),('byte32',base+1,48),('copy','frame',base+2,'saved',1,1)]
    for source,dest in ((9,254),(3,248)):steps.append(('copy','frame',base+source,'frame',dest,8))
    steps += [('byte32',base+17,36),('byte32',base+18,40)]
    for source,dest in ((25,238),(19,232)):steps.append(('copy','frame',base+source,'frame',dest,8))
    for source,dest,size in ((33,5861,200),(233,3240,168),(401,3072,168),(569,2904,168),
        (737,1296,40),(777,1248,40),(817,5661,200)):
        steps.append(('copy','frame',base+source,'frame',dest,size))
    for source,dest,size in ((1017,2,4),(1021,6,1),(1022,7,1),(1023,8,1)):
        steps.append(('copy','frame',base+source,'saved',dest,size))
    steps += [('byte32',base+1024,56),('copy','frame',base+1025,'frame',120,1)]
    for source,dest,size in ((1104,2878,16),(1090,2864,16),(1026,2800,64)):
        steps.append(('copy','frame',base+source,'frame',dest,size))
    steps += [('inner_tag',6),('byte32',base+1025,64),('destroy',)]
    for source,dest,size in ((35,16,1),(64,18,1),(288,19,8),(294,25,8),(48,33,1),
        (248,35,8),(254,41,8),(36,49,1),(40,50,1),(232,51,8),(238,57,8),
        (5861,65,200),(3240,265,168),(3072,433,168),(2904,601,168),(1296,769,40),
        (1248,809,40),(5661,849,200),(56,1056,1),(120,1057,1),
        (2800,1058,64),(2864,1122,16),(2878,1136,16)):
        steps.append(('copy','frame',source,'owner',dest,size))
    for source,dest,size in ((0,17,1),(1,34,1),(2,1049,4),(6,1053,1),(7,1054,1),(8,1055,1)):
        steps.append(('copy','saved',source,'owner',dest,size))
    return steps+[('publish',)]


def replay(tag,customized,steps=None):
    s.require(type(tag) is int and tag in (7,8) and type(customized) is bool,'cSHAKE model inputs')
    original=[('setup',i) for i in range(1109)]
    if not customized:original[0]=original[-1]=0
    padding=[('padding',i) for i in range(11)]
    memory={n:[('unknown',n,i) for i in range(size)] for n,size in (('frame',7168),('saved',11),('owner',2400))}
    before=memory['owner'].copy();produced=destroyed=published=False;written=set();overlap=0
    def region(name,at,size):
        s.require(name in memory and type(at) is int and type(size) is int and size>0 and
            (32 if name=='frame' else 16 if name=='owner' else 0)<=at and
            at+size<=(1152 if name=='owner' else len(memory[name])),'bounded constructor copy region')
        return memory[name]
    expected_padding=padding if customized else [('unknown','frame',128+i) for i in range(11)]
    expected=[tag,6,original[1025]]+[('unknown','frame',i) for i in range(288,301)]+original+expected_padding
    def complete():
        s.require(produced and destroyed and written==set(range(16,1152)),'all physical state writes after typed destruction')
        s.require(memory['owner'][16:1152]==expected,'exact active, inactive and padding provenance without claiming initialization')
        s.require(memory['owner'][32:1141]==original,'all1109 active setup bytes retain exact origins')
    for step in schedule(tag,customized) if steps is None else steps:
        s.require(not published,'nothing mutates the state after publication')
        if step[0]=='setup':
            s.require(not produced,'single setup result');produced=True
            memory['frame'][1680:2800]=original+padding;continue
        if step[0]=='destroy':
            s.require(not destroyed and not written,'old state destroyed before first physical placement');destroyed=True
            memory['owner'][16:1152]=[('destroyed',i) for i in range(16,1152)];continue
        if step[0]=='publish':complete();published=True;continue
        if step[0] in ('tag','inner_tag'):
            memory['frame' if step[0]=='tag' else 'saved'][35 if step[0]=='tag' else 0]=step[1];continue
        if step[0]=='literal':
            _,at,value=step;s.require(type(value) is int and 0<=value<=255,'defined literal byte')
            region('saved',at,1)[at]=value;continue
        if step[0]=='byte32':
            _,source,end=step;dst='frame';size=4;values=[region('frame',source,1)[source],0,0,0]
        else:
            s.require(step[0]=='copy','known physical byte transfer')
            _,src,source,dst,end,size=step;values=region(src,source,size)[source:source+size]
            s.require(src!=dst or source+size<=end or end+size<=source,'nonoverlapping memcpy extents')
        target=region(dst,end,size)
        if dst=='owner':
            s.require(destroyed,'typed replacement before physical stores')
            for i,value in enumerate(values):
                if end+i in written:s.require(target[end+i]==value,'overlapping stores agree');overlap+=1
                written.add(end+i)
        target[end:end+size]=values
    complete();s.require(published,'publication follows complete replacement')
    s.require(memory['frame'][1680:2789]==original and memory['frame'][6061:7168]==original[1:1108],
              'original and snapshot remain live through replacement, not implicitly erased')
    s.require(memory['owner'][:16]==before[:16] and memory['owner'][1152:]==before[1152:],'no placement outside retained state')
    return dict(tag=tag,customized=customized,active_setup_span=[32,1141],active_setup_bytes=1109,
        padding_span=[1141,1152],inactive_span=[18,32],physical_state_bytes=1136,
        matching_overlap_bytes=overlap,active_origins_preserved=True,padding_initialized=False,
        inactive_bytes_initialized=False,publication_after_replacement=True,
        original_and_snapshot_erased=False,private_frame_erasure_qualified=False)


def inspect(bodies,assembly,construction,initialized,prefix,placement):
    name,positions,all_positions=check_shapes(bodies,assembly)
    s.require(all_positions==list(range(1361)),'complete scalar start instruction coverage')
    s.require(initialized['function']==name and initialized['cshake_initial_arithmetic_and_fields_qualified'] and
        prefix['function']==name and prefix['success_only_after_both_prefix_updates_and_advance'], 'actual constructor results before transfer')
    s.require(construction['function']==name and construction['successful_slot_and_phase_commit_after_state_copy'] and
        construction['successful_placement_destroys_previous_typed_state_first'],'publication and replacement composition')
    s.require(placement['state_destructor']['typed_payload_cleanup_composed'],'old typed state destructor replay')
    return dict(function=name,reviewed_instruction_positions=positions,scalar_start_instruction_positions=len(all_positions),
        transfers=[replay(tag,customized) for tag in (7,8) for customized in (False,True)],
        scalar_active_constructor_transfers_qualified=True,scalar_start_instruction_coverage_complete=True,
        all_constructor_paths_qualified=False,private_frame_erasure_qualified=False,shared_runtime_completion_package=8)
