"""Saved AVX2 cSHAKE prefix replacement and full retained-state provenance.

Physical padding is tracked without initialization or erasure claims.
"""
import windows_enclave_sha3_batch_avx2_cshake as prefix

life,s,L=prefix.life,prefix.s,prefix.L


def parts():
    return [L('''.B27:|movl 305(%rsp), %eax|movl %eax, 64(%rsp)
        movzwl 309(%rsp), %eax|movw %ax, 78(%rsp)|movzbl 311(%rsp), %eax|movb %al, 63(%rsp)
        movq 312(%rsp), %rax|movq %rax, 176(%rsp)|movq 320(%rsp), %r9|movq 328(%rsp), %r10
        movzbl 336(%rsp), %r11d|movq 337(%rsp), %r14|movl 345(%rsp), %r12d
        movzwl 349(%rsp), %r13d|movzbl 351(%rsp), %eax|movq 352(%rsp), %rcx
        movq 360(%rsp), %rdx|movzbl 368(%rsp), %r8d|vmovdqu 346(%rsp), %ymm0
        vmovdqu %ymm0, 137(%rsp)|movq %r14, 128(%rsp)|movq 4880(%rbp), %r14
        movl %r12d, 136(%rsp)|movw %r13w, 140(%rsp)|movb %al, 142(%rsp)
        movq %rcx, 143(%rsp)|movq %rdx, 151(%rsp)|movb %r8b, 159(%rsp)
        movl 64(%rsp), %eax|movl %eax, 96(%rsp)|movzwl 78(%rsp), %eax|movw %ax, 100(%rsp)
        movzbl 63(%rsp), %eax|movb %al, 102(%rsp)|movq 176(%rsp), %rax|movq %rax, 103(%rsp)
        movq %r9, 111(%rsp)|movq %r10, 119(%rsp)|movb %r11b, 127(%rsp)
        movb $2, %r12b|xorl %r13d, %r13d'''),
        L(f'''.B28:|movl 137(%rsp), %eax|movl %eax, 265(%rsp)
        movzbl 141(%rsp), %eax|movb %al, 269(%rsp)|movzbl 142(%rsp), %eax|movb %al, 270(%rsp)
        movq 143(%rsp), %rax|movq %rax, 271(%rsp)|movq 151(%rsp), %rax|movq %rax, 279(%rsp)
        movzbl 159(%rsp), %eax|movb %al, 287(%rsp)|movq 160(%rsp), %rax|movq %rax, 288(%rsp)
        movzbl 168(%rsp), %eax|movb %al, 296(%rsp)|vmovaps 96(%rsp), %ymm0|vmovaps 128(%rsp), %ymm1
        vmovaps %ymm1, 256(%rsp)|vmovaps %ymm0, 224(%rsp)|movl 88(%rsp), %eax|movl %eax, 80(%rsp)
        movzbl 92(%rsp), %eax|movb %al, 84(%rsp)|cmpb $-1, 1642(%rsp)|je .B30
        leaq 1640(%rsp), %rcx|movl $1, %edx|vzeroupper|callq {life.ZERO}'''),
        L('''.B30:|movb %r13b, 1568(%rsp)|vmovaps 224(%rsp), %ymm0|vmovaps 256(%rsp), %ymm1
        vmovups %ymm0, 1569(%rsp)|vmovups %ymm1, 1601(%rsp)|vmovups 265(%rsp), %ymm0
        vmovups %ymm0, 1610(%rsp)|movb %r12b, 1642(%rsp)|movl 80(%rsp), %eax|movl %eax, 1643(%rsp)
        movzbl 84(%rsp), %eax|movb %al, 1647(%rsp)|movb $0, 1666(%rsp)
        orq 4864(%rbp), %rbx|je .B31|movb $4, 1664(%rsp)|leaq 1024(%rsi), %r13|jmp .B49'''),
        L('''.B31:|orq %r14, 184(%rsp)|movl $31, %eax|movl $4, %ecx|cmovel %eax, %ecx
        movb %cl, 1664(%rsp)|leaq 1024(%rsi), %r13|je .B32'''),
        L('.B49:|movb $3, %al'),
        L('''.B50:|movb %al, 1665(%rsp)|movzbl 704(%rsp), %r12d|leaq 2976(%rsp), %rcx
        movl $943, %r8d|leaq 705(%rsp), %rdx|vzeroupper|callq memcpy
        movq 1648(%rsp), %r14|leaq 1656(%rsp), %rax|vmovdqu (%rax), %ymm0|vmovdqa %ymm0, 640(%rsp)
        movq 32(%rax), %rax|movq %rax, 672(%rsp)|cmpq $-1, %r14|je .B51
        leaq 3945(%rsp), %rcx|leaq 2976(%rsp), %rdx|movl $943, %r8d|vzeroupper|callq memcpy
        vmovaps 640(%rsp), %ymm0|vmovaps %ymm0, 576(%rsp)|movq 672(%rsp), %rax|jmp .B58'''),
        L('.B32:|movb $5, %al|jmp .B50')]


def check(bodies,assembly):
    name,_,before=prefix.shapes.check(bodies,assembly);lines=life.code(bodies[name]);covered=set()
    for part in parts():
        at=lines.index(part[0]);end=next((i for i in range(at+1,len(lines)) if lines[i].endswith(':')),len(lines))
        s.require(lines[at:end]==part,'complete AVX2 cSHAKE prefix/retained transfer block')
        covered.update(range(at,end))
    pred=prefix.shapes.direct.predecessors(lines)
    for at in covered:s.require(pred[at]<=covered|set(before),'no unreviewed transfer entry')
    for a,b in ((27,28),(28,30),(31,49),(49,50)):
        at=lines.index(f'.B{a}:');end=next(i for i in range(at+1,len(lines)) if lines[i].endswith(':'))
        s.require(lines[end]==f'.B{b}:','actual transfer fallthrough')
    total=sorted(covered|set(before));s.require(total==list(range(597)),'complete AVX2 start instruction coverage')
    return name,sorted(covered),total


def schedule(customized):
    steps=[('seed',)]
    def cp(src,at,dst,end,width):steps.append(('copy',src,at,dst,end,width))
    if customized:
        cp('frame',304,'saved',0,1);cp('frame',378,'saved',1,1)
        for at,end,width in ((305,96,32),(337,128,32),(346,137,32),(379,88,4),(383,92,1)):
            cp('frame',at,'frame',end,width)
    else:
        for at,end,width in ((305,64,4),(309,78,2),(311,63,1),(312,176,8)):
            cp('frame',at,'frame',end,width)
        for at,end,width in ((320,8,8),(328,16,8),(336,24,1),(337,25,8),(345,33,4),
            (349,37,2),(351,39,1),(352,40,8),(360,48,8),(368,56,1)):
            cp('frame',at,'saved',end,width)
        cp('frame',346,'frame',137,32)
        for at,end,width in ((25,128,8),(33,136,4),(37,140,2),(39,142,1),(40,143,8),(48,151,8),(56,159,1)):
            cp('saved',at,'frame',end,width)
        for at,end,width in ((64,96,4),(78,100,2),(63,102,1),(176,103,8)):
            cp('frame',at,'frame',end,width)
        for at,end,width in ((8,111,8),(16,119,8),(24,127,1)):cp('saved',at,'frame',end,width)
        steps += [('literal','saved',1,2),('literal','saved',0,0)]
    for at,end,width in ((137,265,4),(141,269,1),(142,270,1),(143,271,8),(151,279,8),
        (159,287,1),(160,288,8),(168,296,1),(128,256,32),(96,224,32),(88,80,4),(92,84,1)):
        cp('frame',at,'frame',end,width)
    steps += [('replace_prefix',)]
    cp('saved',0,'frame',1568,1)
    for at,end,width in ((224,1569,32),(256,1601,32),(265,1610,32)):cp('frame',at,'frame',end,width)
    cp('saved',1,'frame',1642,1);cp('frame',80,'frame',1643,4);cp('frame',84,'frame',1647,1)
    steps += [('literal','frame',1666,0),('literal','frame',1664,4 if customized else 31),
        ('literal','frame',1665,3 if customized else 5),('state_ready',)]
    cp('frame',704,'saved',0,1);cp('frame',705,'frame',2976,943);cp('frame',1648,'saved',8,8)
    cp('frame',1656,'frame',640,32);cp('frame',1688,'frame',672,8)
    steps += [('accept_final',)]
    for at,end,width in ((2976,3945,943),(640,576,32),(672,608,8)):cp('frame',at,'frame',end,width)
    steps += [('destroy',)]
    cp('saved',0,'owner',1216,1);cp('frame',3945,'owner',1217,943);cp('saved',8,'owner',2160,8)
    cp('frame',576,'owner',2168,32);cp('frame',608,'owner',2200,8)
    return steps+[('publish',)]


def replay(rate,name,custom,steps=None):
    counts=prefix.counts(rate,name,custom);path=prefix.prefix_path(rate,name,custom)
    s.require(counts is not None and path['result']==-1,'successful constructor inputs')
    customized=counts['customized'];memory={n:[('unknown',n,i) for i in range(size)]
        for n,size in (('frame',4888),('saved',64),('owner',2272))}
    original=memory['owner'].copy();authority=[('authority',i) for i in range(8)]
    state=[('core-after-prefix',i) for i in range(992)];state[576:584]=authority
    state[938]=255;state[944:952]=[0]*8
    data=b''.join(v.to_bytes(16,'little') for v in (path['remaining'],custom,path['emitted'],counts['expected']))
    data+=rate.to_bytes(8,'little')+bytes((0,0,path['phase']))
    active=[('prefix',i,v) for i,v in enumerate(data)];active[0]=data[0];active[74]=data[74]
    padding=[('prefix-padding',i) for i in range(5)]
    expected=state.copy();expected[864:944]=active+(padding if customized else memory['frame'][88:93])
    expected[960:963]=[4 if customized else 31,3 if customized else 5,0]
    seeded=replacing=ready=accepted=destroyed=published=False;written=set();prefix_written=set();overlap=0
    def region(n,at,width):
        s.require(n in memory and type(at) is int and type(width) is int and width>0 and
            (32 if n=='frame' else 1216 if n=='owner' else 0)<=at and
            at+width<=(2208 if n=='owner' else len(memory[n])),'bounded prefix/state/staging/retained region')
        return memory[n]
    def complete():
        s.require(ready and accepted and destroyed and written==set(range(1216,2208)),
            'all992 physical retained bytes follow final success and typed destruction')
        s.require(memory['owner'][1216:2208]==expected,'complete constructor result origins retained')
        s.require(memory['owner'][:1216]==original[:1216] and memory['owner'][2208:]==original[2208:],
            'output, plan and outer authority outside replacement')
    for step in schedule(customized) if steps is None else steps:
        s.require(not published,'no post-publication mutation')
        if step==('seed',):
            s.require(not seeded,'one replayed helper result');seeded=True
            memory['frame'][704:1696]=state;memory['frame'][304:384]=active+padding;continue
        s.require(seeded,'live prefix and core before transfers')
        if step==('replace_prefix',):
            s.require(not replacing and memory['frame'][704:1696]==state,'replace absent prefix exactly once before local mutation')
            replacing=True;continue
        if step==('state_ready',):
            s.require(replacing and not ready and memory['frame'][704:1696]==expected,
                'all active prefix origins, padding and cSHAKE domain installed before result staging')
            s.require(prefix_written==set(range(1568,1648)),'complete physical prefix replacement')
            ready=True;continue
        if step==('accept_final',):
            s.require(ready and not accepted and memory['saved'][8:16]==[0]*8,'exact final discriminant before retained installation')
            accepted=True;continue
        if step==('destroy',):
            s.require(accepted and not destroyed and not written,'old state destroyed before replacement')
            destroyed=True;memory['owner'][1216:2208]=[('destroyed',i) for i in range(992)];continue
        if step==('publish',):complete();published=True;continue
        if step[0]=='literal':
            _,dst,end,value=step;width=1;s.require(type(value) is int and 0<=value<=255,'one literal byte');values=[value]
        else:
            s.require(step[0]=='copy','known constructor move')
            _,src,at,dst,end,width=step;values=region(src,at,width)[at:at+width]
            s.require(src!=dst or at+width<=end or end+width<=at,'nonoverlapping memcpy extents')
        target=region(dst,end,width)
        if dst=='frame' and end<1696 and end+width>704:
            s.require(replacing and not ready and 1568<=end and end+width<=1667,
                'local engine remains intact; only prefix/domain fields change')
            for i,value in enumerate(values):
                if 1568<=end+i<1648:
                    if end+i in prefix_written:
                        s.require(target[end+i]==value,'overlapping prefix stores have identical origins');overlap+=1
                    prefix_written.add(end+i)
        if dst=='owner':
            s.require(destroyed and not written.intersection(range(end,end+width)),'retained writes only after destruction without overlap')
            written.update(range(end,end+width))
        target[end:end+width]=values
    complete();s.require(published,'publish completed constructor')
    s.require(memory['frame'][704:1696]==expected,'live local result preserved through final replacement')
    return dict(rate=rate,customized=customized,prefix_bytes=80,active_prefix_bytes=75,
        matching_prefix_overlap_bytes=overlap,physical_retained_bytes=992,local_authority_span=[1280,1288],
        retained_authority_span=[1792,1800],prefix_active_retained_span=[2080,2155],
        prefix_padding_retained_span=[2155,2160],domain=expected[960:962],
        active_origins_preserved=True,old_state_destroyed_before_installation=True,
        publication_after_complete_replacement=True,padding_initialized=False,
        local_and_staging_copy_erasure_qualified=False)


def inspect(bodies,assembly,construction,prefix_review,placement):
    name,covered,total=check(bodies,assembly)
    s.require(prefix_review['function']==name and prefix_review['cshake_prefix_calls_and_failure_joins_qualified'] and
        prefix_review['geometry']['used_zero_preserved_by_engine_absorb'],'replayed complete initialized prefix and failure contracts')
    s.require(construction['function']==name and construction['successful_placement_destroys_previous_typed_state_first'] and
        construction['successful_slot_and_phase_commit_after_state_copy'],'same retained-state publication path')
    s.require(placement['state_destructor']['function']==life.DROP['avx2'] and
        placement['state_destructor']['typed_payload_cleanup_composed'],'reviewed typed old-state destruction')
    return dict(function=name,reviewed_instruction_positions=covered,combined_start_instruction_positions=total,
        cases=[replay(rate,n,v) for rate in (136,168) for n,v in ((0,0),(1,0),(0,1))],
        avx2_start_instruction_coverage_complete=True,cshake_constructor_transfer_origins_qualified=True,
        all_constructor_paths_qualified=False,private_frame_erasure_qualified=False,
        runtime_abi_and_disjoint_resident_allocation_required=True,shared_runtime_completion_package=8)
