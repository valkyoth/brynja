"""Saved SIMD resident construction and authority origin, not lifetime closure."""
import windows_enclave_sha3_simd_session as session
import windows_enclave_sha3_avx2_shapes as kat

life=session.life
s=life.s
KAT='anon.da1211fce185a4acaa3e5310c69f5eba.0'


def L(text):
    return [v.strip() for v in text.replace('\n','').split('|') if v.strip()]


def names(bodies):
    return session.names(bodies)|{
        'new':s.one(bodies,r'^[^?].*keccak_simd_resident.*Resident3new$'),
        'compiled':s.one(bodies,r'keccak_hardened_batch.*Kernel8compiled$')}


def page_clear(label):
    return [f'.B{label}:']+['movb $0, '+('' if i==0 else str(i))+'(%rdi,%rax)' for i in range(8)]+[
        'addq $8, %rax','cmpq $4096, %rax',f'jne .B{label}']


def constructor(n):
    code=L('''pushq %r15|pushq %r14|pushq %rsi|pushq %rdi|pushq %rbx|
        movl $4576, %eax|callq __chkstk|subq %rax, %rsp|movq %rdx, %rdi|movq %rcx, %rsi|
        leaq 2752(%rsp), %rcx|movl $800, %r8d|xorl %edx, %edx|callq memset|
        vxorps %xmm0, %xmm0, %xmm0''')
    code += [f'vmovups %ymm0, {at}(%rsp)' for at in range(32,832,32)]
    code += L('''leaq 832(%rsp), %rcx|leaq 32(%rsp), %rbx|movl $800, %r8d|
        movq %rbx, %rdx|vzeroupper|callq memcpy|leaq 1952(%rsp), %rcx|
        vxorps %xmm0, %xmm0, %xmm0''')
    code += [f'vmovups %ymm0, {at}(%rsp)' for at in range(1632,1952,32)]
    code += L(f'''movl $800, %r8d|movq %rbx, %rdx|vzeroupper|callq memcpy|
        xorl %ecx, %ecx|callq {n['compiled']}|testb %al, %al|je .B8|
        leaq 832(%rsp), %rbx|movq %rbx, %rcx|callq {n['wipe']}|
        leaq 2752(%rsp), %rdx|movl $4, %r8d|movq %rbx, %rcx|callq {n['pack']}|
        movq %rbx, %rcx|callq {n['wrapper']}|xorl %ecx, %ecx|callq {n['compiled']}|
        testb %al, %al|je .B8|leaq 2752(%rsp), %rbx|leaq 832(%rsp), %r14|
        movl $4, %r8d|movq %rbx, %rcx|movq %r14, %rdx|callq {n['unpack']}|
        movq %r14, %rcx|callq {n['wipe']}''')
    for lane in range(4):
        if lane:code += [f'leaq {2752+200*lane}(%rsp), %rcx']
        code += [f'leaq {KAT}(%rip), %rdx','movl $200, %r8d']
        if not lane:code += ['movq %rbx, %rcx']
        code += ['callq memcmp','testl %eax, %eax','jne .B6']
    code += L(f'''leaq 832(%rsp), %rcx|callq {n['wipe']}|
        movb $0, (%rdi)|movb $0, 7(%rdi)|movw $0, 5(%rdi)|movl $0, 1(%rdi)|
        leaq {n['compiled']}(%rip), %rax|movq %rax, 8(%rdi)|movw $1, 16(%rdi)''')
    code += L(f'xorl %ecx, %ecx|callq {n["compiled"]}|testb %al, %al|je .B11')*2
    code += L('''leaq 24(%rdi), %r15|leaq 832(%rsp), %rbx|movl $1024, %r8d|
        movq %rbx, %rcx|xorl %edx, %edx|callq memset|leaq 3552(%rsp), %r14|
        movl $1024, %r8d|movq %r14, %rcx|movq %rbx, %rdx|callq memcpy|
        movb $5, 24(%rdi)|movb $-1, 32(%rdi)|movq %rdi, 88(%rdi)|
        leaq 96(%rdi), %rcx|movl $1024, %r8d|movq %r14, %rdx|callq memcpy|
        movq $0, 1120(%rdi)|movb $0, 1128(%rdi)|movq %rdi, (%rsi)|
        movq %rdi, 8(%rsi)|movq %r15, 16(%rsi)|jmp .B15''')
    code += L(f'''.B8:|leaq 832(%rsp), %rcx|callq {n['wipe']}|
        .B6:|leaq 832(%rsp), %rcx|callq {n['wipe']}|xorl %eax, %eax''')
    code += page_clear(7)+L('''.B13:|movb $5, 8(%rsi)|movq $0, (%rsi)|.B15:|
        addq $4576, %rsp|popq %rbx|popq %rdi|popq %rsi|popq %r14|popq %r15|retq|
        .B11:|movb $0, 16(%rdi)|xorl %eax, %eax''')+page_clear(12)+['jmp .B13']
    return code


def geometry():
    # These are public initialization spans, NOT secret-erasure coverage.
    spans={'public_zero_array':[32,832],'kat_workspace':[832,2752],
           'kat_states':[2752,3552],'output_snapshot':[3552,4576]}
    for a,(start,end) in spans.items():
        s.require(32<=start<end<=4576,'constructor frame allocation bound')
        for b,(other,limit) in spans.items():
            if a!=b:s.require(end<=other or limit<=start,'disjoint initial constructor allocations')
    authority=(0,24);owner=(24,1136)
    s.require(authority[1]==owner[0] and owner[1]<=4096,'disjoint page authority and borrower')
    return dict(frame_spans=spans,authority_page_span=list(authority),owner_page_span=list(owner),
        owner_authority_pointer_offset=64,owner_output_span=[72,1096],
        owner_sequence_offset=1096,owner_phase_offset=1104,
        output_page_span=[96,1120],return_backing_authority_owner_offsets=[0,0,24],
        scratch_reused_for_output_only_after_kat_retirement=True,
        constructor_temporaries_public_only=True,padding_initialization_claimed=False)


def paths(lines,n):
    """Conservative constructor CFG; two reviewed fixed-page loops summarized.

    This does not execute the kernel or memcpy. Their semantics are explicit
    prerequisites; it checks KAT/admission/publication/retirement event order.
    """
    labels={v[:-1]:i for i,v in enumerate(lines) if v.endswith(':')}
    pending=[(0,(),())];result=[]
    events={'callq '+n['compiled']:'compiled','callq '+n['wipe']:'wipe',
        'callq '+n['pack']:'pack','callq '+n['wrapper']:'kernel','callq '+n['unpack']:'unpack',
        'callq memcmp':'compare','movq %rax, 8(%rdi)':'bind_callback',
        'movw $1, 16(%rdi)':'healthy_avx2','movq %rdi, 88(%rdi)':'bind_owner',
        'movq $0, 1120(%rdi)':'zero_sequence','movb $0, 1128(%rdi)':'empty_phase',
        'movq %rdi, (%rsi)':'publish_backing','movq %rdi, 8(%rsi)':'publish_authority',
        'movq %r15, 16(%rsi)':'publish_owner','movq $0, (%rsi)':'reject'}
    success=('compiled','wipe','pack','kernel','compiled','unpack','wipe',
        *('compare',)*4,'wipe','bind_callback','healthy_avx2','compiled','compiled',
        'bind_owner','zero_sequence','empty_phase','publish_backing','publish_authority','publish_owner')
    while pending:
        at,trace,seen=pending.pop();s.require(0<=at<len(lines) and at not in seen,'finite constructor CFG')
        line=lines[at];seen=seen+(at,)
        if line in ('.B7:','.B12:'):
            label=int(line[2:-1]);expected=page_clear(label)
            s.require(lines[at:at+len(expected)]==expected,'full bounded page-erasure loop')
            pending.append((at+len(expected),trace+('page_clear',),seen));continue
        if line in events:trace+=events[line],
        if line=='retq':
            if 'publish_owner' in trace:s.require(trace==success,'complete KAT before resident publication')
            else:
                s.require(trace[-2:]==('page_clear','reject'),'failed constructor clears full page before rejection')
                if 'bind_callback' not in trace:
                    s.require(trace[-3:]==('wipe','page_clear','reject'),'failed KAT retires scratch before page')
                s.require(not any(x.startswith('publish_') for x in trace),'no partially published resident on failure')
            result.append(list(trace));continue
        if line.startswith(('je ','jne ','jmp ')):
            target=line.split()[1];s.require(target in labels,'constructor local target')
            pending.append((labels[target],trace,seen))
            if line.startswith('jmp '):continue
        pending.append((at+1,trace,seen))
    s.require(len(result)==9,'all nine conservative constructor paths')
    return result


def inspect(bodies,ir,constants,checked_session):
    n=names(bodies)
    for role in ('wipe','pack','unpack','wrapper'):
        s.require(checked_session['functions'][role]==n[role],'constructor reviewed callee '+role)
    s.require(checked_session['full_scratch_wipe_ranges']==[[0,800],[800,960],[960,1120],[1120,1920]],
              'constructor exact complete scratch erasure')
    raw=kat.zero_permutation()
    s.require(KAT in constants and constants[KAT]['bytes']==200 and constants[KAT]['sha256']==kat.digest(raw),
              'independently computed four-lane startup answer')
    s.require(life.code(bodies[n['compiled']])==['movl %ecx, %eax','xorb $1, %al','retq'],
              'compiled callback admits only immutable AVX2 tag zero')
    expected=constructor(n);s.require(life.code(bodies[n['new']])==expected,'complete resident construction body')
    target='"target-cpu"="x86-64" "target-features"="'+session.zero.SIMD_FEATURES+'"'
    compiled=f'define internal noundef zeroext i1 @{n["compiled"]}(i1 noundef zeroext %0) unnamed_addr '+(
        '{ mustprogress nofree norecurse nosync nounwind willreturn memory(none) uwtable '+target+' } {')
    new=f'define internal fastcc void @{n["new"]}('+(
        'ptr dead_on_unwind noalias nofree noundef nonnull writable writeonly align 8 captures(none) dereferenceable(24) %0, '
        'ptr noalias nofree noundef nonnull align 4096 dereferenceable(4096) %1) unnamed_addr { uwtable '+target+
        ' } personality ptr @__CxxFrameHandler3 {')
    s.require(life.reuse.abi(ir,n['compiled'])==compiled,'exact pure nonthrowing callback ABI')
    s.require(life.reuse.abi(ir,n['new'])==new,'exact exclusive page and resident-result ABI')
    return dict(function=n['new'],compiled_callback=n['compiled'],instruction_positions=len(expected),
        constructor_path_events=paths(expected,n),placement=geometry(),
        startup_all_four_200_byte_results_compared=True,callback_is_pure_compiled_tag_check=True,
        public_callback_not_host_supplied=True,publication_after_authority_and_owner_initialization=True,
        constructor_failure_clears_all_page_bytes=True,shared_memory_runtime_semantics_required=True,
        worker_page_admission_and_resident_lifetime_qualified=False,
        owner_operation_and_digest_callers_qualified=False,private_frame_erasure_qualified=False)
