"""Saved executor output validation/commit; inner hashing remains separate."""
import windows_enclave_sha3_simd_digest as digest
import windows_enclave_sha3_simd_output_ir as provenance
life,s,L=digest.life,digest.s,digest.L


def validate_shape():
    code=[]
    for i in range(4):
        absent,after=3+4*i,4+4*i
        if i:code+=[f'.B{4*i}:']
        code+=L(f'cmpb $-1, {104+112*i}(%rcx)|movq {str(16*i) if i else ""}(%rdx), %r8')
        if not i:code+=['movb $8, %al']
        code+=L(f'je .B{absent}|testq %r8, %r8|je .B17')
        src,result,low=('rcx','r8','ecx') if i==3 else ('r8','r9','r8d')
        code+=L(f'''movq {96+112*i}(%rcx), %{src}|movq %{src}, %{result}|
            shrq $3, %{result}|andl $7, %{low}|cmpq $1, %{src}|sbbq $-1, %{result}|
            cmpq %{result}, {8+16*i}(%rdx)''')
        if not i:code+=L('je .B4|.B17:|retq')
        else:code+=L(f'jne .B17|jmp .B{after}')
        code+=L(f'.B{absent}:|testq %r8, %r8|jne .B17')
    return code+L('.B16:|movb $-1, %al|retq')


def prepare_shape():
    # Includes the adjacent rejected internal-invariant block: not elided from
    # the shape contract merely because valid entry cannot branch to it.
    return L('''movq 592(%rbp), %rcx|testq %rcx, %rcx|je .B245|
        movq 600(%rbp), %r9|cmpq $1024, %r9|ja .B269|
        movq %r12, %r8|leaq (%r12,%r9), %rbx|movl $1024, %eax|
        subq %r9, %rax|jmp .B246|.B244:|xorl %r14d, %r14d|movb $14, %r13b|
        movq 976(%rbp), %rsi|jmp .B75|.B245:|movl $1024, %eax|
        xorl %r8d, %r8d|movq %r12, %rbx|.B246:|movq 608(%rbp), %r15|
        testq %r15, %r15|je .B249|movq 616(%rbp), %rdi|subq %rdi, %rax|
        jb .B269|movq %rbx, 944(%rbp)|addq %rdi, %rbx|jmp .B250|
        .B249:|movq $0, 944(%rbp)|.B250:|movq 624(%rbp), %rdx|
        movq %rdx, 824(%rbp)|testq %rdx, %rdx|je .B253|
        movq 632(%rbp), %r10|movq %r10, 936(%rbp)|subq %r10, %rax|
        jb .B269|movq %rbx, 960(%rbp)|movq 936(%rbp), %rdx|
        addq %rdx, %rbx|jmp .B254|.B253:|movq $0, 960(%rbp)|.B254:|
        movq 640(%rbp), %rdx|movq %rdx, 928(%rbp)|testq %rdx, %rdx|je .B256|
        movq 648(%rbp), %rdx|movq %rdx, 912(%rbp)|cmpq %rax, %rdx|
        jbe .B257|jmp .B269|.B256:|xorl %ebx, %ebx|.B257:''')


def copy_shape(n):
    return L(f'''testq %r8, %r8|je .B260|testq %rcx, %rcx|je .B260|
        movq 600(%rbp), %rdx|callq {n['copy']}|cmpb $-1, %al|jne .B269|.B260:|
        cmpq $0, 944(%rbp)|je .B263|testq %r15, %r15|je .B263|
        movq 616(%rbp), %rdx|movq %r15, %rcx|movq 944(%rbp), %r8|
        movq %rdi, %r9|callq {n['copy']}|cmpb $-1, %al|jne .B269|.B263:|
        cmpq $0, 960(%rbp)|je .B266|cmpq $0, 824(%rbp)|je .B266|
        movq 632(%rbp), %rdx|movq 824(%rbp), %rcx|movq 960(%rbp), %r8|
        movq 936(%rbp), %r9|callq {n['copy']}|cmpb $-1, %al|jne .B269|.B266:|
        testq %rbx, %rbx|je .B270|cmpq $0, 928(%rbp)|je .B270|
        movq 648(%rbp), %rdx|movq 928(%rbp), %rcx|movq %rbx, %r8|
        movq 912(%rbp), %r9|callq {n['copy']}|cmpb $-1, %al|je .B270|.B269:|
        movq 1104(%rbp), %rcx|callq {n['workspace_wipe']}|movl $1024, %edx|
        movq %r12, %rcx|callq {life.ZERO}|movb $14, %r13b|movq 976(%rbp), %rsi|
        movq %r14, %rdi|jmp .B76|.B270:|movq 1104(%rbp), %rcx|
        callq {n['workspace_wipe']}|movl $1024, %edx|movq %r12, %rcx|callq {life.ZERO}''')


def region(lines,expected):
    matches=[i for i in range(len(lines)) if lines[i:i+len(expected)]==expected]
    s.require(len(matches)==1,'unique complete executor output region')
    return matches[0],matches[0]+len(expected)


def inspect(bodies,ir,caller):
    n=digest.helpers.names(bodies)|{'validate':s.one(bodies,r'hardened_batch6output8validate$')}
    s.require(caller['functions']['executor']==n['executor'] and
        caller['helpers']['copy_wrapper_checks_equal_lengths'] and
        caller['helpers']['geometry']['workspace_bytes']==5260,
        'replayed caller/helper prerequisites')
    s.require(life.code(bodies[n['validate']])==validate_shape(),'full output validator')
    args=', '.join(f'ptr noalias nofree noundef nonnull readonly align 8 captures(none) dereferenceable({size}) %{i}'
        for i,size in enumerate((448,64)))
    want=f'define internal fastcc noundef range(i8 -1, 9) i8 @{n["validate"]}({args}) unnamed_addr '+(
        '{ mustprogress nofree norecurse nosync nounwind willreturn memory(argmem: read) uwtable '+digest.target()+
        ' } personality ptr @__CxxFrameHandler3 {')
    s.require(life.reuse.abi(ir,n['validate'])==want,'read-only validator ABI')
    lines=life.code(bodies[n['executor']]);prepared=prepare_shape();copies=copy_shape(n)
    first,last=region(lines,prepared);next_first,end=region(lines,copies)
    s.require((len(lines),first,last,next_first,end)==(1676,1482,1542,1542,1602),
        'exact saved output region extents; no inserted early-return prefix')
    # Saved descriptors are loaded on entry and copied without recomputation on
    # success. LLVM use closure, not these local sequences alone, forbids writes.
    region(lines,L('''vmovups (%r9), %ymm0|vmovups 32(%r9), %ymm1|
        vmovups %ymm0, 592(%rbp)|vmovups %ymm1, 624(%rbp)'''))
    region(lines,L('''vmovups 592(%rbp), %ymm0|vmovups 624(%rbp), %ymm1|
        vmovups 656(%rbp), %xmm2|vmovups %xmm2, 64(%rcx)|movq 672(%rbp), %rax|
        movq %rax, 80(%rcx)|movq 680(%rbp), %rax|movq %rax, 88(%rcx)|
        vmovups %ymm1, 32(%rcx)|vmovups %ymm0, (%rcx)'''))
    return dict(functions=n,ir_provenance=provenance.inspect(ir,n),
        validator_instruction_positions=len(validate_shape()),output_prepare_region=[first,last],
        output_copy_and_cleanup_region=[next_first,end],
        all_four_source_extents_preflight_before_first_copy=True,
        copy_failure_retires_workspace_and_staging_then_reaches_quarantine=True,
        output_borrow_pointer_ir_uses_closed=True,
        remaining_executor_instructions_and_machine_aliases_qualified=False,
        private_frame_erasure_qualified=False)
