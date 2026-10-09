"""Saved SIMD executor scalar fallback and its distinct scalar callee."""
import re
import hashlib
import windows_enclave_sha3_simd_vector_shape as vector
import windows_enclave_sha3_permutation as permutation
import windows_enclave_sha3_simd_kernel as kernel
life,s,L=vector.life,vector.s,vector.L


def names(bodies):
    return vector.names(bodies)|{'scalar':s.one(bodies,r'11permutation6native6scalar$')}


def shape(n):
    return L(f'''.B190:|xorl %esi, %esi|jmp .B192|.B191:|incq %rsi|cmpq $4, %rsi|
        je .B206|.B192:|movq 888(%rbp), %rax|cmpb $1, (%rax,%rsi)|jne .B191|
        movq 928(%rbp), %rcx|vzeroupper|callq *912(%rbp)|nop|testb %al, %al|jne .B216|
        movq 16(%r12), %rax|testq %rax, %rax|je .B217|movq 24(%r12), %rcx|
        cmpq $-1, %rcx|je .B207|incq %rcx|decq %rax|movq %rax, 16(%r12)|
        movq %rcx, 24(%r12)|cmpb $0, 16(%rdi)|jne .B218|movq (%rdi), %rax|
        testq %rax, %rax|je .B202|cmpb $0, 16(%rax)|je .B215|movzbl 17(%rax), %ecx|
        movq %rax, 952(%rbp)|callq *8(%rax)|nop|testb %al, %al|
        movq 952(%rbp), %rax|je .B215|.B202:|movq %rsi, 952(%rbp)|
        imulq $200, %rsi, %rbx|addq 960(%rbp), %rbx|movl $200, %edx|
        movl $200, %r9d|movq 704(%rbp), %rcx|movq %rcx, %rsi|movq %rbx, %r8|
        callq {n['copy']}|cmpb $-1, %al|jne .B207|movq %rsi, %rcx|
        movq 488(%rbp), %rsi|movq %rsi, %rdx|movq 712(%rbp), %r8|
        movq 720(%rbp), %r9|callq {n['scalar']}|movl $40, %edx|movq %rsi, %rcx|
        callq {life.ZERO}|movl $40, %edx|movq 712(%rbp), %rcx|callq {life.ZERO}|
        movl $200, %edx|movq 720(%rbp), %rcx|callq {life.ZERO}|movl $200, %edx|
        movl $200, %r9d|movq %rbx, %rcx|movq 704(%rbp), %r8|callq {n['copy']}|
        cmpb $-1, %al|jne .B207|movq 496(%rbp), %rcx|callq {n['scalar_wipe']}|
        movq 808(%rbp), %rax|cmpq $-1, %rax|movq 1104(%rbp), %rbx|
        movq 952(%rbp), %rsi|je .B244|incq %rax|movq %rax, 808(%rbp)|jmp .B191|
        .B206:|movq 808(%rbp), %rax|movq 888(%rbp), %r11|movq 504(%rbp), %rsi|jmp .B87''')


def inspect_kernel(bodies,ir,constants,n):
    # Re-run the established scalar coordinate/LFSR construction, with this
    # image's explicit label and table placement. No earlier PASS is trusted.
    body=bodies[n['scalar']]
    before,active,after=kernel.envelope.opaque_parts(body,
        ('BRYNJA_SCALAR_BEGIN','BRYNJA_SCALAR_ERASE','BRYNJA_SCALAR_END'))
    kernel.envelope.complete(before[:3],[n['scalar']+':','.Lfunc_begin28:',
        '.seh_proc '+n['scalar']],'scalar complete function identity')
    want=[re.sub(r'\.Ltmp(\d+)',lambda m:'.Ltmp'+str(int(m[1])+18),line)
          for line in permutation.opaque_shape()]
    kernel.envelope.complete(active,want,'actual scalar round schedule and register/scratch erasure')
    kernel.envelope.complete(before[3:],L(f'''pushq %rsi|.seh_pushreg %rsi|
        pushq %rdi|.seh_pushreg %rdi|pushq %rbx|.seh_pushreg %rbx|.seh_endprologue|
        movq %rdx, %rsi|movq %rcx, %rdi|leaq {kernel.TABLE}(%rip), %rbx'''),
        'scalar pointer-only entry saves')
    kernel.envelope.complete(after,L('''.seh_startepilogue|popq %rbx|popq %rdi|
        popq %rsi|.seh_endepilogue|retq'''),'scalar pointer-only return restores')
    raw=permutation.round_constants()
    s.require(kernel.TABLE in constants and constants[kernel.TABLE]['bytes']==192 and
        constants[kernel.TABLE]['sha256']==hashlib.sha256(raw).hexdigest(),'scalar linked LFSR constants')
    args=', '.join(f'ptr noalias nofree noundef nonnull dereferenceable({size}) %{i}'
                  for i,size in enumerate((200,40,40,200)))
    features=vector.absorb.squeeze.shape.digest.helpers.receive.worker.resident.session.zero.SIMD_FEATURES
    want=f'define internal fastcc void @{n["scalar"]}({args}) unnamed_addr '+(
        '{ noinline nounwind uwtable "target-cpu"="x86-64" "target-features"="'+features+'" } {')
    s.require(life.reuse.abi(ir,n['scalar'])==want,'actual noalias four-region scalar ABI')
    return dict(function=n['scalar'],rounds=24,state_bytes=200,scratch_bytes=[40,40,200],
        linked_constants_independently_derived=True,opaque_stack_accesses=0,
        working_gprs_erased=['rax','rcx','rdx','r10','r11'],
        caller_disjoint_live_regions_required=True,caller_frame_erasure_qualified=False)
