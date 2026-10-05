"""Inspected scalar SHA-3 owner/receiver assembly sequences; not a general proof."""
import windows_enclave_sha3_lifecycle as life

DROP,ZERO = life.s.DROP,life.s.ZERO
STATE = '_RNvMNtCsgp9hxIs16B4_11sha3_stream17sha3_stream_stateNtB2_5State'
MASK = '_RNvNtCsjNKEhcqdpKw_11brynja_core13secret_memory24secret_byte_mask_is_zero'
COPY = '_RNvNtCsjNKEhcqdpKw_11brynja_core13secret_memory18copy_secret_region'
ROLES = ('begin','setup','setup_chunk','finish_setup','update','finish','rehash','squeeze','export','receive')
IR_HASH = 'a616cca964d4d226908b7ad5d400e21fba9e0acfac4a9c85c005381446d10b4d'
RUNTIME_BOUNDARIES = {'__chkstk','__umodti3'}
SEQUENCES = {
 'begin':(
    'cmpb $0, 2178(%rcx)|je .LBB44_1',
    'decq %r8|cmpq $7, %r8|ja .LBB44_5',
    'callq '+STATE+'3new|movzbl 32(%rsp), %ebp|movzbl 33(%rsp), %edi|cmpb $-1, %bpl|je .LBB44_3',
    'leaq 34(%rsp), %rdx|leaq 1170(%rsp), %rbx|movl $1134, %r8d|movq %rbx, %rcx|callq memcpy',
    'callq '+DROP+'|movb %bpl, 1024(%rsi)|movb %dil, 1025(%rsi)',
    'movb $-1, %dil|movb $3, %al|jmp .LBB44_8'),
 'setup':(
    'cmpl $6, %eax|ja .LBB47_4|movl $97, %ecx|btl %eax, %ecx|jae .LBB47_4',
    'cmpq $7, %r8|movq %r9, 40(%rsp)|je .LBB47_9|cmpq $8, %r8|jne .LBB47_8',
    'adcq $0, %r8|movb $1, %bpl|jb .LBB47_58|addq %r14, %rax|adcq %r12, %r8|jb .LBB47_58',
    'adcq $0, %r15|movb $1, %bpl|jb .LBB47_32|addq %r14, %rax|adcq %r12, %r15|jb .LBB47_32',
    'callq __umodti3',
    'leaq 4864(%rsp), %rcx|movl $1120, %r8d|callq memcpy',
    'callq '+DROP+'|movb %dil, 1024(%rsi)|leaq 1026(%rsi), %rcx|leaq 4850(%rsp), %rdx|movl $1134, %r8d|callq memcpy',
    'movb %bl, 2177(%rsi)|cmpb $1, 2178(%rsi)|movb $2, %al|sbbb $0, %al',
    'movdqa %xmm6, 5984(%rsp)', 'movaps 5984(%rsp), %xmm6'),
 'setup_chunk':(
    'decb %al|movb $2, %bl|cmpb $1, %al|ja .LBB42_20',
    'cmpq $1024, %r14|ja .LBB42_20',
    'testq %r14, %r14|sete %al|testb %dil, %dil|setne %cl|movb $4, %bl|cmpb %cl, %al|je .LBB42_20',
    'shlb %cl, %dl|leaq (%r9,%r14), %rcx|decq %rcx',
    'callq '+MASK,
    'cmpl $8, %eax|je .LBB42_13|movb $2, %bl|cmpl $7, %eax|jne .LBB42_20',
    'movb $6, %bl|cmpb $-1, %al|je .LBB42_22'),
 'finish_setup':(
    'decb %al|movb $2, %bl|cmpb $1, %al|ja .LBB43_3',
    'leaq 1328(%rsp), %rcx|movl $1136, %r8d|movq %rdi, %rdx|callq memcpy|movb $0, 1024(%rsi)',
    'cmpb $2, 274(%rsp)|jne .LBB43_36|movq 232(%rsp), %rax|orq 224(%rsp), %rax|jne .LBB43_36|cmpb $0, 273(%rsp)|jne .LBB43_36',
    'cmpb $2, 274(%rsp)|jne .LBB43_16|movq 232(%rsp), %rax|orq 224(%rsp), %rax|jne .LBB43_16|cmpb $0, 273(%rsp)|jne .LBB43_16',
    'pcmpeqb 256(%rsp), %xmm0|pmovmskb %xmm0, %eax|cmpl $65535, %eax',
    'movb %bl, 1024(%rsi)|movb $0, 1025(%rsi)',
    'movb $3, %al|cmpb $2, 2178(%rsi)|jne .LBB43_65',
    'cmpq $1024, %r15|ja .LBB43_48',
    'callq '+MASK+'|testb %al, %al|je .LBB43_48',
    'movb $6, %r14b|cmpb $-1, %al|jne .LBB43_48',
    'movb $0, 2176(%rsi)|movb $4, %al|jmp .LBB43_65'),
 'update':(
    'cmpb $3, 2178(%rcx)|jne .LBB53_16',
    'cmpq $1024, %r9|ja .LBB53_16',
    'movzbl 1024(%rsi), %eax|leaq .LJTI53_0(%rip), %rcx|movslq (%rcx,%rax,4), %rax|addq %rcx, %rax|movb $2, %bl|jmpq *%rax',
    'cmpb $0, 1025(%rsi)|jne .LBB53_16',
    'testb %cl, %cl|je .LBB53_17'),
 'finish':(
    'cmpb $3, 2178(%rcx)|jne .LBB49_3',
    'cmpq $1024, %r9|ja .LBB49_3',
    'testq %r9, %r9|sete %al|testb %bl, %bl|setne %cl|movb $4, %dil|cmpb %cl, %al|je .LBB49_3',
    'shlb %cl, %dl|leaq (%r8,%r9), %rcx|decq %rcx',
    'callq '+MASK,
    'callq '+STATE+'12finish_fixed|movl %eax, %edi|cmpb $-1, %al|je .LBB49_25',
    'movq %rbx, 2168(%rsi)|movb $8, 2176(%rsi)|movb $-1, %dil|movb $6, %al',
    'cmpb $-1, %al|jne .LBB49_3|movb $-1, %dil|movb $4, %al'),
 'rehash':(
    'addb $-5, %al|movb $2, %bl|cmpb $1, %al|ja .LBB51_3',
    'callq '+STATE+'3new',
    'cmpq $1024, %r14|ja .LBB51_23',
    'callq '+MASK+'|testb %al, %al|jne .LBB51_13|jmp .LBB51_23',
    'leaq 1200(%rsp), %rcx|movl $1024, %r8d|xorl %edx, %edx|callq memset',
    'cmpb $-1, %al|je .LBB51_16|movl %eax, %ebx|leaq 1200(%rsp), %rcx|movl $1024, %edx|callq '+ZERO,
    'callq '+DROP+'|movl $1136, %r8d|movq %r14, %rcx|movq %rbx, %rdx|callq memcpy',
    'callq '+COPY+'|cmpb $-1, %al|je .LBB51_18',
    'movq %rdi, 2168(%rsi)|movb $8, 2176(%rsi)|movb $6, %al',
    'movb %al, 2178(%rsi)|leaq 1200(%rsp), %rcx|movl $1024, %edx|callq '+ZERO),
 'squeeze':(
    'cmpb $4, 2178(%rcx)|jne .LBB54_3',
    'testb %r13b, %r13b|jne .LBB54_6|testq %r8, %r8|setne %al|shlb $3, %al|movb $4, %bl|cmpb %al, %r9b|jne .LBB54_3',
    'cmpq $1025, %r8|jae .LBB54_3',
    'leaq 152(%rsp), %rdi|movl $1024, %r8d|movq %rdi, %rcx|xorl %edx, %edx|callq memset',
    'callq '+COPY+'|movl %eax, %ebp|testq %rdi, %rdi|je .LBB54_31|movq %rdi, %rcx|movq %rbx, %rdx|callq '+ZERO,
    'leaq 152(%rsp), %rcx|movl $1024, %edx|callq '+ZERO,
    'movb $5, %dil|testb %r13b, %r13b|je .LBB54_36',
    'callq '+DROP+'|movb $0, (%rdi)|movb $6, %dil',
    'movq %r12, 2168(%rsi)|movb %r15b, 2176(%rsi)|movb $-1, %bl'),
 'export':(
    'addb $-5, %al|movb $2, %dil|cmpb $1, %al|ja .LBB1_19',
    'movq 2160(%rsi), %rax|incq %rax|movb $1, %dil|cmpq %rdx, %rax|jne .LBB1_19',
    'cmpq 2168(%rsi), %r9|jne .LBB1_19|movzbl 96(%rsp), %eax|cmpb 2176(%rsi), %al|jne .LBB1_19',
    'cmpq $1024, %r9|ja .LBB1_19|movq %rsi, %rcx|movq %r9, %rdx|callq PublicSha3Output',
    'movb $5, %dil|testl %eax, %eax|jne .LBB1_19',
    'movb $4, %al|cmpb $5, %bl|je .LBB1_20|movq %rsi, %rcx|callq '+life.s.CLEAR_OWNER),
 'receive':(
    'movl $96, %r9d|xorl %ecx, %ecx|movq %rax, %r8|callq PublicSha3Input',
    'cmpq $8, %r15|ja .LBB3_1|cmpq $7, 1024(%rdi)|jne .LBB3_1|movq 1032(%rdi), %r10|testq %r10, %r10|je .LBB3_1',
    'cmpq $1024, %r12|ja .LBB3_1|movq 1072(%rdi), %r13|cmpq $1024, %r13|ja .LBB3_1',
    'addq %r12, %rdx|jb .LBB3_1|xorb %al, %cl|jne .LBB3_1',
    'cmpq $10, %rbp|ja .LBB3_15',
    'cmpb $-1, %al|sete %bpl|jmp .LBB3_1'),
}
