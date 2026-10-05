"""Inspected saved SHA-NI owner/decoder normal paths; not an unwind proof."""
import windows_enclave_sha_ni_engine as engine

state,life = engine.state,engine.life
BEGIN,FINISH,REHASH = state.BEGIN,state.OWNER_FINISH,state.REHASH
UPDATE = life.PREFIX+'6update'
DECODE = '_RNvMNtCs11e1ovcwz1T_16sha2_accelerated21sha2_accelerated_wireNtB2_7Request6decode'
PREDICATE = '_RNvNtCscJA3KwNFXab_16brynja_hash_core23secret_memory_predicate12mask_is_zero'
FINISH_DROP = '?dtor$32@?0?'+FINISH+'@4HA'
REHASH_DROP = '?dtor$38@?0?'+REHASH+'@4HA'
NAMES = (BEGIN,FINISH,REHASH,UPDATE,DECODE,FINISH_DROP,REHASH_DROP,PREDICATE)
FRAMES = {BEGIN:4056,FINISH:2152,REHASH:4200,UPDATE:2072,DECODE:24}
TABLES = {
    FINISH: ('1601000021010000570100003701000026010000310100004a010000',((261,0),)),
    REHASH: ('0201000001010000190300001d0300001201000011010000be020000'
             '680100006701000003030000070300007801000077010000f0020000'
             '400200004902000003030000070300005002000059020000ef030000',((231,0),(338,28),(559,56))),
}

# Exact contiguous normalized assembler lines, independently of full body pins.
# Label references retain the reviewed destinations; this is a saved-artifact
# inspection aid, not a compiler-independent symbolic interpreter.
SEQUENCES = {
    DECODE:(
        'movq 8(%r8), %rax|testq %rax, %rax|je .LBB26_18|cmpq $13, (%r8)|jne .LBB26_18|cmpq $1, 48(%r8)|jne .LBB26_18|cmpq $0, 56(%r8)|jne .LBB26_18',
        'leaq -17(%rdx), %r10|cmpq $-6, %r10|setae %r10b|cmpq $1025, %r9|setb %r11b|testb %r11b, %r10b|jne .LBB26_6',
        'movq 32(%r8), %r10|cmpq $255, %r10|jbe .LBB26_8',
        'movq %r11, %rdi|addq %r9, %rdi|jb .LBB26_5|xorb %bl, %sil|jne .LBB26_5',
        'movl $51200, %esi|btq %rdx, %rsi|jae .LBB26_17',
        'testl $65534, %esi|movl $65535, %ebx|cmovnel %ebx, %esi|cmpw $-1, %di|cmovel %ebx, %esi',
        'testq %r9, %r9|je .LBB26_30|leal -9(%r10), %esi|cmpb $-9, %sil|jbe .LBB26_7',
        'movq %r10, %rsi|orq %r9, %rsi|jne .LBB26_5',
        'cmpq $8, %r10|jne .LBB26_7|jmp .LBB26_31',
        'movq %rdx, 8(%rcx)|movq %rax, 16(%rcx)|movq %r8, 24(%rcx)|movq %r9, 32(%rcx)|movq %r11, 40(%rcx)|movb %r10b, 48(%rcx)',
    ),
    BEGIN:(
        'xorl %r9d, %r9d|callq '+life.OPERATION,
        'testl $65534, %edi|movl $65535, %ecx|cmovnel %ecx, %edi|cmpw $-1, %ax|cmovel %ecx, %edi|cmpw $-1, %di|je .LBB28_6',
        'leaq 49(%rsp), %rdx|leaq 2033(%rsp), %rcx|movl $1983, %r8d|callq memcpy',
        'movl %edi, 2048(%rsi)|movb $1, 2052(%rsi)|movb $-1, %al',
        'movb $2, 8(%rax)|movq $3, (%rax)',
        'movb $3, 2052(%rsi)|movl %ebx, %eax',
    ),
    UPDATE:(
        'movb $1, %r9b|callq '+life.OPERATION,
        'leaq 16(%rsi), %rcx|movq %rbx, %rdx|movq %rdi, %r8|callq '+engine.shapes.UPDATE,
        'movl %eax, %ecx|movb $6, %al|cmpb $-1, %cl|je .LBB37_4',
        'movb $2, 8(%rax)|movq $3, (%rax)',
        'movb $3, 2052(%rsi)|movl %ebx, %eax|jmp .LBB37_5',
    ),
    FINISH:(
        'movb $1, %r9b|callq '+life.OPERATION,
        'leal -1(%rbx), %ecx|movb $4, %al|cmpb $7, %cl|ja .LBB34_11',
        'callq '+PREDICATE+'|movl %eax, %ecx|movb $4, %al|cmpl $1, %ecx|jne .LBB34_11',
        'movq %rax, 1928(%rbp)|movb %bl, 1936(%rbp)|movq %rsi, 1912(%rbp)|movb %dil, 1920(%rbp)',
        'movq $2, (%r15)|vpxor '+life.NONE+'(%rip), %xmm0, %xmm0|movq $0, 8(%r15)',
        'cmpl $33, %esi|jae .LBB34_26',
        'movb $2, 2052(%r15)|movb $-1, %al|jmp .LBB34_31',
        'leaq 2000(%r15), %rcx|movl $32, %edx|callq '+life.bounded.CLEAR,
        'movb $2, 8(%rax)|movq $3, (%rax)',
        'movb $3, 2052(%r15)|movl %esi, %eax',
    ),
    REHASH:(
        'movl $4136, %eax|callq __chkstk|subq %rax, %rsp',
        'movb $2, %r9b|callq '+life.OPERATION,
        'vpxor %xmm0, %xmm0, %xmm0|vmovdqu %ymm0, 3904(%rbp)',
        'leaq -96(%rbp), %rcx|leaq 3944(%rbp), %rdx|leaq 3904(%rbp), %r8|movq %rdi, %r9|callq '+state.FINISH,
        'movl $32, %edx|movq 3976(%rbp), %rcx|callq '+life.bounded.CLEAR,
        'leaq 3904(%rbp), %r8|movq 3976(%rbp), %rcx|movq %rbx, %rdx|movq %rdi, %r9|callq '+state.COPY,
        'movl %esi, 2048(%r14)|leaq 3904(%rbp), %rcx|movl $32, %edx|callq '+life.bounded.CLEAR+'|movb $-1, %bl',
        'leaq 3904(%rbp), %rcx|movl $32, %edx|vzeroupper|callq '+life.bounded.CLEAR,
        'movb $2, 8(%rax)|movq $3, (%rax)',
        'movb $3, 2052(%r14)',
    ),
    FINISH_DROP:('movq 1944(%rbp), %rcx|movzbl 1959(%rbp), %edx|callq '+life.GUARD,),
    REHASH_DROP:('leaq 3904(%rbp), %rcx|movl $32, %edx|callq '+life.bounded.CLEAR,
                 'movq 3984(%rbp), %rcx|movzbl 3999(%rbp), %edx|callq '+life.GUARD),
    PREDICATE:('movzbl (%rcx), %r10d|andl %edx, %r10d|sete %al|movzbl %al, %eax',
               'xorl %r10d, %r10d'),
}
