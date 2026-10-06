"""Reviewed emitted scalar finish within SIMD 256; private frame proof pending."""

START = ".B143"
END = ".B258"
CODE = """.B143:
leaq 2920(%rbx), %rax
movq %rax, 176(%rbx)
movb %dil, 2936(%rbx)
movq %r15, 2912(%rbx)
movq 72(%rbx), %rax
movq %rax, 2920(%rbx)
leaq 7712(%rbx), %rax
movq %rax, 184(%rbx)
movq $0, 72(%rbx)
movq $0, 80(%rbx)
jmp .B146
.B144:
leaq 10792(%rbx), %rcx
callq {wipe}
.B145:
movq 80(%rbx), %rcx
addq $40, %rcx
incq 72(%rbx)
movq %rcx, 80(%rbx)
cmpq $320, %rcx
je .B178
.B146:
movq 80(%rbx), %rax
movzbl 576(%rbx,%rax), %eax
movb %al, 128(%rbx)
cmpb $2, %al
je .B145
leaq 10792(%rbx), %rcx
callq {wipe}
movq 72(%rbx), %rcx
shlq $5, %rcx
leaq 7200(%rbx), %rax
movq %rcx, 136(%rbx)
leaq (%rax,%rcx), %r8
movl $32, %edx
movl $32, %r9d
leaq 11816(%rbx), %rcx
callq {copy}
movb $11, 96(%rbx)
cmpb $-1, %al
jne .B176
movq 80(%rbx), %rax
movq 552(%rbx,%rax), %rdx
movq 560(%rbx,%rax), %rax
movq %rax, 144(%rbx)
shrq $3, %rax
movq %rax, 168(%rbx)
movq %rdx, 120(%rbx)
cmpq %rdx, %rax
ja .B176
movq 72(%rbx), %rax
movq 7968(%rbx,%rax,8), %rdi
movq 144(%rbx), %r12
shrq $9, %r12
cmpq %rdi, %r12
jb .B176
movq 80(%rbx), %rax
movq 544(%rbx,%rax), %rax
movq %rax, 112(%rbx)
jne .B154
.B151:
movq 168(%rbx), %rdx
movq %rdx, %r8
andq $-64, %r8
addq 112(%rbx), %r8
andl $63, %edx
leaq 11688(%rbx), %rcx
movq %rdx, %rsi
movq %rdx, %r9
callq {copy}
cmpb $-1, %al
jne .B176
leaq 11688(%rbx), %rax
leaq (%rax,%rsi), %r15
movq 80(%rbx), %rax
movzbl 568(%rbx,%rax), %edi
testb $-9, %dil
jne .B163
movb $-128, (%r15)
jmp .B167
.B154:
shlq $6, %r12
movq 112(%rbx), %rax
addq %rax, %r12
shlq $6, %rdi
addq %rax, %rdi
movq 2928(%rbx), %rsi
movq 240(%rbx), %rax
movq %rax, 56(%rbx)
movq 248(%rbx), %rax
movq %rax, 104(%rbx)
.B155:
movl $64, %edx
movl $64, %r9d
leaq 11560(%rbx), %rcx
movq %rdi, %r8
callq {copy}
cmpb $-1, %al
jne .B176
.Ltmp54:
movq 56(%rbx), %rcx
movq 104(%rbx), %rax
callq *32(%rax)
nop
.Ltmp55:
testb %al, %al
jne .B258
movq 256(%rbx), %rax
testq %rax, %rax
je .B175
movq 264(%rbx), %rcx
cmpq $-1, %rcx
je .B176
incq %rcx
decq %rax
movq %rax, 256(%rbx)
movq %rcx, 264(%rbx)
leaq 11816(%rbx), %rcx
leaq 11560(%rbx), %r13
movq %r13, %rdx
leaq 10920(%rbx), %r15
movq %r15, %r8
callq {compress}
movl $640, %edx
movq %r15, %rcx
callq {zero}
movl $128, %edx
movq %r13, %rcx
callq {zero}
cmpq $-1, %rsi
je .B176
addq $64, %rdi
incq %rsi
cmpq %r12, %rdi
jne .B155
movq %rsi, 2928(%rbx)
jmp .B151
.B163:
cmpq $0, 120(%rbx)
je .B176
movq 120(%rbx), %rax
movq 112(%rbx), %rcx
leaq (%rcx,%rax), %r8
decq %r8
movl $1, %edx
movl $1, %r9d
movq %r15, %rcx
callq {copy}
cmpb $-1, %al
jne .B176
cmpb $7, %dil
ja .B190
movb $-128, %dl
movl %edi, %ecx
shrb %cl, %dl
movq %r15, %rcx
callq {mask}
.B167:
cmpl $55, %esi
jbe .B171
.Ltmp56:
leaq 6688(%rbx), %rcx
leaq 240(%rbx), %rdx
leaq 2912(%rbx), %r8
callq {padding}
nop
.Ltmp57:
cmpb $-1, %al
jne .B260
movl $128, %edx
leaq 11688(%rbx), %rcx
callq {zero}
.B171:
movq 144(%rbx), %rax
bswapq %rax
movq %rax, 11744(%rbx)
.Ltmp58:
leaq 6688(%rbx), %rcx
leaq 240(%rbx), %rdx
leaq 2912(%rbx), %r8
callq {padding}
nop
.Ltmp59:
cmpb $-1, %al
jne .B260
movzbl 128(%rbx), %eax
leaq 28(,%rax,4), %rdx
leaq 7712(%rbx), %rax
movq 136(%rbx), %rcx
addq %rax, %rcx
leaq 11816(%rbx), %r8
movq %rdx, %r9
callq {copy}
cmpb $-1, %al
je .B144
jmp .B176
"""
