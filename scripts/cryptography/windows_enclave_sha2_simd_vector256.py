"""Reviewed emitted SIMD 256 vector-loop regions; not a compiler oracle.

Entry/width, iteration, pack/block/unpack and checked accounting are frozen
separately from scalar finish, frame lifetime and platform qualification.
"""

REGIONS = (
    (".B91", ".B93", """.B91:
movq 80(%rbx), %r8
movb %r8b, 11962(%rbx)
movq 88(%rbx), %rax
movzbl 17(%rax), %r13d
movl %r13d, %eax
xorl $1, %eax
movl %r13d, %edi
xorb $3, %dil
movl %r8d, %edx
movl %edi, %ecx
shrb %cl, %dl
leaq 4(,%rax,4), %rcx
movzbl %dl, %edx
movq %rcx, 56(%rbx)
decl %ecx
xorl %eax, %eax
testb %r8b, %cl
setne %al
movb $7, %cl
addq %rdx, %rax
je .B80
xorl %edx, %edx
leaq 10784(%rbx), %r8
xorl %r9d, %r9d
"""),
    (".B102", ".B106", """.B102:
testb $1, %r9b
je .B80
leaq 70(%rbx), %rcx
callq {poll}
movb $10, %cl
testb %al, %al
jne .B80
movb $2, 2936(%rbx)
vxorps %xmm0, %xmm0, %xmm0
movq 80(%rbx), %rdx
movl %edx, %eax
movl %edi, %ecx
shrb %cl, %al
vmovaps %xmm0, 2912(%rbx)
movq $0, 2928(%rbx)
movzbl %al, %eax
movq 56(%rbx), %rcx
decl %ecx
xorl %esi, %esi
testb %dl, %cl
setne %sil
addq %rax, %rsi
je .B142
movzbl %r13b, %eax
xorq $3, %rax
movq %rax, 128(%rbx)
movb $2, %dil
xorl %eax, %eax
movq $0, 112(%rbx)
xorl %r15d, %r15d
movq $0, 72(%rbx)
"""),
    (".B106", ".B142", """.B106:
movq 80(%rbx), %rcx
subq %rax, %rcx
movl $0, %edx
cmovaeq %rcx, %rdx
cmpq 56(%rbx), %rdx
jb .B143
movq 56(%rbx), %rcx
addq %rax, %rcx
movq %rcx, 168(%rbx)
decq %rsi
movq $-1, %r12
xorl %ecx, %ecx
.B108:
leaq (%rax,%rcx), %rdx
movb $11, 96(%rbx)
cmpq $7, %rdx
ja .B176
movq 104(%rbx), %rdx
movzbl (%rdx,%rcx), %edx
cmpq $7, %rdx
ja .B176
leaq (%rdx,%rdx,4), %rdx
cmpb $2, 576(%rbx,%rdx,8)
je .B176
leaq (%rbx,%rdx,8), %r8
addq $544, %r8
movq 16(%r8), %rdx
movq %rdx, %r9
shrq $3, %r9
cmpq 8(%r8), %r9
ja .B176
incq %rcx
shrq $9, %rdx
cmpq %r12, %rdx
cmovbq %rdx, %r12
cmpq %rcx, 56(%rbx)
jne .B108
testq %r12, %r12
je .B141
leaq 7456(%rbx), %rdi
xorl %r13d, %r13d
.B115:
cmpq %r13, 56(%rbx)
je .B118
movq 104(%rbx), %rax
movzbl (%rax,%r13), %r8d
cmpq $8, %r8
jae .B176
incq %r13
shll $5, %r8d
leaq 7200(%rbx), %rax
addq %rax, %r8
movl $32, %edx
movl $32, %r9d
movq %rdi, %rcx
callq {copy}
addq $32, %rdi
cmpb $-1, %al
je .B115
jmp .B176
.B118:
movq %r12, %rax
movq 128(%rbx), %rcx
shlq %cl, %rax
leaq (%r15,%r12), %rcx
movq %rcx, 176(%rbx)
addq 72(%rbx), %rax
movq %rax, 184(%rbx)
movq $0, 120(%rbx)
.B119:
movq 120(%rbx), %rax
movq %rax, 136(%rbx)
incq %rax
movq %rax, 120(%rbx)
leaq 6688(%rbx), %rdi
xorl %r13d, %r13d
.B120:
cmpq %r13, 56(%rbx)
je .B126
movq 104(%rbx), %rax
movzbl (%rax,%r13), %eax
cmpq $8, %rax
jae .B176
leaq (%rax,%rax,4), %rax
cmpb $2, 576(%rbx,%rax,8)
je .B176
leaq (%rbx,%rax,8), %rax
addq $544, %rax
movq 16(%rax), %rcx
movq %rcx, %rdx
shrq $3, %rdx
cmpq 8(%rax), %rdx
ja .B176
shrq $9, %rcx
cmpq %rcx, 136(%rbx)
jae .B176
movq 136(%rbx), %r8
shlq $6, %r8
addq (%rax), %r8
movl $64, %edx
movl $64, %r9d
movq %rdi, %rcx
callq {copy}
addq $64, %rdi
incq %r13
cmpb $-1, %al
je .B120
jmp .B176
.B126:
leaq 70(%rbx), %rcx
callq {poll}
testb %al, %al
jne .B258
movq 56(%rbx), %rax
subq %rax, 144(%rbx)
jb .B175
movq 112(%rbx), %rax
addq 56(%rbx), %rax
movq %rax, 112(%rbx)
jb .B176
movq 144(%rbx), %rax
movq %rax, 256(%rbx)
movq 112(%rbx), %rax
movq %rax, 264(%rbx)
movq 88(%rbx), %rcx
movq (%rcx), %rdi
.Ltmp52:
leaq 7456(%rbx), %rdx
leaq 6688(%rbx), %r8
movq %r14, %r9
callq {session}
nop
.Ltmp53:
cmpb $-1, %al
jne .B260
cmpq $-1, %rdi
je .B176
incq %rdi
movq 88(%rbx), %rax
cmpq %rdi, (%rax)
jne .B176
incq %r15
je .B176
movq 72(%rbx), %rax
addq 56(%rbx), %rax
movq %rax, 72(%rbx)
jb .B176
cmpq %r12, 120(%rbx)
jne .B119
movq 88(%rbx), %rax
movzbl 17(%rax), %edi
leaq 7456(%rbx), %rax
movq %rax, 72(%rbx)
xorl %r13d, %r13d
.B137:
movq 104(%rbx), %rax
movzbl (%rax,%r13), %r15d
cmpq $7, %r15
ja .B176
movl %r15d, %ecx
shll $5, %ecx
leaq 7200(%rbx), %rax
addq %rax, %rcx
movl $32, %edx
movl $32, %r9d
movq 72(%rbx), %r8
callq {copy}
cmpb $-1, %al
jne .B176
incq %r13
movq %r12, 7968(%rbx,%r15,8)
addq $32, 72(%rbx)
cmpq %r13, 56(%rbx)
jne .B137
movq 184(%rbx), %rax
movq %rax, 72(%rbx)
movq 176(%rbx), %r15
.B141:
movq 56(%rbx), %rax
addq %rax, 104(%rbx)
movq 168(%rbx), %rax
testq %rsi, %rsi
jne .B106
jmp .B143
"""),
)
