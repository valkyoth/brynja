"""Reviewed emitted SIMD 512 vector-loop regions; not a compiler oracle.

Entry/width, iteration, pack/block/unpack and checked accounting are frozen
separately from scalar finish, frame lifetime and platform qualification.
"""

REGIONS = (
    (".B68", ".B71", """.B68:
movq %rdx, 968(%rbp)
movb %dl, 5750(%rdi)
movq (%r15), %rax
testq %rax, %rax
movq %rcx, 944(%rbp)
je .B70
movzbl 17(%rax), %eax
xorl $1, %eax
leaq 2(,%rax,2), %rax
jmp .B71
.B70:
movl $4, %eax
"""),
    (".B126", ".B129", """.B126:
movq 1016(%rbp), %rax
movq %rax, 800(%rbp)
cmpq $0, (%r15)
je .B182
movq 1032(%rbp), %r8
rep bsfl %r8d, %ecx
movq 968(%rbp), %rdx
movl %edx, %eax
shrb %cl, %al
movzbl %al, %eax
leal -1(%r8), %ecx
xorl %r9d, %r9d
testb %dl, %cl
setne %r9b
addq %rax, %r9
je .B180
leaq 1280(%rdi), %r10
movb $2, %r13b
xorl %ebx, %ebx
movq 944(%rbp), %rax
movq %rax, 1024(%rbp)
xorl %r11d, %r11d
xorl %r12d, %r12d
movb $11, %r14b
"""),
    (".B129", ".B179", """.B129:
movq %rdx, %rax
subq %r11, %rax
movl $0, %ecx
cmovaeq %rax, %rcx
cmpl %r8d, %ecx
jb .B181
cmpq $3, %r11
ja .B230
movb %r13b, 992(%rbp)
movq %r12, 1016(%rbp)
movq %rbx, 1008(%rbp)
movq %r10, 952(%rbp)
movq %r9, 928(%rbp)
movq 944(%rbp), %rax
movzbl (%rax,%r11), %eax
cmpq $3, %rax
ja .B228
leaq (%rax,%rax,4), %rax
movq 1040(%rbp), %rcx
cmpw $-1, 32(%rcx,%rax,8)
je .B228
leaq (%rcx,%rax,8), %rcx
movq 16(%rcx), %rax
movq %rax, %rdx
shrq $3, %rdx
cmpq 8(%rcx), %rdx
ja .B228
movq %r11, %rdi
movq 944(%rbp), %rcx
movzbl 1(%rcx,%r11), %ecx
cmpq $3, %rcx
ja .B228
leaq (%rcx,%rcx,4), %rcx
movq 1040(%rbp), %rdx
cmpw $-1, 32(%rdx,%rcx,8)
je .B228
leaq (%rdx,%rcx,8), %rcx
movq 16(%rcx), %r12
movq %r12, %rdx
shrq $3, %rdx
cmpq 8(%rcx), %rdx
ja .B228
shrq $10, %rax
shrq $10, %r12
cmpq %rax, %r12
cmovaeq %rax, %r12
cmpl $2, 1032(%rbp)
je .B146
testq %rdi, %rdi
jne .B228
movq 1168(%rbp), %rax
movzbl 4578(%rax), %eax
cmpq $3, %rax
ja .B228
leaq (%rax,%rax,4), %rax
movq 1040(%rbp), %rcx
cmpw $-1, 32(%rcx,%rax,8)
je .B228
movq 1040(%rbp), %rcx
leaq (%rcx,%rax,8), %rcx
movq 16(%rcx), %rax
movq %rax, %rdx
shrq $3, %rdx
cmpq 8(%rcx), %rdx
ja .B228
shrq $10, %rax
cmpq %r12, %rax
cmovaeq %r12, %rax
movq 1168(%rbp), %rcx
movzbl 4579(%rcx), %ecx
cmpq $3, %rcx
ja .B228
leaq (%rcx,%rcx,4), %rcx
movq 1040(%rbp), %rdx
cmpw $-1, 32(%rdx,%rcx,8)
je .B228
movq 1040(%rbp), %rdx
leaq (%rdx,%rcx,8), %rcx
movq 16(%rcx), %r12
movq %r12, %rdx
shrq $3, %rdx
cmpq 8(%rcx), %rdx
ja .B228
shrq $10, %r12
cmpq %rax, %r12
cmovaeq %rax, %r12
cmpl $4, 1032(%rbp)
jne .B228
.B146:
movq 1048(%rbp), %rax
cmpq 8(%rax), %r12
jae .B148
.B147:
movq 1032(%rbp), %r8
movq %rdi, %r11
addq %r8, %r11
movq 928(%rbp), %r9
decq %r9
addq %r8, 1024(%rbp)
testq %r9, %r9
movq 1168(%rbp), %rdi
movq 1048(%rbp), %r15
movq 968(%rbp), %rdx
movq 952(%rbp), %r10
movq 1008(%rbp), %rbx
movq 1016(%rbp), %r12
movzbl 992(%rbp), %r13d
jne .B129
jmp .B181
.B148:
movq 1000(%rbp), %rbx
xorl %r13d, %r13d
movq 1024(%rbp), %r15
.B149:
cmpq %r13, 1032(%rbp)
je .B152
movzbl (%r15,%r13), %r8d
cmpq $4, %r8
jae .B228
incq %r13
shll $6, %r8d
addq 984(%rbp), %r8
movl $64, %edx
movl $64, %r9d
movq %rbx, %rcx
vzeroupper
callq {copy}
addq $64, %rbx
cmpb $-1, %al
je .B149
jmp .B228
.B152:
testq %r12, %r12
je .B173
movq 1008(%rbp), %rax
addq %r12, %rax
movq %rax, 936(%rbp)
movq 1032(%rbp), %rax
imulq %r12, %rax
addq 1016(%rbp), %rax
movq %rax, 976(%rbp)
movq $0, 992(%rbp)
.B154:
movq 992(%rbp), %rax
movq %rax, %r15
incq %rax
movq %rax, 992(%rbp)
movq 1168(%rbp), %rbx
xorl %r13d, %r13d
.B155:
cmpq %r13, 1032(%rbp)
je .B161
movq 1024(%rbp), %rax
movzbl (%rax,%r13), %eax
cmpq $4, %rax
jae .B228
leaq (%rax,%rax,4), %rax
movq 1040(%rbp), %rcx
cmpw $-1, 32(%rcx,%rax,8)
je .B228
movq 1040(%rbp), %rcx
leaq (%rcx,%rax,8), %rax
movq 16(%rax), %rcx
movq %rcx, %rdx
shrq $3, %rdx
cmpq 8(%rax), %rdx
ja .B228
shrq $10, %rcx
cmpq %rcx, %r15
jae .B228
movq %r15, %r8
shlq $7, %r8
addq (%rax), %r8
movl $128, %edx
movl $128, %r9d
movq %rbx, %rcx
vzeroupper
callq {copy}
subq $-128, %rbx
incq %r13
cmpb $-1, %al
je .B155
jmp .B228
.B161:
.Ltmp42:
movq 960(%rbp), %rcx
vzeroupper
callq *920(%rbp)
nop
.Ltmp43:
testb %al, %al
jne .B227
movq 1176(%rbp), %rax
movq 16(%rax), %rax
subq 1032(%rbp), %rax
jb .B271
movq 1176(%rbp), %rcx
movq 24(%rcx), %rcx
addq 1032(%rbp), %rcx
jb .B228
movq 1176(%rbp), %rdx
movq %rax, 16(%rdx)
movq %rcx, 24(%rdx)
movq 1048(%rbp), %rax
movq (%rax), %rcx
movq (%rcx), %rbx
.Ltmp44:
movq 1000(%rbp), %rdx
movq 1168(%rbp), %r8
movq 952(%rbp), %r9
callq {session}
nop
.Ltmp45:
cmpb $-1, %al
jne .B236
cmpq $-1, %rbx
je .B228
movq 1048(%rbp), %rax
movq (%rax), %rax
incq %rbx
cmpq %rbx, (%rax)
jne .B228
incq 1008(%rbp)
je .B228
movq 1016(%rbp), %rcx
addq 1032(%rbp), %rcx
movq %rcx, 1016(%rbp)
jb .B228
cmpq %r12, 992(%rbp)
jne .B154
movzbl 17(%rax), %eax
movb %al, 992(%rbp)
jmp .B174
.B173:
movq 1016(%rbp), %rax
movq %rax, 976(%rbp)
movq 1008(%rbp), %rax
movq %rax, 936(%rbp)
.B174:
movq 1000(%rbp), %rbx
xorl %r13d, %r13d
.B175:
movq 1024(%rbp), %rax
movzbl (%rax,%r13), %r15d
cmpq $3, %r15
ja .B228
movl %r15d, %ecx
shll $6, %ecx
addq 984(%rbp), %rcx
movl $64, %edx
movl $64, %r9d
movq %rbx, %r8
vzeroupper
callq {copy}
cmpb $-1, %al
jne .B228
incq %r13
movq 1168(%rbp), %rax
movq %r12, 4544(%rax,%r15,8)
addq $64, %rbx
cmpq %r13, 1032(%rbp)
jne .B175
movq 976(%rbp), %rax
movq %rax, 1016(%rbp)
movq 936(%rbp), %rax
movq %rax, 1008(%rbp)
jmp .B147
"""),
)
