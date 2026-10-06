"""Reviewed emitted scalar finish within SIMD 512; private frame proof pending."""

START = ".B182"
END = ".B227"
CODE = """.B182:
leaq 4580(%rdi), %rbx
leaq 5604(%rdi), %rax
movq %rax, 1016(%rbp)
leaq 5348(%rdi), %rax
movq %rax, 1024(%rbp)
leaq 5476(%rdi), %rcx
leaq 1024(%rdi), %rax
movq %rax, 976(%rbp)
leaq 4708(%rdi), %rax
movq %rax, 968(%rbp)
xorl %r14d, %r14d
xorl %edx, %edx
movq %rbx, 760(%rbp)
movq %rcx, 928(%rbp)
jmp .B184
.B183:
addq $40, %rdx
incq %r14
cmpq $160, %rdx
je .B233
.B184:
movq 1040(%rbp), %rax
movzwl 32(%rax,%rdx), %eax
movl %eax, 1008(%rbp)
cmpl $65535, %eax
je .B183
movq %rdx, 1000(%rbp)
movq %rbx, %rcx
vzeroupper
callq {wipe}
movq %r14, 952(%rbp)
shlq $6, %r14
movq 984(%rbp), %rax
movq %r14, 992(%rbp)
leaq (%rax,%r14), %r8
movl $64, %edx
movl $64, %r9d
movq 1016(%rbp), %rcx
callq {copy}
movb $11, %r14b
cmpb $-1, %al
jne .B230
movq 1040(%rbp), %rax
movq 1000(%rbp), %r8
movq 8(%rax,%r8), %r9
movq 16(%rax,%r8), %r12
movq %r12, %r13
shrq $3, %r13
cmpq %r9, %r13
movq 1176(%rbp), %rcx
ja .B229
movq %r9, 936(%rbp)
movq 952(%rbp), %rax
movq 4544(%rdi,%rax,8), %r15
movq %r12, %rax
shrq $10, %rax
cmpq %r15, %rax
jb .B229
movq %rax, %r9
movq 1040(%rbp), %rax
movq (%rax,%r8), %rax
movq %r12, 960(%rbp)
jne .B192
.B189:
movq %r13, %r8
andq $-128, %r8
movq %rax, %r15
addq %rax, %r8
andl $127, %r13d
movq 928(%rbp), %rbx
movq %rbx, %rcx
movq %r13, %rdx
movq %r13, %r9
callq {copy}
cmpb $-1, %al
jne .B229
leaq (%rbx,%r13), %r10
movq 1040(%rbp), %rax
movq 1000(%rbp), %rcx
movzbl 24(%rax,%rcx), %ebx
testb $-9, %bl
jne .B201
movb $-128, (%r10)
movq 1176(%rbp), %rdx
jmp .B205
.B192:
movq %r13, 768(%rbp)
shlq $7, %r9
addq %rax, %r9
movq %r9, 944(%rbp)
shlq $7, %r15
movq %rax, 776(%rbp)
addq %rax, %r15
movq 800(%rbp), %rbx
movq (%rcx), %rax
movq %rax, 920(%rbp)
movq 8(%rcx), %rax
movq %rax, 1032(%rbp)
.B193:
movl $128, %edx
movl $128, %r9d
movq 1024(%rbp), %rcx
movq %r15, %r8
callq {copy}
cmpb $-1, %al
jne .B229
.Ltmp46:
movq 920(%rbp), %rcx
movq 1032(%rbp), %rax
callq *32(%rax)
nop
.Ltmp47:
testb %al, %al
jne .B227
movq 1176(%rbp), %rdx
movq 16(%rdx), %rax
testq %rax, %rax
movq 1168(%rbp), %rdi
je .B231
movq 24(%rdx), %rcx
cmpq $-1, %rcx
je .B229
incq %rcx
decq %rax
movq %rax, 16(%rdx)
movq %rcx, 24(%rdx)
movq 1016(%rbp), %rcx
movq 1024(%rbp), %r12
movq %r12, %rdx
movq 968(%rbp), %r13
movq %r13, %r8
callq {compress}
movl $640, %edx
movq %r13, %rcx
callq {zero}
movl $128, %edx
movq %r12, %rcx
callq {zero}
cmpq $-1, %rbx
je .B229
subq $-128, %r15
incq %rbx
cmpq 944(%rbp), %r15
movq 960(%rbp), %r12
jne .B193
movq %rbx, 800(%rbp)
movq 768(%rbp), %r13
movq 776(%rbp), %rax
jmp .B189
.B201:
movq 936(%rbp), %rax
testq %rax, %rax
je .B228
leaq (%r15,%rax), %r8
decq %r8
movl $1, %edx
movl $1, %r9d
movq %r10, %rdi
movq %r10, %rcx
callq {copy}
cmpb $-1, %al
jne .B228
cmpb $7, %bl
ja .B302
movb $-128, %r8b
movl %ebx, %ecx
shrb %cl, %r8b
movq %rdi, %rcx
movb $-1, %dl
callq {mask}
movq 1168(%rbp), %rdi
movq 1176(%rbp), %rdx
movq 960(%rbp), %r12
.B205:
cmpl $111, %r13d
jbe .B209
.Ltmp48:
movq %rdi, %rcx
leaq 784(%rbp), %r8
callq {padding}
nop
.Ltmp49:
cmpb $-1, %al
jne .B236
movl $128, %edx
movq 928(%rbp), %rcx
callq {zero}
movq 1168(%rbp), %rdi
movq 1176(%rbp), %rdx
.B209:
bswapq %r12
movq %r12, 5596(%rdi)
movq $0, 5588(%rdi)
.Ltmp50:
movq %rdi, %rcx
leaq 784(%rbp), %r8
callq {padding}
nop
.Ltmp51:
cmpb $-1, %al
jne .B236
movl 1008(%rbp), %eax
leaq .LJTI23_5(%rip), %rcx
movslq (%rcx,%rax,4), %rax
addq %rcx, %rax
movq 1168(%rbp), %rdi
movq 1048(%rbp), %r15
jmpq *%rax
.B212:
movw $384, %ax
jmp .B217
.B213:
movq 1040(%rbp), %rax
movq 1000(%rbp), %rcx
movzwl 34(%rax,%rcx), %eax
jmp .B217
.B214:
movw $224, %ax
jmp .B217
.B215:
movw $256, %ax
jmp .B217
.B216:
movw $512, %ax
.B217:
movzwl %ax, %edx
shrl $3, %edx
andl $7, %eax
cmpw $1, %ax
sbbw $-1, %dx
cmpw $64, %dx
ja .B230
movq 992(%rbp), %rcx
addq 976(%rbp), %rcx
movzwl %dx, %edx
movq %rcx, %rbx
movq 1016(%rbp), %r8
movq %rdx, %r9
callq {copy}
cmpb $-1, %al
jne .B230
movzwl 1008(%rbp), %eax
leaq .LJTI23_6(%rip), %rcx
movslq (%rcx,%rax,4), %rax
addq %rcx, %rax
jmpq *%rax
.B220:
movw $384, %ax
jmp .B225
.B221:
movq 1040(%rbp), %rax
movq 1000(%rbp), %rcx
movzwl 34(%rax,%rcx), %eax
testw %ax, %ax
jne .B225
jmp .B230
.B222:
movw $224, %ax
jmp .B225
.B223:
movw $256, %ax
jmp .B225
.B224:
movw $512, %ax
.B225:
movzwl %ax, %ecx
shrl $3, %ecx
andl $7, %eax
cmpw $1, %ax
sbbw $-1, %cx
cmpw $64, %cx
ja .B230
movzwl %cx, %eax
addq %rbx, %rax
decq %rax
xorl %ecx, %ecx
movq 1040(%rbp), %rdx
movq 1000(%rbp), %r14
subb 34(%rdx,%r14), %cl
andb $7, %cl
movb $-1, %dl
shlb %cl, %dl
cmpw $4, 1008(%rbp)
movzbl %dl, %edx
movl $255, %ecx
cmovnel %ecx, %edx
movq %rax, %rcx
xorl %r8d, %r8d
callq {mask}
movq 760(%rbp), %rbx
movq %rbx, %rcx
callq {wipe}
movq %r14, %rdx
movq 952(%rbp), %r14
jmp .B183
"""
