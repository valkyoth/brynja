; Diagnostic public patterns only. ProbeAvx must have CPU/OS admission.
TRANSITION_POISON MACRO
    LOCAL narrow, done
    cmp ProbeAvx, 0
    je narrow
    vmovdqu ymm0, YMMWORD PTR ProbePoison
    vmovdqu ymm1, YMMWORD PTR ProbePoison
    vmovdqu ymm2, YMMWORD PTR ProbePoison
    vmovdqu ymm3, YMMWORD PTR ProbePoison
    vmovdqu ymm4, YMMWORD PTR ProbePoison
    vmovdqu ymm5, YMMWORD PTR ProbePoison
    vmovdqu ymm6, YMMWORD PTR ProbePoison
    vmovdqu ymm7, YMMWORD PTR ProbePoison
    vmovdqu ymm8, YMMWORD PTR ProbePoison
    vmovdqu ymm9, YMMWORD PTR ProbePoison
    vmovdqu ymm10, YMMWORD PTR ProbePoison
    vmovdqu ymm11, YMMWORD PTR ProbePoison
    vmovdqu ymm12, YMMWORD PTR ProbePoison
    vmovdqu ymm13, YMMWORD PTR ProbePoison
    vmovdqu ymm14, YMMWORD PTR ProbePoison
    vmovdqu ymm15, YMMWORD PTR ProbePoison
    jmp done
narrow:
    movdqu xmm0, XMMWORD PTR ProbePoison
    movdqu xmm1, XMMWORD PTR ProbePoison
    movdqu xmm2, XMMWORD PTR ProbePoison
    movdqu xmm3, XMMWORD PTR ProbePoison
    movdqu xmm4, XMMWORD PTR ProbePoison
    movdqu xmm5, XMMWORD PTR ProbePoison
    movdqu xmm6, XMMWORD PTR ProbePoison
    movdqu xmm7, XMMWORD PTR ProbePoison
    movdqu xmm8, XMMWORD PTR ProbePoison
    movdqu xmm9, XMMWORD PTR ProbePoison
    movdqu xmm10, XMMWORD PTR ProbePoison
    movdqu xmm11, XMMWORD PTR ProbePoison
    movdqu xmm12, XMMWORD PTR ProbePoison
    movdqu xmm13, XMMWORD PTR ProbePoison
    movdqu xmm14, XMMWORD PTR ProbePoison
    movdqu xmm15, XMMWORD PTR ProbePoison
done:
    mov rbx, QWORD PTR ProbePoison
    mov r12, QWORD PTR ProbePoison
    mov r10, QWORD PTR ProbePoison
    mov r11, QWORD PTR ProbePoison
    mov rax, QWORD PTR ProbePoison
    mov rbp, QWORD PTR ProbePoison
    mov rsi, QWORD PTR ProbePoison
    mov rdi, QWORD PTR ProbePoison
    mov r13, QWORD PTR ProbePoison
    mov r14, QWORD PTR ProbePoison
    mov r15, QWORD PTR ProbePoison
ENDM
TRANSITION_SNAPSHOT MACRO destination
    LOCAL narrow, done
    mov QWORD PTR [destination + 512], rbx
    mov QWORD PTR [destination + 520], r12
    mov QWORD PTR [destination + 528], r10
    mov QWORD PTR [destination + 536], r11
    mov QWORD PTR [destination + 544], rax
    mov QWORD PTR [destination + 552], rbp
    mov QWORD PTR [destination + 560], rsi
    mov QWORD PTR [destination + 568], rdi
    mov QWORD PTR [destination + 576], r13
    mov QWORD PTR [destination + 584], r14
    mov QWORD PTR [destination + 592], r15
    cmp ProbeAvx, 0
    je narrow
    vmovdqu YMMWORD PTR [destination + 0], ymm0
    vmovdqu YMMWORD PTR [destination + 32], ymm1
    vmovdqu YMMWORD PTR [destination + 64], ymm2
    vmovdqu YMMWORD PTR [destination + 96], ymm3
    vmovdqu YMMWORD PTR [destination + 128], ymm4
    vmovdqu YMMWORD PTR [destination + 160], ymm5
    vmovdqu YMMWORD PTR [destination + 192], ymm6
    vmovdqu YMMWORD PTR [destination + 224], ymm7
    vmovdqu YMMWORD PTR [destination + 256], ymm8
    vmovdqu YMMWORD PTR [destination + 288], ymm9
    vmovdqu YMMWORD PTR [destination + 320], ymm10
    vmovdqu YMMWORD PTR [destination + 352], ymm11
    vmovdqu YMMWORD PTR [destination + 384], ymm12
    vmovdqu YMMWORD PTR [destination + 416], ymm13
    vmovdqu YMMWORD PTR [destination + 448], ymm14
    vmovdqu YMMWORD PTR [destination + 480], ymm15
    jmp done
narrow:
    movdqu XMMWORD PTR [destination + 0], xmm0
    movdqu XMMWORD PTR [destination + 32], xmm1
    movdqu XMMWORD PTR [destination + 64], xmm2
    movdqu XMMWORD PTR [destination + 96], xmm3
    movdqu XMMWORD PTR [destination + 128], xmm4
    movdqu XMMWORD PTR [destination + 160], xmm5
    movdqu XMMWORD PTR [destination + 192], xmm6
    movdqu XMMWORD PTR [destination + 224], xmm7
    movdqu XMMWORD PTR [destination + 256], xmm8
    movdqu XMMWORD PTR [destination + 288], xmm9
    movdqu XMMWORD PTR [destination + 320], xmm10
    movdqu XMMWORD PTR [destination + 352], xmm11
    movdqu XMMWORD PTR [destination + 384], xmm12
    movdqu XMMWORD PTR [destination + 416], xmm13
    movdqu XMMWORD PTR [destination + 448], xmm14
    movdqu XMMWORD PTR [destination + 480], xmm15
done:
ENDM
