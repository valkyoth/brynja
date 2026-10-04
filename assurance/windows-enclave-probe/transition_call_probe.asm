; Public-sentinel transition experiment, NOT a production callback scrubber.
; All original nonvolatile saves stay in the admitted root window for VBS.
EXTERN ProbeAvx:DWORD
EXTERN ProbePoison:BYTE
EXTERN ProbeBefore:BYTE
EXTERN ProbeCount:QWORD
EXTERN PrivateTransitionAdmit:PROC
IFNDEF TRANSITION_DIRECT
EXTERN __imp_CallEnclave:QWORD
ENDIF
INCLUDE transition_vectors.inc
PUBLIC PrivateTransitionCall
.code
PrivateTransitionCall PROC FRAME
    sub rsp, 312
    .allocstack 312
    movdqu XMMWORD PTR [rsp + 32], xmm6
    .savexmm128 xmm6, 32
    movdqu XMMWORD PTR [rsp + 48], xmm7
    .savexmm128 xmm7, 48
    movdqu XMMWORD PTR [rsp + 64], xmm8
    .savexmm128 xmm8, 64
    movdqu XMMWORD PTR [rsp + 80], xmm9
    .savexmm128 xmm9, 80
    movdqu XMMWORD PTR [rsp + 96], xmm10
    .savexmm128 xmm10, 96
    movdqu XMMWORD PTR [rsp + 112], xmm11
    .savexmm128 xmm11, 112
    movdqu XMMWORD PTR [rsp + 128], xmm12
    .savexmm128 xmm12, 128
    movdqu XMMWORD PTR [rsp + 144], xmm13
    .savexmm128 xmm13, 144
    movdqu XMMWORD PTR [rsp + 160], xmm14
    .savexmm128 xmm14, 160
    movdqu XMMWORD PTR [rsp + 176], xmm15
    .savexmm128 xmm15, 176
    mov [rsp + 192], rbx
    .savereg rbx, 192
    mov [rsp + 200], r12
    .savereg r12, 200
    mov [rsp + 256], rbp
    .savereg rbp, 256
    mov [rsp + 264], rsi
    .savereg rsi, 264
    mov [rsp + 272], rdi
    .savereg rdi, 272
    mov [rsp + 280], r13
    .savereg r13, 280
    mov [rsp + 288], r14
    .savereg r14, 288
    mov [rsp + 296], r15
    .savereg r15, 296
    .endprolog
    mov [rsp + 208], rcx
    mov [rsp + 216], rdx
    mov [rsp + 224], r8
    mov [rsp + 232], r9
    mov QWORD PTR [rsp + 248], 0
    mov rcx, rsp
    mov edx, 312
    call PrivateTransitionAdmit
    test eax, eax
    jz denied
    cmp ProbeAvx, 0
    je admitted
    mov eax, 1
    cpuid
    and ecx, 01c000000h
    cmp ecx, 01c000000h
    jne denied
    xor ecx, ecx
    xgetbv
    and eax, 6
    cmp eax, 6
    jne denied
    mov QWORD PTR [rsp + 248], 1
admitted:
IFNDEF TRANSITION_SKIP_POISON
    TRANSITION_POISON
ENDIF
IFNDEF TRANSITION_SKIP_SNAPSHOT
    TRANSITION_SNAPSHOT ProbeBefore
ENDIF
    inc ProbeCount
    mov rcx, [rsp + 208]
    mov rdx, [rsp + 216]
    mov r8, [rsp + 224]
    mov r9, [rsp + 232]
IFDEF TRANSITION_DIRECT
    mov r9, rcx
    mov rcx, rdx
    call r9
    mov r9, [rsp + 232]
    mov [r9], rax
    mov eax, 1
ELSE
    call QWORD PTR __imp_CallEnclave
ENDIF
    jmp restore
denied:
    xor eax, eax
restore:
    mov [rsp + 240], rax
    cmp QWORD PTR [rsp + 248], 0
    je restore_narrow
    vzeroupper
restore_narrow:
    movdqu xmm6, XMMWORD PTR [rsp + 32]
    movdqu xmm7, XMMWORD PTR [rsp + 48]
    movdqu xmm8, XMMWORD PTR [rsp + 64]
    movdqu xmm9, XMMWORD PTR [rsp + 80]
    movdqu xmm10, XMMWORD PTR [rsp + 96]
    movdqu xmm11, XMMWORD PTR [rsp + 112]
    movdqu xmm12, XMMWORD PTR [rsp + 128]
    movdqu xmm13, XMMWORD PTR [rsp + 144]
    movdqu xmm14, XMMWORD PTR [rsp + 160]
    movdqu xmm15, XMMWORD PTR [rsp + 176]
    mov rbx, [rsp + 192]
    mov r12, [rsp + 200]
    mov rbp, [rsp + 256]
    mov rsi, [rsp + 264]
    mov rdi, [rsp + 272]
    mov r13, [rsp + 280]
    mov r14, [rsp + 288]
    mov r15, [rsp + 296]
    mov rax, [rsp + 240]
    ; Diagnostic copies, including saved caller state, are erased before return.
    mov r10, rsp
    mov r11d, 39
    xor edx, edx
clear_frame:
    mov [r10], rdx
    add r10, 8
    dec r11d
    jnz clear_frame
    pxor xmm0, xmm0
    pxor xmm1, xmm1
    pxor xmm2, xmm2
    pxor xmm3, xmm3
    pxor xmm4, xmm4
    pxor xmm5, xmm5
    add rsp, 312
    ret
PrivateTransitionCall ENDP
END
