; Public sentinel diagnostic, NOT an enclave or a cryptographic implementation.
; Links the unmodified sequential/concurrent stack wrappers. Snapshot before any
; compiler-generated callback/return code can destroy the observed registers.
EXTERN PublicLockedFrame:PROC
EXTERN PublicStackFrame:PROC
EXTERN ProbeAvx:DWORD
EXTERN ProbeConcurrent:DWORD
EXTERN ProbeDeny:DWORD
EXTERN ProbeRestoreFail:DWORD
EXTERN ProbeGpr:QWORD
EXTERN ProbeNonvolatile:BYTE
EXTERN ProbeRbx:QWORD
EXTERN ProbeBodyCalls:DWORD
EXTERN ProbeFinishCalls:DWORD
EXTERN ProbePoison:BYTE
EXTERN ProbeBody:BYTE
EXTERN ProbeRestore:BYTE
EXTERN ProbeFinish:BYTE
EXTERN ProbeReturn:BYTE
EXTERN ProbeSlot:QWORD
PUBLIC PublicLockedAdmit, PublicStackAdmit
PUBLIC PublicRustBody, PublicStackBody
PUBLIC PublicLockedFinish, PublicStackFinish
PUBLIC PublicGuardRestore, PublicStackRestore
PUBLIC ProbeRun

SNAPSHOT MACRO destination
    LOCAL narrow, done
    cmp ProbeAvx, 0
    je narrow
    vmovdqu YMMWORD PTR [destination], ymm0
    vmovdqu YMMWORD PTR [destination + 32], ymm1
    vmovdqu YMMWORD PTR [destination + 64], ymm2
    vmovdqu YMMWORD PTR [destination + 96], ymm3
    vmovdqu YMMWORD PTR [destination + 128], ymm4
    vmovdqu YMMWORD PTR [destination + 160], ymm5
    jmp done
narrow:
    movdqu XMMWORD PTR [destination], xmm0
    movdqu XMMWORD PTR [destination + 32], xmm1
    movdqu XMMWORD PTR [destination + 64], xmm2
    movdqu XMMWORD PTR [destination + 96], xmm3
    movdqu XMMWORD PTR [destination + 128], xmm4
    movdqu XMMWORD PTR [destination + 160], xmm5
done:
ENDM

POISON_VECTORS MACRO
    LOCAL narrow, done
    cmp ProbeAvx, 0
    je narrow
    vmovdqu ymm0, YMMWORD PTR ProbePoison
    vmovdqu ymm1, YMMWORD PTR ProbePoison
    vmovdqu ymm2, YMMWORD PTR ProbePoison
    vmovdqu ymm3, YMMWORD PTR ProbePoison
    vmovdqu ymm4, YMMWORD PTR ProbePoison
    vmovdqu ymm5, YMMWORD PTR ProbePoison
    ; Change only volatile upper halves of nonvolatile vector registers.
    vinsertf128 ymm6, ymm6, xmm0, 1
    vinsertf128 ymm7, ymm7, xmm0, 1
    vinsertf128 ymm8, ymm8, xmm0, 1
    vinsertf128 ymm9, ymm9, xmm0, 1
    vinsertf128 ymm10, ymm10, xmm0, 1
    vinsertf128 ymm11, ymm11, xmm0, 1
    vinsertf128 ymm12, ymm12, xmm0, 1
    vinsertf128 ymm13, ymm13, xmm0, 1
    vinsertf128 ymm14, ymm14, xmm0, 1
    vinsertf128 ymm15, ymm15, xmm0, 1
    jmp done
narrow:
    movdqu xmm0, XMMWORD PTR ProbePoison
    movdqu xmm1, XMMWORD PTR ProbePoison
    movdqu xmm2, XMMWORD PTR ProbePoison
    movdqu xmm3, XMMWORD PTR ProbePoison
    movdqu xmm4, XMMWORD PTR ProbePoison
    movdqu xmm5, XMMWORD PTR ProbePoison
done:
ENDM

.code
PublicLockedAdmit PROC
PublicStackAdmit LABEL PROC
    xor eax, eax
    cmp ProbeDeny, 0
    sete al
    ret
PublicLockedAdmit ENDP

PublicRustBody PROC
PublicStackBody LABEL PROC
    inc ProbeBodyCalls
    POISON_VECTORS
    SNAPSHOT ProbeBody
    mov eax, 37
    ret
PublicRustBody ENDP

PublicLockedFinish PROC
PublicStackFinish LABEL PROC
    SNAPSHOT ProbeFinish
    inc ProbeFinishCalls
    mov eax, 91
    ret
PublicLockedFinish ENDP

PublicGuardRestore PROC
PublicStackRestore LABEL PROC
    ; Prove the final return wipe independently of the pre-reclamation wipe.
    POISON_VECTORS
    SNAPSHOT ProbeRestore
    mov rcx, QWORD PTR ProbePoison
    mov rdx, QWORD PTR ProbePoison
    mov r8, QWORD PTR ProbePoison
    mov r9, QWORD PTR ProbePoison
    mov r10, QWORD PTR ProbePoison
    mov r11, QWORD PTR ProbePoison
    xor eax, eax
    cmp ProbeRestoreFail, 0
    sete al
    ret
PublicGuardRestore ENDP

ProbeRun PROC FRAME
    sub rsp, 216
    .allocstack 216
    mov [rsp + 192], rbx
    .savereg rbx, 192
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
    .endprolog
    mov rbx, QWORD PTR ProbePoison
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
    ; Explicit initial state distinguishes denied admission from executed body.
    cmp ProbeAvx, 0
    je initial_narrow
    vxorpd ymm0, ymm0, ymm0
    vxorpd ymm1, ymm1, ymm1
    vxorpd ymm2, ymm2, ymm2
    vxorpd ymm3, ymm3, ymm3
    vxorpd ymm4, ymm4, ymm4
    vxorpd ymm5, ymm5, ymm5
    jmp invoke
initial_narrow:
    pxor xmm0, xmm0
    pxor xmm1, xmm1
    pxor xmm2, xmm2
    pxor xmm3, xmm3
    pxor xmm4, xmm4
    pxor xmm5, xmm5
invoke:
    lea rcx, ProbeSlot
    cmp ProbeConcurrent, 0
    je sequential
    call PublicStackFrame
    jmp capture_return
sequential:
    call PublicLockedFrame
capture_return:
    SNAPSHOT ProbeReturn
    mov QWORD PTR [ProbeGpr + 0], rcx
    mov QWORD PTR [ProbeGpr + 8], rdx
    mov QWORD PTR [ProbeGpr + 16], r8
    mov QWORD PTR [ProbeGpr + 24], r9
    mov QWORD PTR [ProbeGpr + 32], r10
    mov QWORD PTR [ProbeGpr + 40], r11
    mov ProbeRbx, rbx
    cmp ProbeAvx, 0
    je nonvolatile_narrow
    vmovdqu YMMWORD PTR [ProbeNonvolatile + 0], ymm6
    vmovdqu YMMWORD PTR [ProbeNonvolatile + 32], ymm7
    vmovdqu YMMWORD PTR [ProbeNonvolatile + 64], ymm8
    vmovdqu YMMWORD PTR [ProbeNonvolatile + 96], ymm9
    vmovdqu YMMWORD PTR [ProbeNonvolatile + 128], ymm10
    vmovdqu YMMWORD PTR [ProbeNonvolatile + 160], ymm11
    vmovdqu YMMWORD PTR [ProbeNonvolatile + 192], ymm12
    vmovdqu YMMWORD PTR [ProbeNonvolatile + 224], ymm13
    vmovdqu YMMWORD PTR [ProbeNonvolatile + 256], ymm14
    vmovdqu YMMWORD PTR [ProbeNonvolatile + 288], ymm15
    jmp nonvolatile_captured
nonvolatile_narrow:
    movdqu XMMWORD PTR [ProbeNonvolatile + 0], xmm6
    movdqu XMMWORD PTR [ProbeNonvolatile + 32], xmm7
    movdqu XMMWORD PTR [ProbeNonvolatile + 64], xmm8
    movdqu XMMWORD PTR [ProbeNonvolatile + 96], xmm9
    movdqu XMMWORD PTR [ProbeNonvolatile + 128], xmm10
    movdqu XMMWORD PTR [ProbeNonvolatile + 160], xmm11
    movdqu XMMWORD PTR [ProbeNonvolatile + 192], xmm12
    movdqu XMMWORD PTR [ProbeNonvolatile + 224], xmm13
    movdqu XMMWORD PTR [ProbeNonvolatile + 256], xmm14
    movdqu XMMWORD PTR [ProbeNonvolatile + 288], xmm15
nonvolatile_captured:
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
    ; Upper halves are volatile; preserve XMM6..15 as required by Windows ABI.
    cmp ProbeAvx, 0
    je finished
    vzeroupper
finished:
    add rsp, 216
    ret
ProbeRun ENDP
END
