; Public sentinel diagnostic, NOT an enclave or a cryptographic implementation.
; Links the unmodified sequential/concurrent stack wrappers. Snapshot before any
; compiler-generated callback/return code can destroy the observed registers.
EXTERN PublicLockedFrame:PROC
EXTERN PublicStackFrame:PROC
EXTERN ProbeAvx:DWORD
EXTERN ProbeConcurrent:DWORD
EXTERN ProbeDeny:DWORD
EXTERN ProbeBodyCalls:DWORD
EXTERN ProbeFinishCalls:DWORD
EXTERN ProbePoison:BYTE
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
    cmp ProbeAvx, 0
    je body_narrow
    vmovdqu ymm0, YMMWORD PTR ProbePoison
    vmovdqu ymm1, YMMWORD PTR ProbePoison
    vmovdqu ymm2, YMMWORD PTR ProbePoison
    vmovdqu ymm3, YMMWORD PTR ProbePoison
    vmovdqu ymm4, YMMWORD PTR ProbePoison
    vmovdqu ymm5, YMMWORD PTR ProbePoison
    jmp body_return
body_narrow:
    movdqu xmm0, XMMWORD PTR ProbePoison
    movdqu xmm1, XMMWORD PTR ProbePoison
    movdqu xmm2, XMMWORD PTR ProbePoison
    movdqu xmm3, XMMWORD PTR ProbePoison
    movdqu xmm4, XMMWORD PTR ProbePoison
    movdqu xmm5, XMMWORD PTR ProbePoison
body_return:
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
    mov eax, 1
    ret
PublicGuardRestore ENDP

ProbeRun PROC FRAME
    sub rsp, 40
    .allocstack 40
    .endprolog
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
    ; Upper halves are volatile; preserve XMM6..15 as required by Windows ABI.
    cmp ProbeAvx, 0
    je finished
    vzeroupper
finished:
    add rsp, 40
    ret
ProbeRun ENDP
END
