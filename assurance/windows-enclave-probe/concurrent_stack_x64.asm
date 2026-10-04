; Public-marker experiment. Slot pointer and saved state stay below/above the
; window; no shared stack-bound globals. Not arbitrary unwind qualification.
EXTERN PublicStackAdmit:PROC
EXTERN PublicStackBody:PROC
EXTERN PublicStackFinish:PROC
EXTERN PublicStackRestore:PROC
EXTERN __chkstk:PROC
PUBLIC PublicStackFrame
; Baseline-x64 wrapper cleanup, not authority to enter an accelerated worker.
; Cache CPU/OS AVX state BEFORE processing. Preserve RBX across CPUID in R10,
; not a new stack spill. Deployment stability is required.
BRYNJA_REGISTER_SETUP MACRO
    LOCAL ready
    mov QWORD PTR [rbp + 32], 0
    mov r10, rbx
    mov eax, 1
    cpuid
    and ecx, 01c000000h
    cmp ecx, 01c000000h
    jne ready
    xor ecx, ecx
    xgetbv
    and eax, 6
    cmp eax, 6
    jne ready
    mov QWORD PTR [rbp + 32], 1
ready:
    mov rbx, r10
    xor r10d, r10d
ENDM

; XMM6..15 are nonvolatile: never erase their low halves. VZEROUPPER clears
; volatile upper halves only after OSXSAVE/AVX and XCR0 XMM/YMM admission.
BRYNJA_REGISTER_CLEAR MACRO keep_rax, keep_r8
    LOCAL baseline
    cmp QWORD PTR [rbp + 32], 0
    je baseline
    vzeroupper
baseline:
    pxor xmm0, xmm0
    pxor xmm1, xmm1
    pxor xmm2, xmm2
    pxor xmm3, xmm3
    pxor xmm4, xmm4
    pxor xmm5, xmm5
    IF keep_rax EQ 0
        xor eax, eax
    ENDIF
    xor ecx, ecx
    xor edx, edx
    IF keep_r8 EQ 0
        xor r8d, r8d
    ENDIF
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
ENDM

.code
PublicStackFrame PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    .endprolog
    mov [rbp + 16], rcx
    BRYNJA_REGISTER_SETUP
    mov rax, 81952
    call __chkstk
    sub rsp, rax
    mov rax, rbp
    and rax, -4096
    sub rax, 4096
    mov r11, [rbp + 16]
    mov [r11 + 8], rax
    sub rax, 65536
    mov [r11], rax
    lea rsp, [rax - 4128]
    mov rcx, r11
    call PublicStackAdmit
    test rax, rax
    jz stack_denied
    mov r11, [rbp + 16]
    mov r10, [r11]
    mov rdx, [r11 + 8]
    mov rax, 0a5a5a5a5a5a5a5a5h
stack_fill:
    mov [r10], rax
    add r10, 8
    cmp r10, rdx
    jb stack_fill
    mov rcx, r11
    lea rsp, [rdx - 32]
    call PublicStackBody
    mov r8, rax
    jmp stack_reclaim
stack_denied:
    mov r8, -1
stack_reclaim:
    ; Public worker result remains in R8; no secret register spills here.
    BRYNJA_REGISTER_CLEAR 0, 1
    mov r11, [rbp + 16]
    mov r10, [r11]
    lea rsp, [r10 - 4128]
    mov rdx, [r11 + 8]
    xor eax, eax
IFNDEF BRYNJA_PROBE_SKIP_CONCURRENT_CLEAR
stack_clear:
    mov [r10], rax
    add r10, 8
    cmp r10, rdx
    jb stack_clear
ENDIF
    mov r10, [r11]
    xor r9d, r9d
stack_readback:
    or r9, [r10]
    add r10, 8
    cmp r10, rdx
    jb stack_readback
    test r9, r9
    jnz stack_dirty
    mov rcx, r11
    mov rdx, r8
    call PublicStackFinish
    jmp stack_restore
stack_dirty:
    mov rax, -1
stack_restore:
    mov [rbp + 24], rax
    mov rcx, [rbp + 16]
    call PublicStackRestore
    test rax, rax
    jz stack_failed
    mov rax, [rbp + 24]
    jmp stack_return
stack_failed:
    mov rax, -1
stack_return:
    ; Preserve the public scalar return, clear volatile callback residue.
    BRYNJA_REGISTER_CLEAR 1, 0
    lea rsp, [rbp]
    pop rbp
    ret
PublicStackFrame ENDP
END
