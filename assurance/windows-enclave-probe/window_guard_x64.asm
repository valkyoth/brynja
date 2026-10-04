; Synthetic guarded OS-stack window. Public markers only; not a Rust adapter.
EXTERN PublicLockedAdmit:PROC
EXTERN PublicLockedFinish:PROC
EXTERN PublicLockedBody:PROC
EXTERN PublicGuardRestore:PROC
EXTERN PublicLockedLow:QWORD
EXTERN PublicLockedHigh:QWORD
EXTERN __chkstk:PROC
PUBLIC PublicLockedFrame
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
PublicLockedFrame PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    .endprolog
    mov [rbp + 16], rcx
    BRYNJA_REGISTER_SETUP
    ; Includes alignment slack, both boundary pages, and bootstrap shadow space.
    mov rax, 81952
    call __chkstk
    sub rsp, rax
    mov rax, rbp
    and rax, -4096
    sub rax, 4096
    mov PublicLockedHigh, rax
    sub rax, 65536
    mov PublicLockedLow, rax
    lea rsp, [rax - 4128]
    ; Both page protections and admission are established from below the window.
    call PublicLockedAdmit
    test rax, rax
    jz guarded_denied
    mov r10, PublicLockedLow
    mov rdx, PublicLockedHigh
    mov r11, 0a5a5a5a5a5a5a5a5h
guarded_fill:
    mov [r10], r11
    add r10, 8
    cmp r10, rdx
    jb guarded_fill
    mov rcx, [rbp + 16]
    lea rsp, [rdx - 32]
    call PublicLockedBody
    mov r8, rax
    jmp guarded_reclaim
guarded_denied:
    xor r8d, r8d
guarded_reclaim:
    ; Public worker result remains in R8; no secret register spills here.
    BRYNJA_REGISTER_CLEAR 0, 1
    mov r10, PublicLockedLow
    lea rsp, [r10 - 4128]
    mov rdx, PublicLockedHigh
    xor eax, eax
IFNDEF BRYNJA_PROBE_SKIP_GUARDED_CLEAR
guarded_clear:
    mov [r10], rax
    add r10, 8
    cmp r10, rdx
    jb guarded_clear
ENDIF
    mov r10, PublicLockedLow
    xor r9d, r9d
guarded_readback:
    or r9, [r10]
    add r10, 8
    cmp r10, rdx
    jb guarded_readback
    test r9, r9
    jnz guarded_dirty
    mov rcx, r8
    or rcx, 64
    call PublicLockedFinish
    jmp guarded_restore
guarded_dirty:
    xor eax, eax
guarded_restore:
    mov [rbp + 24], rax
    ; Restoring page access is not clearing; dirty mutants retain host locks.
    call PublicGuardRestore
    test rax, rax
    jz guarded_return
    mov rax, [rbp + 24]
guarded_return:
    ; Preserve the public scalar return, clear volatile callback residue.
    BRYNJA_REGISTER_CLEAR 1, 0
    lea rsp, [rbp]
    pop rbp
    ret
PublicLockedFrame ENDP
END
