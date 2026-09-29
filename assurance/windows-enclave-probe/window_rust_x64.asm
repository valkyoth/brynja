; Synthetic guarded OS-stack window. Public markers only; not a Rust adapter.
EXTERN PublicLockedAdmit:PROC
EXTERN PublicLockedFinish:PROC
EXTERN PublicRustBody:PROC
EXTERN PublicGuardRestore:PROC
EXTERN PublicLockedLow:QWORD
EXTERN PublicLockedHigh:QWORD
EXTERN __chkstk:PROC
PUBLIC PublicLockedFrame
.code
PublicLockedFrame PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    .endprolog
    mov [rbp + 16], rcx
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
    call PublicRustBody
    mov r8, rax
    jmp guarded_reclaim
guarded_denied:
    xor r8d, r8d
guarded_reclaim:
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
    lea rsp, [rbp]
    pop rbp
    ret
PublicLockedFrame ENDP
END
