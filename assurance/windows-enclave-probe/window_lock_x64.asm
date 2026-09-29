; Synthetic live-window residency handshake; no independent guards or secrets.
EXTERN PublicLockedAdmit:PROC
EXTERN PublicLockedFinish:PROC
EXTERN PublicLockedBody:PROC
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
    ; Public mode in this function's incoming home slot, outside the window.
    mov [rbp + 16], rcx
    mov rax, 65568
    call __chkstk
    sub rsp, rax
    lea rax, [rsp + 32]
    mov PublicLockedLow, rax
    mov PublicLockedHigh, rbp
    ; Callback frames stay below the prospective window. No work before reply.
    call PublicLockedAdmit
    test rax, rax
    jz admission_denied
    lea r10, [rbp - 65536]
    mov r11, 0a5a5a5a5a5a5a5a5h
fill_locked_window:
    mov [r10], r11
    add r10, 8
    cmp r10, rbp
    jb fill_locked_window
    mov rcx, [rbp + 16]
    lea rsp, [rbp - 32]
    call PublicLockedBody
    mov r8, rax
    jmp reclaim_locked_window
admission_denied:
    xor r8d, r8d
reclaim_locked_window:
    lea rsp, [rbp - 65568]
    lea r10, [rsp + 32]
    xor eax, eax
IFNDEF BRYNJA_PROBE_SKIP_LOCKED_CLEAR
clear_locked_window:
    mov [r10], rax
    add r10, 8
    cmp r10, rbp
    jb clear_locked_window
ENDIF
    lea r10, [rsp + 32]
    xor r9d, r9d
verify_locked_window:
    or r9, [r10]
    add r10, 8
    cmp r10, rbp
    jb verify_locked_window
    test r9, r9
    jnz rejected_locked_window
    mov rcx, r8
    or rcx, 64
    ; Only public result/geometry leaves after all window bytes read as zero.
    call PublicLockedFinish
    jmp return_locked_window
rejected_locked_window:
    ; No finish callback: never explicitly unlock a dirty window.
    xor eax, eax
return_locked_window:
    lea rsp, [rbp]
    pop rbp
    ret
PublicLockedFrame ENDP
END
