; Synthetic fixed-target experiment: normal OS stack, public markers only.
; No guards, residency or Rust-unwind claims. Never a production trampoline.
EXTERN PublicWindowBody:PROC
EXTERN __chkstk:PROC
EXTERN PublicWindowLow:QWORD
EXTERN PublicWindowHigh:QWORD
PUBLIC PublicWindowFrame
.code
PublicWindowFrame PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    .endprolog
    ; Dynamically reserve/probe below the fixed frame without changing TEB data.
    mov rax, 65536
    call __chkstk
    sub rsp, rax
    mov PublicWindowLow, rsp
    mov PublicWindowHigh, rbp
    ; Fill while RSP covers the whole region (no red-zone assumptions).
    mov r10, rsp
    mov r11, 0a5a5a5a5a5a5a5a5h
fill_window:
    mov [r10], r11
    add r10, 8
    cmp r10, rbp
    jb fill_window
    ; RCX still holds the public mode. Fixed body catches its own exact SEH.
    lea rsp, [rbp - 32]
    call PublicWindowBody
    mov r8, rax
    ; Reclaim the entire window before reading/writing below the returned RSP.
    lea rsp, [rbp - 65536]
    mov r10, rsp
    xor eax, eax
IFNDEF BRYNJA_PROBE_SKIP_WINDOW_CLEAR
clear_window:
    mov [r10], rax
    add r10, 8
    cmp r10, rbp
    jb clear_window
ENDIF
    mov r10, rsp
    xor r9d, r9d
verify_window:
    or r9, [r10]
    add r10, 8
    cmp r10, rbp
    jb verify_window
    test r9, r9
    jnz rejected_window
    mov rax, r8
    or rax, 64
    jmp return_window
rejected_window:
    xor eax, eax
return_window:
    lea rsp, [rbp]
    pop rbp
    ret
PublicWindowFrame ENDP
END
