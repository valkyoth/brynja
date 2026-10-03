; Public-marker experiment. Slot pointer and saved state stay below/above the
; window; no shared stack-bound globals. Not arbitrary unwind qualification.
EXTERN PublicStackAdmit:PROC
EXTERN PublicStackBody:PROC
EXTERN PublicStackFinish:PROC
EXTERN PublicStackRestore:PROC
EXTERN __chkstk:PROC
PUBLIC PublicStackFrame
.code
PublicStackFrame PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    .endprolog
    mov [rbp + 16], rcx
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
    lea rsp, [rbp]
    pop rbp
    ret
PublicStackFrame ENDP
END
