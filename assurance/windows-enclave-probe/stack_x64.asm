; Synthetic experiment only. No caller callbacks, secrets or production entry.
; RCX is the checked end of the owned mapping, or zero for an OS-stack control.
; RDX is 0 or 1. Both paths use the same frame and fixed call instruction.
; RBP anchors the original frame for unwind metadata. This describes register
; restoration, NOT proof that Windows accepts exception dispatch across stacks.
EXTERN PublicStackWork:PROC
PUBLIC PublicSwitch
.code
PublicSwitch PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    .endprolog
    test rcx, rcx
    jz current_stack
    mov rsp, rcx
current_stack:
    sub rsp, 32
    mov rcx, rdx
    call PublicStackWork
    lea rsp, [rbp]
    pop rbp
    ret
PublicSwitch ENDP
END
