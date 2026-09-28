; Synthetic experiment only. No caller callbacks, secrets or production entry.
; RCX is the checked, 16-byte-aligned end of the owned mapping; RDX is 0 or 1.
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
    mov rsp, rcx
    sub rsp, 32
    mov rcx, rdx
    call PublicStackWork
    lea rsp, [rbp]
    pop rbp
    ret
PublicSwitch ENDP
END
