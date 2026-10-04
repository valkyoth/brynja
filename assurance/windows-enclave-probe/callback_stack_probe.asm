; Diagnostic only: return the actual call-entry RSP, no spills or frame.
PUBLIC PrivateCallbackStack
.code
PrivateCallbackStack PROC
    mov rax, rsp
    ret
PrivateCallbackStack ENDP
END
