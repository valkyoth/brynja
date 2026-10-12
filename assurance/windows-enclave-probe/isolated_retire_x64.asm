; Private experiment leaf. RCX is one live, writable, exclusively owned 4096-byte
; enclave page. No SDK, stack traffic, vector register, or caller payload read.
; Dirty readback terminates before unlock/free/SDK; it is not successful cleanup.
OPTION CASEMAP:NONE
.code
PUBLIC IsolatedRetirePage
IsolatedRetirePage PROC
    xor eax, eax
    mov edx, 4096
IFNDEF BRYNJA_PROBE_SKIP_STAGE_CLEAR
stage_clear:
    mov qword ptr [rcx+rdx-8], rax
    sub rdx, 8
    jne stage_clear
ENDIF
    xor r8d, r8d
    mov edx, 4096
stage_readback:
    or r8, qword ptr [rcx+rdx-8]
    sub rdx, 8
    jne stage_readback
    test r8, r8
    jne stage_dirty
    xor eax, eax
    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    ret
stage_dirty:
    mov ecx, 7
    int 29h
    jmp stage_dirty
IsolatedRetirePage ENDP
END
