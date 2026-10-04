; Capture at the FIRST user callback instructions, before compiler/Python code.
; Active root tags only; no writes from concurrent leaf callbacks.
EXTERN ProbeAvx:DWORD
EXTERN ProbeHost:BYTE
EXTERN ProbeHostCount:QWORD
EXTERN ProbeTarget:QWORD
INCLUDE transition_vectors.inc
PUBLIC PublicTransitionHost
.code
PublicTransitionHost PROC
    cmp cl, 042h
    jb forward
    cmp cl, 044h
    ja forward
IFNDEF TRANSITION_SKIP_HOST
    TRANSITION_SNAPSHOT ProbeHost
ENDIF
    inc ProbeHostCount
forward:
    jmp QWORD PTR ProbeTarget
PublicTransitionHost ENDP
END
