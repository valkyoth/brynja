// Test-only leaf functions. The baseline executable has no vector requirement;
// each extension is local to its positive probe. Use only caller-saved registers.
.text
.option push
.option arch, +v,+zvkg
.balign 4
.global probe_vlenb
probe_vlenb:
    csrr a0, vlenb
    ret

.global probe_zvkg
probe_zvkg:
    li t0, 4
    vsetvli t1, t0, e32, m1, ta, ma
    bne t0, t1, 1f
    vle32.v v8, (a0)
    vle32.v v9, (a1)
    vgmul.vv v9, v8
    vse32.v v9, (a3)
    vle32.v v10, (a2)
    vghsh.vv v9, v8, v10
    addi a3, a3, 16
    vse32.v v9, (a3)
1:  mv a0, t1
    ret
.option pop

.option push
.option arch, +v,+zvbc
.balign 4
.global probe_zvbc
probe_zvbc:
    li t0, 1
    vsetvli t1, t0, e64, m1, ta, ma
    bne t0, t1, 2f
    vle64.v v8, (a0)
    vle64.v v9, (a1)
    vclmul.vv v10, v8, v9
    vclmulh.vv v11, v8, v9
    vse64.v v10, (a2)
    addi a2, a2, 8
    vse64.v v11, (a2)
2:  mv a0, t1
    ret
.option pop
