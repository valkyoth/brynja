// Evidence fixture, standard scalar ELF calling convention. a0 points at 16
// contiguous 16-byte columns, with four u32 lanes in each. Only basic V 1.0.
.text
.option push
.option arch, +v
.p2align 2
.global brynja_probe_rvv_rounds
.hidden brynja_probe_rvv_rounds
.type brynja_probe_rvv_rounds,@function
brynja_probe_rvv_rounds:
    vsetivli zero, 4, e32, m1, ta, ma
    mv t0, a0
    .irp r,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
        vle32.v v\r, (t0)
        addi t0, t0, 16
    .endr
    .macro brynja_qr a,b,c,d
        vadd.vv \a, \a, \b
        vxor.vv \d, \d, \a
        vsll.vi v16, \d, 16
        vsrl.vi \d, \d, 16
        vor.vv \d, \d, v16
        vadd.vv \c, \c, \d
        vxor.vv \b, \b, \c
        vsll.vi v16, \b, 12
        vsrl.vi \b, \b, 20
        vor.vv \b, \b, v16
        vadd.vv \a, \a, \b
        vxor.vv \d, \d, \a
        vsll.vi v16, \d, 8
        vsrl.vi \d, \d, 24
        vor.vv \d, \d, v16
        vadd.vv \c, \c, \d
        vxor.vv \b, \b, \c
        vsll.vi v16, \b, 7
        vsrl.vi \b, \b, 25
        vor.vv \b, \b, v16
    .endm
    li t1, 10
1:
    brynja_qr v0,v4,v8,v12
    brynja_qr v1,v5,v9,v13
    brynja_qr v2,v6,v10,v14
    brynja_qr v3,v7,v11,v15
    brynja_qr v0,v5,v10,v15
    brynja_qr v1,v6,v11,v12
    brynja_qr v2,v7,v8,v13
    brynja_qr v3,v4,v9,v14
    addi t1, t1, -1
    bnez t1, 1b
    .purgem brynja_qr
    .irp r,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
        vse32.v v\r, (a0)
        addi a0, a0, 16
    .endr
    // Clear the used vector register groups at their full implemented length.
    vsetvli t0, zero, e32, m8, ta, ma
    vmv.v.i v0, 0
    vmv.v.i v8, 0
    vmv.v.i v16, 0
    ret
.size brynja_probe_rvv_rounds, .-brynja_probe_rvv_rounds
.option pop
