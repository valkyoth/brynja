// Public-input probe; standard scalar ABI, Linux RV64 with full V.
// a0 = 5 x 4 u32 message limbs; a1 = 9 x 4 u32 weights; a2 = 5 u64 sums.
.text
.option push
.option arch, +v
.p2align 2
.global brynja_probe_poly1305_rvv_columns
.hidden brynja_probe_poly1305_rvv_columns
.type brynja_probe_poly1305_rvv_columns,@function
brynja_probe_poly1305_rvv_columns:
    vsetivli zero, 4, e32, m1, ta, ma
    .irp r,0,1,2,3,4
        vle32.v v\r, (a0)
        addi a0, a0, 16
    .endr
    .irp r,5,6,7,8,9,10,11,12,13
        vle32.v v\r, (a1)
        addi a1, a1, 16
    .endr
    .macro column dest,a,b,c,d,e
        vwmulu.vv \dest,v0,\a
        vwmaccu.vv \dest,v1,\b
        vwmaccu.vv \dest,v2,\c
        vwmaccu.vv \dest,v3,\d
        vwmaccu.vv \dest,v4,\e
    .endm
    // v5..9 contain r,s,t,u,v; v10..13 contain 5s,5t,5u,5v.
    column v16,v5,v13,v12,v11,v10
    column v18,v6,v5,v13,v12,v11
    column v20,v7,v6,v5,v13,v12
    column v22,v8,v7,v6,v5,v13
    column v24,v9,v8,v7,v6,v5
    .purgem column
    vsetivli zero, 4, e64, m2, ta, ma
    vmv.s.x v28, zero
    .irp r,16,18,20,22,24
        vredsum.vs v30, v\r, v28
        vmv.x.s t0, v30
        sd t0, 0(a2)
        addi a2, a2, 8
    .endr
    ret
.size brynja_probe_poly1305_rvv_columns, .-brynja_probe_poly1305_rvv_columns
.option pop
