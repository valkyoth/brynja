0000000100001d08 <brynja_ghash_timing::timed::he7ec93e563ecf130>:
100001d08:     	sub	sp, sp, #0xc0
100001d0c:     	stp	x22, x21, [sp, #0x90]
100001d10:     	stp	x20, x19, [sp, #0xa0]
100001d14:     	stp	x29, x30, [sp, #0xb0]
100001d18:     	add	x29, sp, #0xb0
100001d1c:     	mov	x19, x1
100001d20:     	stp	xzr, xzr, [sp]
100001d24:     	stp	xzr, xzr, [sp, #0x10]
100001d28:     	stur	x0, [x29, #-0x40]
100001d2c:     	sub	x8, x29, #0x40
100001d30:     	ldur	x20, [x29, #-0x40]
100001d34:     	mov	w22, #0x10              ; =16
100001d38:     	mov	x21, sp
100001d3c:     	mov	x0, sp
100001d40:     	mov	w1, #0x10               ; =16
100001d44:     	bl	0x100003830 <brynja_core::secret_memory_volatile::zeroize_region_volatile::hf353afdbdb331608>
100001d48:     	mov	x8, #0xa392             ; =41874
100001d4c:     	movk	x8, #0x60b6, lsl #16
100001d50:     	movk	x8, #0xdace, lsl #32
100001d54:     	movk	x8, #0x388, lsl #48
100001d58:     	mov	x9, #0xfe78             ; =65144
100001d5c:     	movk	x9, #0x71b2, lsl #16
100001d60:     	movk	x9, #0xc2b9, lsl #32
100001d64:     	movk	x9, #0xf328, lsl #48
100001d68:     	stp	x9, x8, [x29, #-0x40]
100001d6c:     	sub	x8, x29, #0x40
100001d70:     	ldp	x9, x8, [x29, #-0x40]
100001d74:     	mov	x10, #0x2c3b            ; =11323
100001d78:     	movk	x10, #0xef8a, lsl #16
100001d7c:     	movk	x10, #0x4bd4, lsl #32
100001d80:     	movk	x10, #0x66e9, lsl #48
100001d84:     	mov	x11, #0x2b2e            ; =11054
100001d88:     	movk	x11, #0xca34, lsl #16
100001d8c:     	movk	x11, #0xfa59, lsl #32
100001d90:     	movk	x11, #0x884c, lsl #48
100001d94:     	stp	x11, x10, [x29, #-0x40]
100001d98:     	sub	x10, x29, #0x40
100001d9c:     	ldp	x11, x10, [x29, #-0x40]
100001da0:     	rbit	x9, x9
100001da4:     	rbit	x8, x8
100001da8:     	rbit	x11, x11
100001dac:     	rbit	x10, x10
100001db0:     	eor	x12, x9, x8
100001db4:     	fmov	d0, x8
100001db8:     	fmov	d1, x10
100001dbc:     	pmull.1q	v0, v0, v1
100001dc0:     	mov.d	x8, v0[1]
100001dc4:     	eor	x10, x11, x10
100001dc8:     	fmov	d1, x9
100001dcc:     	fmov	d2, x11
100001dd0:     	pmull.1q	v1, v1, v2
100001dd4:     	fmov	d2, x12
100001dd8:     	fmov	d3, x10
100001ddc:     	pmull.1q	v2, v2, v3
100001de0:     	eor3.16b	v2, v0, v2, v1
100001de4:     	fmov	x9, d0
100001de8:     	mov.d	x10, v1[1]
100001dec:     	fmov	x11, d1
100001df0:     	mov.d	x12, v2[1]
100001df4:     	fmov	x13, d2
100001df8:     	eor	x11, x12, x11
100001dfc:     	extr	x12, x10, x11, #0x3f
100001e00:     	extr	x14, x10, x11, #0x3e
100001e04:     	extr	x15, x10, x11, #0x39
100001e08:     	lsr	x16, x10, #63
100001e0c:     	eor	x16, x16, x10, lsr #62
100001e10:     	eor	x16, x16, x10, lsr #57
100001e14:     	eor	x9, x9, x16, lsl #2
100001e18:     	eor	x9, x9, x16, lsl #1
100001e1c:     	eor	x9, x9, x16, lsl #7
100001e20:     	eor	x8, x8, x13
100001e24:     	eor	x8, x8, x14
100001e28:     	eor	x9, x9, x11, lsl #2
100001e2c:     	eor	x9, x9, x11, lsl #1
100001e30:     	eor	x12, x12, x15
100001e34:     	eor	x8, x8, x12
100001e38:     	eor	x9, x9, x11, lsl #7
100001e3c:     	eor	x11, x16, x11
100001e40:     	mov	x12, #0xa134            ; =41268
100001e44:     	movk	x12, #0x160d, lsl #16
100001e48:     	movk	x12, #0xcaca, lsl #32
100001e4c:     	movk	x12, #0xed7b, lsl #48
100001e50:     	eor	x10, x10, x12
100001e54:     	eor	x8, x8, x10
100001e58:     	mov	x10, #0x747a            ; =29818
100001e5c:     	movk	x10, #0x62e3, lsl #16
100001e60:     	movk	x10, #0xe89, lsl #32
100001e64:     	movk	x10, #0x1146, lsl #48
100001e68:     	eor	x10, x11, x10
100001e6c:     	eor	x9, x9, x10
100001e70:     	orr	x8, x9, x8
100001e74:     	cmp	x8, #0x0
100001e78:     	mov	w8, #0x4                ; =4
100001e7c:     	mov	w9, #0x2                ; =2
100001e80:     	csel	w8, w9, w8, eq
100001e84:     	stp	x21, xzr, [sp, #0x38]
100001e88:     	strb	w8, [sp, #0x48]
100001e8c:     	str	x20, [sp, #0x30]
100001e90:     	adrp	x8, 0x100036000 <std::sync::once_lock::OnceLock$LT$T$GT$::initialize::hd4fd922149a33959+0x54>
100001e94:     	ldr	q0, [x8, #0x640]
100001e98:     	str	q0, [sp, #0x20]
100001e9c:     	bl	0x1000308c4 <std::sys::pal::unix::time::Timespec::now::he65ceb2d6e902d9e>
100001ea0:     	mov	x20, x0
100001ea4:     	mov	x21, x1
100001ea8:     	stp	x19, x22, [x29, #-0x40]
100001eac:     	sub	x8, x29, #0x40
100001eb0:     	ldp	x1, x2, [x29, #-0x40]
100001eb4:     	add	x0, sp, #0x20
100001eb8:     	bl	0x10000389c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3>
100001ebc:     	and	w8, w0, #0xff
100001ec0:     	cmp	w8, #0x7
100001ec4:     	b.ne	0x100002188 <brynja_ghash_timing::timed::he7ec93e563ecf130+0x480>
100001ec8:     	mov	w8, #0x10               ; =16
100001ecc:     	stp	x19, x8, [x29, #-0x40]
100001ed0:     	sub	x8, x29, #0x40
100001ed4:     	ldp	x1, x2, [x29, #-0x40]
100001ed8:     	add	x0, sp, #0x20
100001edc:     	bl	0x10000389c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3>
100001ee0:     	and	w8, w0, #0xff
100001ee4:     	cmp	w8, #0x7
100001ee8:     	b.ne	0x100002188 <brynja_ghash_timing::timed::he7ec93e563ecf130+0x480>
100001eec:     	mov	w8, #0x10               ; =16
100001ef0:     	stp	x19, x8, [x29, #-0x40]
100001ef4:     	sub	x8, x29, #0x40
100001ef8:     	ldp	x1, x2, [x29, #-0x40]
100001efc:     	add	x0, sp, #0x20
100001f00:     	bl	0x10000389c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3>
100001f04:     	and	w8, w0, #0xff
100001f08:     	cmp	w8, #0x7
100001f0c:     	b.ne	0x100002188 <brynja_ghash_timing::timed::he7ec93e563ecf130+0x480>
100001f10:     	mov	w8, #0x10               ; =16
100001f14:     	stp	x19, x8, [x29, #-0x40]
100001f18:     	sub	x8, x29, #0x40
100001f1c:     	ldp	x1, x2, [x29, #-0x40]
100001f20:     	add	x0, sp, #0x20
100001f24:     	bl	0x10000389c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3>
100001f28:     	and	w8, w0, #0xff
100001f2c:     	cmp	w8, #0x7
100001f30:     	b.ne	0x100002188 <brynja_ghash_timing::timed::he7ec93e563ecf130+0x480>
100001f34:     	mov	w8, #0x10               ; =16
100001f38:     	stp	x19, x8, [x29, #-0x40]
100001f3c:     	sub	x8, x29, #0x40
100001f40:     	ldp	x1, x2, [x29, #-0x40]
100001f44:     	add	x0, sp, #0x20
100001f48:     	bl	0x10000389c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3>
100001f4c:     	and	w8, w0, #0xff
100001f50:     	cmp	w8, #0x7
100001f54:     	b.ne	0x100002188 <brynja_ghash_timing::timed::he7ec93e563ecf130+0x480>
100001f58:     	mov	w8, #0x10               ; =16
100001f5c:     	stp	x19, x8, [x29, #-0x40]
100001f60:     	sub	x8, x29, #0x40
100001f64:     	ldp	x1, x2, [x29, #-0x40]
100001f68:     	add	x0, sp, #0x20
100001f6c:     	bl	0x10000389c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3>
100001f70:     	and	w8, w0, #0xff
100001f74:     	cmp	w8, #0x7
100001f78:     	b.ne	0x100002188 <brynja_ghash_timing::timed::he7ec93e563ecf130+0x480>
100001f7c:     	mov	w8, #0x10               ; =16
100001f80:     	stp	x19, x8, [x29, #-0x40]
100001f84:     	sub	x8, x29, #0x40
100001f88:     	ldp	x1, x2, [x29, #-0x40]
100001f8c:     	add	x0, sp, #0x20
100001f90:     	bl	0x10000389c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3>
100001f94:     	and	w8, w0, #0xff
100001f98:     	cmp	w8, #0x7
100001f9c:     	b.ne	0x100002188 <brynja_ghash_timing::timed::he7ec93e563ecf130+0x480>
100001fa0:     	mov	w8, #0x10               ; =16
100001fa4:     	stp	x19, x8, [x29, #-0x40]
100001fa8:     	sub	x8, x29, #0x40
100001fac:     	ldp	x1, x2, [x29, #-0x40]
100001fb0:     	add	x0, sp, #0x20
100001fb4:     	bl	0x10000389c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3>
100001fb8:     	and	w8, w0, #0xff
100001fbc:     	cmp	w8, #0x7
100001fc0:     	b.ne	0x100002188 <brynja_ghash_timing::timed::he7ec93e563ecf130+0x480>
100001fc4:     	mov	w8, #0x10               ; =16
100001fc8:     	stp	x19, x8, [x29, #-0x40]
100001fcc:     	sub	x8, x29, #0x40
100001fd0:     	ldp	x1, x2, [x29, #-0x40]
100001fd4:     	add	x0, sp, #0x20
100001fd8:     	bl	0x10000389c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3>
100001fdc:     	and	w8, w0, #0xff
100001fe0:     	cmp	w8, #0x7
100001fe4:     	b.ne	0x100002188 <brynja_ghash_timing::timed::he7ec93e563ecf130+0x480>
100001fe8:     	mov	w8, #0x10               ; =16
100001fec:     	stp	x19, x8, [x29, #-0x40]
100001ff0:     	sub	x8, x29, #0x40
100001ff4:     	ldp	x1, x2, [x29, #-0x40]
100001ff8:     	add	x0, sp, #0x20
100001ffc:     	bl	0x10000389c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3>
100002000:     	and	w8, w0, #0xff
100002004:     	cmp	w8, #0x7
100002008:     	b.ne	0x100002188 <brynja_ghash_timing::timed::he7ec93e563ecf130+0x480>
10000200c:     	mov	w8, #0x10               ; =16
100002010:     	stp	x19, x8, [x29, #-0x40]
100002014:     	sub	x8, x29, #0x40
100002018:     	ldp	x1, x2, [x29, #-0x40]
10000201c:     	add	x0, sp, #0x20
100002020:     	bl	0x10000389c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3>
100002024:     	and	w8, w0, #0xff
100002028:     	cmp	w8, #0x7
10000202c:     	b.ne	0x100002188 <brynja_ghash_timing::timed::he7ec93e563ecf130+0x480>
100002030:     	mov	w8, #0x10               ; =16
100002034:     	stp	x19, x8, [x29, #-0x40]
100002038:     	sub	x8, x29, #0x40
10000203c:     	ldp	x1, x2, [x29, #-0x40]
100002040:     	add	x0, sp, #0x20
100002044:     	bl	0x10000389c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3>
100002048:     	and	w8, w0, #0xff
10000204c:     	cmp	w8, #0x7
100002050:     	b.ne	0x100002188 <brynja_ghash_timing::timed::he7ec93e563ecf130+0x480>
100002054:     	mov	w8, #0x10               ; =16
100002058:     	stp	x19, x8, [x29, #-0x40]
10000205c:     	sub	x8, x29, #0x40
100002060:     	ldp	x1, x2, [x29, #-0x40]
100002064:     	add	x0, sp, #0x20
100002068:     	bl	0x10000389c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3>
10000206c:     	and	w8, w0, #0xff
100002070:     	cmp	w8, #0x7
100002074:     	b.ne	0x100002188 <brynja_ghash_timing::timed::he7ec93e563ecf130+0x480>
100002078:     	mov	w8, #0x10               ; =16
10000207c:     	stp	x19, x8, [x29, #-0x40]
100002080:     	sub	x8, x29, #0x40
100002084:     	ldp	x1, x2, [x29, #-0x40]
100002088:     	add	x0, sp, #0x20
10000208c:     	bl	0x10000389c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3>
100002090:     	and	w8, w0, #0xff
100002094:     	cmp	w8, #0x7
100002098:     	b.ne	0x100002188 <brynja_ghash_timing::timed::he7ec93e563ecf130+0x480>
10000209c:     	mov	w8, #0x10               ; =16
1000020a0:     	stp	x19, x8, [x29, #-0x40]
1000020a4:     	sub	x8, x29, #0x40
1000020a8:     	ldp	x1, x2, [x29, #-0x40]
1000020ac:     	add	x0, sp, #0x20
1000020b0:     	bl	0x10000389c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3>
1000020b4:     	and	w8, w0, #0xff
1000020b8:     	cmp	w8, #0x7
1000020bc:     	b.ne	0x100002188 <brynja_ghash_timing::timed::he7ec93e563ecf130+0x480>
1000020c0:     	mov	w8, #0x10               ; =16
1000020c4:     	stp	x19, x8, [x29, #-0x40]
1000020c8:     	sub	x8, x29, #0x40
1000020cc:     	ldp	x1, x2, [x29, #-0x40]
1000020d0:     	add	x0, sp, #0x20
1000020d4:     	bl	0x10000389c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3>
1000020d8:     	and	w8, w0, #0xff
1000020dc:     	cmp	w8, #0x7
1000020e0:     	b.ne	0x100002188 <brynja_ghash_timing::timed::he7ec93e563ecf130+0x480>
1000020e4:     	sub	x0, x29, #0x40
1000020e8:     	add	x1, sp, #0x20
1000020ec:     	add	x2, sp, #0x10
1000020f0:     	bl	0x100003c44 <brynja_crypto::ghash::Ghash::finish::hc885c4f3063f18fd>
1000020f4:     	ldurb	w8, [x29, #-0x40]
1000020f8:     	cmp	w8, #0x1
1000020fc:     	b.eq	0x1000021b0 <brynja_ghash_timing::timed::he7ec93e563ecf130+0x4a8>
100002100:     	ldp	x0, x1, [x29, #-0x38]
100002104:     	cmp	x0, #0x0
100002108:     	csel	x8, xzr, x1, eq
10000210c:     	csinc	x9, x0, xzr, ne
100002110:     	stp	x9, x8, [x29, #-0x40]
100002114:     	sub	x8, x29, #0x40
100002118:     	cbz	x0, 0x100002120 <brynja_ghash_timing::timed::he7ec93e563ecf130+0x418>
10000211c:     	bl	0x100003830 <brynja_core::secret_memory_volatile::zeroize_region_volatile::hf353afdbdb331608>
100002120:     	bl	0x1000308c4 <std::sys::pal::unix::time::Timespec::now::he65ceb2d6e902d9e>
100002124:     	str	x0, [sp, #0x50]
100002128:     	str	w1, [sp, #0x58]
10000212c:     	stur	x20, [x29, #-0x50]
100002130:     	stur	w21, [x29, #-0x48]
100002134:     	sub	x0, x29, #0x40
100002138:     	add	x1, sp, #0x50
10000213c:     	sub	x2, x29, #0x50
100002140:     	bl	0x1000309dc <std::sys::pal::unix::time::Timespec::sub_timespec::h0af050d2bbca3fda>
100002144:     	ldur	w8, [x29, #-0x40]
100002148:     	ldur	x9, [x29, #-0x38]
10000214c:     	ldur	w10, [x29, #-0x30]
100002150:     	mov	w11, #0xca00            ; =51712
100002154:     	movk	w11, #0x3b9a, lsl #16
100002158:     	umulh	x12, x9, x11
10000215c:     	mul	x9, x9, x11
100002160:     	adds	x9, x9, x10
100002164:     	cinc	x10, x12, hs
100002168:     	cmp	w8, #0x0
10000216c:     	csel	x1, xzr, x10, ne
100002170:     	csel	x0, xzr, x9, ne
100002174:     	ldp	x29, x30, [sp, #0xb0]
100002178:     	ldp	x20, x19, [sp, #0xa0]
10000217c:     	ldp	x22, x21, [sp, #0x90]
100002180:     	add	sp, sp, #0xc0
100002184:     	ret
100002188:     	sturb	w0, [x29, #-0x40]
10000218c:     	adrp	x0, 0x100037000 <core::unicode::unicode_data::grapheme_extend::OFFSETS::hd3d203bdcd1ccc7d+0xcb>
100002190:     	add	x0, x0, #0xe7e
100002194:     	adrp	x3, 0x100044000 <dyld_stub_binder+0x100044000>
100002198:     	add	x3, x3, #0x0
10000219c:     	adrp	x4, 0x100044000 <dyld_stub_binder+0x100044000>
1000021a0:     	add	x4, x4, #0x98
1000021a4:     	sub	x2, x29, #0x40
1000021a8:     	mov	w1, #0x2b               ; =43
1000021ac:     	bl	0x100032058 <core::result::unwrap_failed::h61c3c2f1df5908ff>
1000021b0:     	ldurb	w8, [x29, #-0x3f]
1000021b4:     	sturb	w8, [x29, #-0x50]
1000021b8:     	adrp	x0, 0x100037000 <core::unicode::unicode_data::grapheme_extend::OFFSETS::hd3d203bdcd1ccc7d+0xcb>
1000021bc:     	add	x0, x0, #0xe7e
1000021c0:     	adrp	x3, 0x100044000 <dyld_stub_binder+0x100044000>
1000021c4:     	add	x3, x3, #0x0
1000021c8:     	adrp	x4, 0x100044000 <dyld_stub_binder+0x100044000>
1000021cc:     	add	x4, x4, #0x80
1000021d0:     	sub	x2, x29, #0x50
1000021d4:     	mov	w1, #0x2b               ; =43
1000021d8:     	bl	0x100032058 <core::result::unwrap_failed::h61c3c2f1df5908ff>
000000010000389c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3>:
10000389c:     	ldrb	w8, [x0, #0x28]
1000038a0:     	cmp	w8, #0x2
1000038a4:     	b.ne	0x1000038bc <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x20>
1000038a8:     	ldr	x8, [x0, #0x8]
1000038ac:     	subs	x8, x8, x2
1000038b0:     	b.hs	0x1000038c4 <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x28>
1000038b4:     	mov	w0, #0x5                ; =5
1000038b8:     	ret
1000038bc:     	mov	w0, #0x4                ; =4
1000038c0:     	ret
1000038c4:     	stp	x24, x23, [sp, #-0x30]!
1000038c8:     	stp	x22, x21, [sp, #0x10]
1000038cc:     	stp	x20, x19, [sp, #0x20]
1000038d0:     	cbz	x2, 0x100003c2c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x390>
1000038d4:     	add	x9, x1, x2
1000038d8:     	ldr	x4, [x0]
1000038dc:     	ldp	x11, x10, [x0, #0x10]
1000038e0:     	ldr	x12, [x0, #0x20]
1000038e4:     	add	x13, x0, #0x8
1000038e8:     	add	x14, x10, #0x1
1000038ec:     	add	x15, x10, #0x2
1000038f0:     	add	x16, x2, x1
1000038f4:     	add	x17, x10, #0x11
1000038f8:     	mov	w2, #0xf                ; =15
1000038fc:     	mov	w3, #0x20               ; =32
100003900:     	mov	w5, #0x1                ; =1
100003904:     	dup.2d	v0, x5
100003908:     	mov	x5, x4
10000390c:     	b	0x100003a00 <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x164>
100003910:     	mov	x4, #0x0                ; =0
100003914:     	mov	x5, #0x0                ; =0
100003918:     	ldp	x7, x6, [x11]
10000391c:     	ldp	x20, x19, [x10]
100003920:     	rev	x7, x7
100003924:     	rev	x6, x6
100003928:     	rev	x20, x20
10000392c:     	rev	x19, x19
100003930:     	add	x12, x12, #0x1
100003934:     	rbit	x19, x19
100003938:     	rbit	x20, x20
10000393c:     	rbit	x6, x6
100003940:     	rbit	x7, x7
100003944:     	eor	x21, x6, x7
100003948:     	fmov	d1, x7
10000394c:     	eor	x7, x19, x20
100003950:     	fmov	d2, x20
100003954:     	pmull.1q	v1, v2, v1
100003958:     	mov.d	x20, v1[1]
10000395c:     	fmov	d2, x6
100003960:     	fmov	d3, x19
100003964:     	pmull.1q	v2, v3, v2
100003968:     	mov.d	x6, v2[1]
10000396c:     	fmov	d3, x21
100003970:     	fmov	d4, x7
100003974:     	pmull.1q	v3, v4, v3
100003978:     	eor3.16b	v3, v1, v3, v2
10000397c:     	fmov	x7, d2
100003980:     	mov.d	x19, v3[1]
100003984:     	eor	x7, x19, x7
100003988:     	extr	x19, x6, x7, #0x3f
10000398c:     	fmov	x21, d3
100003990:     	extr	x22, x6, x7, #0x3e
100003994:     	extr	x23, x6, x7, #0x39
100003998:     	eor	x20, x20, x21
10000399c:     	fmov	x21, d1
1000039a0:     	eor	x20, x20, x22
1000039a4:     	lsr	x22, x6, #63
1000039a8:     	eor	x22, x22, x6, lsr #62
1000039ac:     	eor	x22, x22, x6, lsr #57
1000039b0:     	eor	x21, x21, x22, lsl #2
1000039b4:     	eor	x21, x21, x22, lsl #1
1000039b8:     	eor	x21, x21, x22, lsl #7
1000039bc:     	eor	x21, x21, x7, lsl #2
1000039c0:     	eor	x21, x21, x7, lsl #1
1000039c4:     	eor	x19, x19, x23
1000039c8:     	eor	x19, x20, x19
1000039cc:     	eor	x20, x21, x7, lsl #7
1000039d0:     	eor	x6, x19, x6
1000039d4:     	eor	x7, x22, x7
1000039d8:     	eor	x7, x20, x7
1000039dc:     	str	x12, [x0, #0x20]
1000039e0:     	rev	x7, x7
1000039e4:     	rbit	x7, x7
1000039e8:     	rev	x6, x6
1000039ec:     	rbit	x6, x6
1000039f0:     	stp	x7, x6, [x10]
1000039f4:     	str	xzr, [x0]
1000039f8:     	cmp	x9, x1
1000039fc:     	b.eq	0x100003c2c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x390>
100003a00:     	cbnz	x5, 0x100003c0c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x370>
100003a04:     	cmp	x1, x9
100003a08:     	b.eq	0x100003c2c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x390>
100003a0c:     	ldrb	w6, [x1]
100003a10:     	ldrb	w7, [x10, x5]
100003a14:     	eor	w6, w7, w6
100003a18:     	strb	w6, [x10, x5]
100003a1c:     	mvn	x6, x1
100003a20:     	add	x7, x16, x6
100003a24:     	sub	x6, x2, x5
100003a28:     	cmp	x7, x6
100003a2c:     	csel	x6, x7, x6, lo
100003a30:     	add	x6, x6, #0x1
100003a34:     	cmp	x6, #0x21
100003a38:     	b.hs	0x100003a58 <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x1bc>
100003a3c:     	mov	x6, x5
100003a40:     	add	x4, x4, #0x1
100003a44:     	add	x1, x1, #0x1
100003a48:     	str	x4, [x0]
100003a4c:     	cmp	x5, #0xf
100003a50:     	b.ne	0x100003bc8 <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x32c>
100003a54:     	b	0x100003bf4 <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x358>
100003a58:     	sub	x19, x2, x5
100003a5c:     	cmp	x7, x19
100003a60:     	csel	x7, x7, x19, lo
100003a64:     	add	x19, x15, x5
100003a68:     	add	x20, x19, x7
100003a6c:     	add	x19, x1, #0x1
100003a70:     	add	x7, x1, x7
100003a74:     	add	x21, x7, #0x2
100003a78:     	cmp	x0, x21
100003a7c:     	ccmp	x19, x13, #0x2, lo
100003a80:     	cset	w7, lo
100003a84:     	add	x22, x14, x5
100003a88:     	cmp	x22, x21
100003a8c:     	ccmp	x19, x20, #0x2, lo
100003a90:     	cset	w19, lo
100003a94:     	cmp	x22, x13
100003a98:     	ccmp	x0, x20, #0x2, lo
100003a9c:     	b.lo	0x100003a3c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x1a0>
100003aa0:     	tbnz	w7, #0x0, 0x100003a3c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x1a0>
100003aa4:     	tbnz	w19, #0x0, 0x100003a3c <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x1a0>
100003aa8:     	ands	x7, x6, #0x1f
100003aac:     	movi.2d	v2, #0000000000000000
100003ab0:     	movi.2d	v1, #0000000000000000
100003ab4:     	mov.d	v1[0], x4
100003ab8:     	csel	x4, x3, x7, eq
100003abc:     	movi.2d	v3, #0000000000000000
100003ac0:     	movi.2d	v5, #0000000000000000
100003ac4:     	sub	x4, x6, x4
100003ac8:     	add	x7, x1, x4
100003acc:     	movi.2d	v4, #0000000000000000
100003ad0:     	add	x6, x5, x4
100003ad4:     	movi.2d	v6, #0000000000000000
100003ad8:     	add	x5, x17, x5
100003adc:     	movi.2d	v7, #0000000000000000
100003ae0:     	add	x1, x1, #0x11
100003ae4:     	movi.2d	v18, #0000000000000000
100003ae8:     	movi.2d	v16, #0000000000000000
100003aec:     	movi.2d	v20, #0000000000000000
100003af0:     	movi.2d	v19, #0000000000000000
100003af4:     	movi.2d	v23, #0000000000000000
100003af8:     	movi.2d	v17, #0000000000000000
100003afc:     	movi.2d	v22, #0000000000000000
100003b00:     	movi.2d	v21, #0000000000000000
100003b04:     	movi.2d	v24, #0000000000000000
100003b08:     	add.2d	v3, v3, v0
100003b0c:     	add.2d	v2, v2, v0
100003b10:     	add.2d	v1, v1, v0
100003b14:     	add.2d	v5, v5, v0
100003b18:     	add.2d	v4, v4, v0
100003b1c:     	add.2d	v6, v6, v0
100003b20:     	add.2d	v7, v7, v0
100003b24:     	add.2d	v18, v18, v0
100003b28:     	add.2d	v19, v19, v0
100003b2c:     	add.2d	v20, v20, v0
100003b30:     	add.2d	v16, v16, v0
100003b34:     	add.2d	v23, v23, v0
100003b38:     	add.2d	v17, v17, v0
100003b3c:     	add.2d	v22, v22, v0
100003b40:     	add.2d	v21, v21, v0
100003b44:     	add.2d	v24, v24, v0
100003b48:     	ldp	q25, q26, [x1, #-0x10]
100003b4c:     	ldp	q27, q28, [x5, #-0x10]
100003b50:     	eor.16b	v25, v27, v25
100003b54:     	eor.16b	v26, v28, v26
100003b58:     	stp	q25, q26, [x5, #-0x10]
100003b5c:     	add	x5, x5, #0x20
100003b60:     	add	x1, x1, #0x20
100003b64:     	subs	x4, x4, #0x20
100003b68:     	b.ne	0x100003b08 <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x26c>
100003b6c:     	add.2d	v5, v23, v5
100003b70:     	add.2d	v18, v24, v18
100003b74:     	add.2d	v2, v20, v2
100003b78:     	add.2d	v6, v22, v6
100003b7c:     	add.2d	v3, v19, v3
100003b80:     	add.2d	v7, v21, v7
100003b84:     	add.2d	v1, v16, v1
100003b88:     	add.2d	v4, v17, v4
100003b8c:     	add.2d	v1, v1, v4
100003b90:     	add.2d	v3, v3, v7
100003b94:     	add.2d	v1, v1, v3
100003b98:     	add.2d	v2, v2, v6
100003b9c:     	add.2d	v3, v5, v18
100003ba0:     	add.2d	v2, v2, v3
100003ba4:     	add.2d	v1, v1, v2
100003ba8:     	addp.2d	d1, v1
100003bac:     	str	d1, [x0]
100003bb0:     	fmov	x4, d1
100003bb4:     	add	x4, x4, #0x1
100003bb8:     	add	x1, x7, #0x1
100003bbc:     	str	x4, [x0]
100003bc0:     	cmp	x6, #0xf
100003bc4:     	b.eq	0x100003bf4 <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x358>
100003bc8:     	cmp	x1, x9
100003bcc:     	b.eq	0x100003bf4 <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x358>
100003bd0:     	ldrb	w5, [x1], #0x1
100003bd4:     	ldrb	w7, [x14, x6]
100003bd8:     	eor	w5, w7, w5
100003bdc:     	strb	w5, [x14, x6]
100003be0:     	add	x4, x4, #0x1
100003be4:     	add	x6, x6, #0x1
100003be8:     	str	x4, [x0]
100003bec:     	cmp	x6, #0xf
100003bf0:     	b.ne	0x100003bc8 <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x32c>
100003bf4:     	mov	x5, x4
100003bf8:     	cmp	x5, #0x10
100003bfc:     	b.ne	0x1000039f8 <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x15c>
100003c00:     	cmn	x12, #0x1
100003c04:     	b.eq	0x100003c18 <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x37c>
100003c08:     	b	0x100003910 <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x74>
100003c0c:     	cmp	x5, #0xf
100003c10:     	b.ls	0x100003a04 <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x168>
100003c14:     	b	0x100003bf8 <brynja_crypto::ghash::Ghash::update::hc60ffc67be082db3+0x35c>
100003c18:     	mov	w0, #0x4                ; =4
100003c1c:     	ldp	x20, x19, [sp, #0x20]
100003c20:     	ldp	x22, x21, [sp, #0x10]
100003c24:     	ldp	x24, x23, [sp], #0x30
100003c28:     	ret
100003c2c:     	str	x8, [x0, #0x8]
100003c30:     	mov	w0, #0x7                ; =7
100003c34:     	ldp	x20, x19, [sp, #0x20]
100003c38:     	ldp	x22, x21, [sp, #0x10]
100003c3c:     	ldp	x24, x23, [sp], #0x30
100003c40:     	ret
