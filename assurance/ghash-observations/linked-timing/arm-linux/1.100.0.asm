0000000000221744 <brynja_ghash_timing::timed>:
  221744:      	sub	sp, sp, #0x130
  221748:      	stp	x29, x30, [sp, #0xd0]
  22174c:      	stp	x28, x27, [sp, #0xe0]
  221750:      	stp	x26, x25, [sp, #0xf0]
  221754:      	stp	x24, x23, [sp, #0x100]
  221758:      	stp	x22, x21, [sp, #0x110]
  22175c:      	stp	x20, x19, [sp, #0x120]
  221760:      	add	x29, sp, #0xd0
  221764:      	stp	xzr, xzr, [sp, #0x40]
  221768:      	sub	x8, x29, #0x18
  22176c:      	mov	x21, x1
  221770:      	stp	xzr, xzr, [sp, #0x50]
  221774:      	mov	w1, #0x10               // =16
  221778:      	stur	x0, [x29, #-0x18]
  22177c:      	add	x0, sp, #0x40
  221780:      	ldur	x8, [x29, #-0x18]
  221784:      	str	x8, [sp, #0x38]
  221788:      	bl	0x226598 <brynja_core::secret_memory_volatile::zeroize_region_volatile>
  22178c:      	adrp	x20, 0x28b000 <<std::backtrace_rs::symbolize::gimli::Cache>::with_global::MAPPINGS_CACHE+0x328>
  221790:      	ldr	x8, [x20, #0x8f0]
  221794:      	cbz	x8, 0x22183c <brynja_ghash_timing::timed+0xf8>
  221798:      	ubfx	x19, x8, #3, #1
  22179c:      	ldr	x8, [x20, #0x8f0]
  2217a0:      	cbz	x8, 0x22184c <brynja_ghash_timing::timed+0x108>
  2217a4:      	ubfx	x8, x8, #1, #1
  2217a8:      	tst	w19, w8
  2217ac:      	b.eq	0x22185c <brynja_ghash_timing::timed+0x118>
  2217b0:      	mov	x8, #0xa392             // =41874
  2217b4:      	mov	x9, #0xfe78             // =65144
  2217b8:      	mov	x10, #0x2c3b            // =11323
  2217bc:      	movk	x8, #0x60b6, lsl #16
  2217c0:      	movk	x9, #0x71b2, lsl #16
  2217c4:      	movk	x10, #0xef8a, lsl #16
  2217c8:      	movk	x8, #0xdace, lsl #32
  2217cc:      	movk	x9, #0xc2b9, lsl #32
  2217d0:      	movk	x10, #0x4bd4, lsl #32
  2217d4:      	movk	x8, #0x388, lsl #48
  2217d8:      	movk	x9, #0xf328, lsl #48
  2217dc:      	movk	x10, #0x66e9, lsl #48
  2217e0:      	stp	x9, x8, [sp, #0x60]
  2217e4:      	mov	x9, #0x2b2e             // =11054
  2217e8:      	add	x8, sp, #0x60
  2217ec:      	movk	x9, #0xca34, lsl #16
  2217f0:      	sub	x8, x29, #0x50
  2217f4:      	movk	x9, #0xfa59, lsl #32
  2217f8:      	movk	x9, #0x884c, lsl #48
  2217fc:      	stp	x9, x10, [x29, #-0x50]
  221800:      	ldp	x0, x1, [sp, #0x60]
  221804:      	ldp	x2, x3, [x29, #-0x50]
  221808:      	bl	0x2266ac <brynja_crypto_cpu::ghash_pmull::multiply>
  22180c:      	mov	x8, #0xdeb7             // =57015
  221810:      	movk	x8, #0x5353, lsl #16
  221814:      	movk	x8, #0xb068, lsl #32
  221818:      	movk	x8, #0x2c85, lsl #48
  22181c:      	cmp	x0, x8
  221820:      	mov	x8, #0x6288             // =25224
  221824:      	movk	x8, #0x9170, lsl #16
  221828:      	movk	x8, #0xc746, lsl #32
  22182c:      	movk	x8, #0x5e2e, lsl #48
  221830:      	ccmp	x1, x8, #0x0, eq
  221834:      	cset	w19, eq
  221838:      	b	0x221860 <brynja_ghash_timing::timed+0x11c>
  22183c:      	bl	0x254df4 <std_detect::detect::cache::detect_and_initialize>
  221840:      	ubfx	x19, x0, #3, #1
  221844:      	ldr	x8, [x20, #0x8f0]
  221848:      	cbnz	x8, 0x2217a4 <brynja_ghash_timing::timed+0x60>
  22184c:      	bl	0x254df4 <std_detect::detect::cache::detect_and_initialize>
  221850:      	ubfx	x8, x0, #1, #1
  221854:      	tst	w19, w8
  221858:      	b.ne	0x2217b0 <brynja_ghash_timing::timed+0x6c>
  22185c:      	mov	w19, wzr
  221860:      	bl	0x2539b4 <<std::sys::pal::unix::time::Timespec>::now>
  221864:      	mov	w8, #0x10               // =16
  221868:      	stp	x21, x8, [x29, #-0x50]
  22186c:      	sub	x8, x29, #0x50
  221870:      	cbz	w19, 0x223d48 <brynja_ghash_timing::timed+0x2604>
  221874:      	ldur	x24, [x29, #-0x48]
  221878:      	cmp	x24, #0x100
  22187c:      	b.hi	0x223b48 <brynja_ghash_timing::timed+0x2404>
  221880:      	mov	x23, xzr
  221884:      	mov	x8, xzr
  221888:      	str	x21, [sp, #0x20]
  22188c:      	str	w1, [sp, #0x4]
  221890:      	str	x0, [sp, #0x8]
  221894:      	cbz	x24, 0x221ac4 <brynja_ghash_timing::timed+0x380>
  221898:      	mov	w9, #0x1                // =1
  22189c:      	ldur	x21, [x29, #-0x50]
  2218a0:      	add	x25, sp, #0x40
  2218a4:      	dup	v28.2d, x9
  2218a8:      	mov	x10, xzr
  2218ac:      	add	x28, x25, #0x11
  2218b0:      	add	x26, x21, x24
  2218b4:      	add	x27, x24, x21
  2218b8:      	orr	x19, x25, #0x1
  2218bc:      	mov	w20, #0xf               // =15
  2218c0:      	mov	w22, #0x20              // =32
  2218c4:      	b	0x221910 <brynja_ghash_timing::timed+0x1cc>
  2218c8:      	ldp	x9, x10, [sp, #0x38]
  2218cc:      	add	x23, x23, #0x1
  2218d0:      	ldr	x11, [sp, #0x48]
  2218d4:      	str	q28, [sp, #0x10]
  2218d8:      	ldp	x8, x9, [x9]
  2218dc:      	rev	x0, x11
  2218e0:      	rev	x1, x10
  2218e4:      	rev	x2, x9
  2218e8:      	rev	x3, x8
  2218ec:      	bl	0x2266ac <brynja_crypto_cpu::ghash_pmull::multiply>
  2218f0:      	ldr	q28, [sp, #0x10]
  2218f4:      	mov	x8, xzr
  2218f8:      	mov	x10, xzr
  2218fc:      	rev	x9, x0
  221900:      	rev	x11, x1
  221904:      	stp	x11, x9, [sp, #0x40]
  221908:      	cmp	x26, x21
  22190c:      	b.eq	0x221ac4 <brynja_ghash_timing::timed+0x380>
  221910:      	cbnz	x10, 0x221ab8 <brynja_ghash_timing::timed+0x374>
  221914:      	cmp	x21, x26
  221918:      	b.eq	0x221ac4 <brynja_ghash_timing::timed+0x380>
  22191c:      	mvn	x9, x21
  221920:      	sub	x11, x20, x10
  221924:      	ldrb	w12, [x21]
  221928:      	add	x9, x27, x9
  22192c:      	ldrb	w13, [x25, x10]
  221930:      	cmp	x9, x11
  221934:      	csel	x9, x9, x11, lo
  221938:      	eor	w11, w13, w12
  22193c:      	strb	w11, [x25, x10]
  221940:      	cmp	x9, #0x20
  221944:      	b.hs	0x221960 <brynja_ghash_timing::timed+0x21c>
  221948:      	mov	x9, x10
  22194c:      	add	x8, x8, #0x1
  221950:      	add	x21, x21, #0x1
  221954:      	cmp	x10, #0xf
  221958:      	b.ne	0x221a78 <brynja_ghash_timing::timed+0x334>
  22195c:      	b	0x221aa0 <brynja_ghash_timing::timed+0x35c>
  221960:      	add	x9, x9, #0x1
  221964:      	movi	v0.2d, #0000000000000000
  221968:      	movi	v4.2d, #0000000000000000
  22196c:      	movi	v5.2d, #0000000000000000
  221970:      	movi	v1.2d, #0000000000000000
  221974:      	ands	x11, x9, #0x1f
  221978:      	movi	v3.2d, #0000000000000000
  22197c:      	movi	v2.2d, #0000000000000000
  221980:      	csel	x11, x22, x11, eq
  221984:      	movi	v19.2d, #0000000000000000
  221988:      	movi	v7.2d, #0000000000000000
  22198c:      	sub	x12, x9, x11
  221990:      	movi	v20.2d, #0000000000000000
  221994:      	movi	v6.2d, #0000000000000000
  221998:      	add	x11, x21, x12
  22199c:      	movi	v22.2d, #0000000000000000
  2219a0:      	movi	v17.2d, #0000000000000000
  2219a4:      	add	x9, x10, x12
  2219a8:      	movi	v18.2d, #0000000000000000
  2219ac:      	movi	v16.2d, #0000000000000000
  2219b0:      	movi	v23.2d, #0000000000000000
  2219b4:      	fmov	d21, x8
  2219b8:      	add	x8, x28, x10
  2219bc:      	add	x10, x21, #0x11
  2219c0:      	ldp	q24, q25, [x10, #-0x10]
  2219c4:      	add	v0.2d, v0.2d, v28.2d
  2219c8:      	ldp	q26, q27, [x8, #-0x10]
  2219cc:      	add	v4.2d, v4.2d, v28.2d
  2219d0:      	add	v21.2d, v21.2d, v28.2d
  2219d4:      	add	v5.2d, v5.2d, v28.2d
  2219d8:      	add	v1.2d, v1.2d, v28.2d
  2219dc:      	add	v3.2d, v3.2d, v28.2d
  2219e0:      	add	v2.2d, v2.2d, v28.2d
  2219e4:      	add	v19.2d, v19.2d, v28.2d
  2219e8:      	eor	v24.16b, v26.16b, v24.16b
  2219ec:      	eor	v25.16b, v27.16b, v25.16b
  2219f0:      	subs	x12, x12, #0x20
  2219f4:      	add	v6.2d, v6.2d, v28.2d
  2219f8:      	add	v20.2d, v20.2d, v28.2d
  2219fc:      	add	x10, x10, #0x20
  221a00:      	add	v7.2d, v7.2d, v28.2d
  221a04:      	add	v22.2d, v22.2d, v28.2d
  221a08:      	add	v17.2d, v17.2d, v28.2d
  221a0c:      	add	v18.2d, v18.2d, v28.2d
  221a10:      	stp	q24, q25, [x8, #-0x10]
  221a14:      	add	x8, x8, #0x20
  221a18:      	add	v16.2d, v16.2d, v28.2d
  221a1c:      	add	v23.2d, v23.2d, v28.2d
  221a20:      	b.ne	0x2219c0 <brynja_ghash_timing::timed+0x27c>
  221a24:      	add	v5.2d, v22.2d, v5.2d
  221a28:      	add	v19.2d, v23.2d, v19.2d
  221a2c:      	add	v4.2d, v20.2d, v4.2d
  221a30:      	add	v7.2d, v7.2d, v21.2d
  221a34:      	add	v1.2d, v17.2d, v1.2d
  221a38:      	add	v3.2d, v18.2d, v3.2d
  221a3c:      	add	v0.2d, v6.2d, v0.2d
  221a40:      	add	v2.2d, v16.2d, v2.2d
  221a44:      	add	v1.2d, v7.2d, v1.2d
  221a48:      	add	v0.2d, v0.2d, v2.2d
  221a4c:      	add	v2.2d, v4.2d, v3.2d
  221a50:      	add	v3.2d, v5.2d, v19.2d
  221a54:      	add	v0.2d, v1.2d, v0.2d
  221a58:      	add	v1.2d, v2.2d, v3.2d
  221a5c:      	add	v0.2d, v0.2d, v1.2d
  221a60:      	addp	d0, v0.2d
  221a64:      	fmov	x8, d0
  221a68:      	add	x8, x8, #0x1
  221a6c:      	add	x21, x11, #0x1
  221a70:      	cmp	x9, #0xf
  221a74:      	b.eq	0x221aa0 <brynja_ghash_timing::timed+0x35c>
  221a78:      	cmp	x21, x26
  221a7c:      	b.eq	0x221aa0 <brynja_ghash_timing::timed+0x35c>
  221a80:      	ldrb	w10, [x21], #0x1
  221a84:      	ldrb	w11, [x19, x9]
  221a88:      	add	x8, x8, #0x1
  221a8c:      	eor	w10, w11, w10
  221a90:      	strb	w10, [x19, x9]
  221a94:      	add	x9, x9, #0x1
  221a98:      	cmp	x9, #0xf
  221a9c:      	b.ne	0x221a78 <brynja_ghash_timing::timed+0x334>
  221aa0:      	mov	x10, x8
  221aa4:      	cmp	x10, #0x10
  221aa8:      	b.ne	0x221908 <brynja_ghash_timing::timed+0x1c4>
  221aac:      	cmn	x23, #0x1
  221ab0:      	b.eq	0x223d48 <brynja_ghash_timing::timed+0x2604>
  221ab4:      	b	0x2218c8 <brynja_ghash_timing::timed+0x184>
  221ab8:      	cmp	x10, #0xf
  221abc:      	b.ls	0x221914 <brynja_ghash_timing::timed+0x1d0>
  221ac0:      	b	0x221aa4 <brynja_ghash_timing::timed+0x360>
  221ac4:      	ldr	x10, [sp, #0x20]
  221ac8:      	mov	w9, #0x10               // =16
  221acc:      	stp	x10, x9, [x29, #-0x50]
  221ad0:      	sub	x9, x29, #0x50
  221ad4:      	mov	w10, #0x100             // =256
  221ad8:      	sub	x10, x10, x24
  221adc:      	ldur	x9, [x29, #-0x48]
  221ae0:      	subs	x24, x10, x9
  221ae4:      	b.lo	0x223b48 <brynja_ghash_timing::timed+0x2404>
  221ae8:      	cbz	x9, 0x221d18 <brynja_ghash_timing::timed+0x5d4>
  221aec:      	mov	w10, #0x1               // =1
  221af0:      	ldur	x21, [x29, #-0x50]
  221af4:      	add	x25, sp, #0x40
  221af8:      	dup	v28.2d, x10
  221afc:      	add	x19, x25, #0x11
  221b00:      	orr	x28, x25, #0x1
  221b04:      	add	x26, x21, x9
  221b08:      	add	x27, x9, x21
  221b0c:      	mov	w20, #0xf               // =15
  221b10:      	mov	w22, #0x20              // =32
  221b14:      	mov	x11, x8
  221b18:      	b	0x221b24 <brynja_ghash_timing::timed+0x3e0>
  221b1c:      	cmp	x26, x21
  221b20:      	b.eq	0x221d18 <brynja_ghash_timing::timed+0x5d4>
  221b24:      	cbnz	x11, 0x221d0c <brynja_ghash_timing::timed+0x5c8>
  221b28:      	cmp	x21, x26
  221b2c:      	b.eq	0x221d18 <brynja_ghash_timing::timed+0x5d4>
  221b30:      	mvn	x9, x21
  221b34:      	sub	x10, x20, x11
  221b38:      	ldrb	w12, [x25, x11]
  221b3c:      	add	x9, x27, x9
  221b40:      	cmp	x9, x10
  221b44:      	csel	x9, x9, x10, lo
  221b48:      	ldrb	w10, [x21]
  221b4c:      	add	x9, x9, #0x1
  221b50:      	cmp	x9, #0x21
  221b54:      	eor	w10, w12, w10
  221b58:      	strb	w10, [x25, x11]
  221b5c:      	b.hs	0x221b78 <brynja_ghash_timing::timed+0x434>
  221b60:      	mov	x9, x11
  221b64:      	add	x8, x8, #0x1
  221b68:      	add	x21, x21, #0x1
  221b6c:      	cmp	x11, #0xf
  221b70:      	b.ne	0x221c8c <brynja_ghash_timing::timed+0x548>
  221b74:      	b	0x221cb4 <brynja_ghash_timing::timed+0x570>
  221b78:      	ands	x10, x9, #0x1f
  221b7c:      	movi	v0.2d, #0000000000000000
  221b80:      	movi	v4.2d, #0000000000000000
  221b84:      	movi	v6.2d, #0000000000000000
  221b88:      	movi	v1.2d, #0000000000000000
  221b8c:      	csel	x10, x22, x10, eq
  221b90:      	movi	v3.2d, #0000000000000000
  221b94:      	movi	v2.2d, #0000000000000000
  221b98:      	sub	x12, x9, x10
  221b9c:      	movi	v19.2d, #0000000000000000
  221ba0:      	movi	v7.2d, #0000000000000000
  221ba4:      	add	x10, x21, x12
  221ba8:      	movi	v20.2d, #0000000000000000
  221bac:      	movi	v5.2d, #0000000000000000
  221bb0:      	add	x9, x11, x12
  221bb4:      	movi	v22.2d, #0000000000000000
  221bb8:      	movi	v17.2d, #0000000000000000
  221bbc:      	movi	v18.2d, #0000000000000000
  221bc0:      	movi	v16.2d, #0000000000000000
  221bc4:      	movi	v23.2d, #0000000000000000
  221bc8:      	fmov	d21, x8
  221bcc:      	add	x8, x19, x11
  221bd0:      	add	x11, x21, #0x11
  221bd4:      	ldp	q24, q25, [x11, #-0x10]
  221bd8:      	add	v0.2d, v0.2d, v28.2d
  221bdc:      	ldp	q26, q27, [x8, #-0x10]
  221be0:      	add	v4.2d, v4.2d, v28.2d
  221be4:      	add	v21.2d, v21.2d, v28.2d
  221be8:      	add	v6.2d, v6.2d, v28.2d
  221bec:      	add	v1.2d, v1.2d, v28.2d
  221bf0:      	add	v3.2d, v3.2d, v28.2d
  221bf4:      	add	v2.2d, v2.2d, v28.2d
  221bf8:      	add	v19.2d, v19.2d, v28.2d
  221bfc:      	eor	v24.16b, v26.16b, v24.16b
  221c00:      	eor	v25.16b, v27.16b, v25.16b
  221c04:      	subs	x12, x12, #0x20
  221c08:      	add	v5.2d, v5.2d, v28.2d
  221c0c:      	add	v20.2d, v20.2d, v28.2d
  221c10:      	add	x11, x11, #0x20
  221c14:      	add	v7.2d, v7.2d, v28.2d
  221c18:      	add	v22.2d, v22.2d, v28.2d
  221c1c:      	add	v17.2d, v17.2d, v28.2d
  221c20:      	add	v18.2d, v18.2d, v28.2d
  221c24:      	stp	q24, q25, [x8, #-0x10]
  221c28:      	add	x8, x8, #0x20
  221c2c:      	add	v16.2d, v16.2d, v28.2d
  221c30:      	add	v23.2d, v23.2d, v28.2d
  221c34:      	b.ne	0x221bd4 <brynja_ghash_timing::timed+0x490>
  221c38:      	add	v6.2d, v22.2d, v6.2d
  221c3c:      	add	v19.2d, v23.2d, v19.2d
  221c40:      	add	v4.2d, v20.2d, v4.2d
  221c44:      	add	v7.2d, v7.2d, v21.2d
  221c48:      	add	v1.2d, v17.2d, v1.2d
  221c4c:      	add	v3.2d, v18.2d, v3.2d
  221c50:      	add	v0.2d, v5.2d, v0.2d
  221c54:      	add	v2.2d, v16.2d, v2.2d
  221c58:      	add	v1.2d, v7.2d, v1.2d
  221c5c:      	add	v0.2d, v0.2d, v2.2d
  221c60:      	add	v2.2d, v4.2d, v3.2d
  221c64:      	add	v3.2d, v6.2d, v19.2d
  221c68:      	add	v0.2d, v1.2d, v0.2d
  221c6c:      	add	v1.2d, v2.2d, v3.2d
  221c70:      	add	v0.2d, v0.2d, v1.2d
  221c74:      	addp	d0, v0.2d
  221c78:      	fmov	x8, d0
  221c7c:      	add	x8, x8, #0x1
  221c80:      	add	x21, x10, #0x1
  221c84:      	cmp	x9, #0xf
  221c88:      	b.eq	0x221cb4 <brynja_ghash_timing::timed+0x570>
  221c8c:      	cmp	x21, x26
  221c90:      	b.eq	0x221cb4 <brynja_ghash_timing::timed+0x570>
  221c94:      	ldrb	w10, [x21], #0x1
  221c98:      	ldrb	w11, [x28, x9]
  221c9c:      	add	x8, x8, #0x1
  221ca0:      	eor	w10, w11, w10
  221ca4:      	strb	w10, [x28, x9]
  221ca8:      	add	x9, x9, #0x1
  221cac:      	cmp	x9, #0xf
  221cb0:      	b.ne	0x221c8c <brynja_ghash_timing::timed+0x548>
  221cb4:      	mov	x11, x8
  221cb8:      	cmp	x11, #0x10
  221cbc:      	b.ne	0x221b1c <brynja_ghash_timing::timed+0x3d8>
  221cc0:      	cmn	x23, #0x1
  221cc4:      	b.eq	0x223d48 <brynja_ghash_timing::timed+0x2604>
  221cc8:      	ldp	x9, x10, [sp, #0x38]
  221ccc:      	add	x23, x23, #0x1
  221cd0:      	ldr	x11, [sp, #0x48]
  221cd4:      	str	q28, [sp, #0x10]
  221cd8:      	ldp	x8, x9, [x9]
  221cdc:      	rev	x0, x11
  221ce0:      	rev	x1, x10
  221ce4:      	rev	x2, x9
  221ce8:      	rev	x3, x8
  221cec:      	bl	0x2266ac <brynja_crypto_cpu::ghash_pmull::multiply>
  221cf0:      	ldr	q28, [sp, #0x10]
  221cf4:      	mov	x8, xzr
  221cf8:      	mov	x11, xzr
  221cfc:      	rev	x9, x0
  221d00:      	rev	x10, x1
  221d04:      	stp	x10, x9, [sp, #0x40]
  221d08:      	b	0x221b1c <brynja_ghash_timing::timed+0x3d8>
  221d0c:      	cmp	x11, #0xf
  221d10:      	b.ls	0x221b28 <brynja_ghash_timing::timed+0x3e4>
  221d14:      	b	0x221cb8 <brynja_ghash_timing::timed+0x574>
  221d18:      	ldr	x10, [sp, #0x20]
  221d1c:      	mov	w9, #0x10               // =16
  221d20:      	stp	x10, x9, [x29, #-0x50]
  221d24:      	sub	x9, x29, #0x50
  221d28:      	ldur	x9, [x29, #-0x48]
  221d2c:      	subs	x24, x24, x9
  221d30:      	b.lo	0x223b48 <brynja_ghash_timing::timed+0x2404>
  221d34:      	cbz	x9, 0x221f64 <brynja_ghash_timing::timed+0x820>
  221d38:      	mov	w10, #0x1               // =1
  221d3c:      	ldur	x21, [x29, #-0x50]
  221d40:      	add	x25, sp, #0x40
  221d44:      	dup	v28.2d, x10
  221d48:      	add	x19, x25, #0x11
  221d4c:      	orr	x28, x25, #0x1
  221d50:      	add	x26, x21, x9
  221d54:      	add	x27, x9, x21
  221d58:      	mov	w20, #0xf               // =15
  221d5c:      	mov	w22, #0x20              // =32
  221d60:      	mov	x11, x8
  221d64:      	b	0x221d70 <brynja_ghash_timing::timed+0x62c>
  221d68:      	cmp	x26, x21
  221d6c:      	b.eq	0x221f64 <brynja_ghash_timing::timed+0x820>
  221d70:      	cbnz	x11, 0x221f58 <brynja_ghash_timing::timed+0x814>
  221d74:      	cmp	x21, x26
  221d78:      	b.eq	0x221f64 <brynja_ghash_timing::timed+0x820>
  221d7c:      	mvn	x9, x21
  221d80:      	sub	x10, x20, x11
  221d84:      	ldrb	w12, [x25, x11]
  221d88:      	add	x9, x27, x9
  221d8c:      	cmp	x9, x10
  221d90:      	csel	x9, x9, x10, lo
  221d94:      	ldrb	w10, [x21]
  221d98:      	add	x9, x9, #0x1
  221d9c:      	cmp	x9, #0x21
  221da0:      	eor	w10, w12, w10
  221da4:      	strb	w10, [x25, x11]
  221da8:      	b.hs	0x221dc4 <brynja_ghash_timing::timed+0x680>
  221dac:      	mov	x9, x11
  221db0:      	add	x8, x8, #0x1
  221db4:      	add	x21, x21, #0x1
  221db8:      	cmp	x11, #0xf
  221dbc:      	b.ne	0x221ed8 <brynja_ghash_timing::timed+0x794>
  221dc0:      	b	0x221f00 <brynja_ghash_timing::timed+0x7bc>
  221dc4:      	ands	x10, x9, #0x1f
  221dc8:      	movi	v0.2d, #0000000000000000
  221dcc:      	movi	v4.2d, #0000000000000000
  221dd0:      	movi	v6.2d, #0000000000000000
  221dd4:      	movi	v1.2d, #0000000000000000
  221dd8:      	csel	x10, x22, x10, eq
  221ddc:      	movi	v3.2d, #0000000000000000
  221de0:      	movi	v2.2d, #0000000000000000
  221de4:      	sub	x12, x9, x10
  221de8:      	movi	v19.2d, #0000000000000000
  221dec:      	movi	v7.2d, #0000000000000000
  221df0:      	add	x10, x21, x12
  221df4:      	movi	v20.2d, #0000000000000000
  221df8:      	movi	v5.2d, #0000000000000000
  221dfc:      	add	x9, x11, x12
  221e00:      	movi	v22.2d, #0000000000000000
  221e04:      	movi	v17.2d, #0000000000000000
  221e08:      	movi	v18.2d, #0000000000000000
  221e0c:      	movi	v16.2d, #0000000000000000
  221e10:      	movi	v23.2d, #0000000000000000
  221e14:      	fmov	d21, x8
  221e18:      	add	x8, x19, x11
  221e1c:      	add	x11, x21, #0x11
  221e20:      	ldp	q24, q25, [x11, #-0x10]
  221e24:      	add	v0.2d, v0.2d, v28.2d
  221e28:      	ldp	q26, q27, [x8, #-0x10]
  221e2c:      	add	v4.2d, v4.2d, v28.2d
  221e30:      	add	v21.2d, v21.2d, v28.2d
  221e34:      	add	v6.2d, v6.2d, v28.2d
  221e38:      	add	v1.2d, v1.2d, v28.2d
  221e3c:      	add	v3.2d, v3.2d, v28.2d
  221e40:      	add	v2.2d, v2.2d, v28.2d
  221e44:      	add	v19.2d, v19.2d, v28.2d
  221e48:      	eor	v24.16b, v26.16b, v24.16b
  221e4c:      	eor	v25.16b, v27.16b, v25.16b
  221e50:      	subs	x12, x12, #0x20
  221e54:      	add	v5.2d, v5.2d, v28.2d
  221e58:      	add	v20.2d, v20.2d, v28.2d
  221e5c:      	add	x11, x11, #0x20
  221e60:      	add	v7.2d, v7.2d, v28.2d
  221e64:      	add	v22.2d, v22.2d, v28.2d
  221e68:      	add	v17.2d, v17.2d, v28.2d
  221e6c:      	add	v18.2d, v18.2d, v28.2d
  221e70:      	stp	q24, q25, [x8, #-0x10]
  221e74:      	add	x8, x8, #0x20
  221e78:      	add	v16.2d, v16.2d, v28.2d
  221e7c:      	add	v23.2d, v23.2d, v28.2d
  221e80:      	b.ne	0x221e20 <brynja_ghash_timing::timed+0x6dc>
  221e84:      	add	v6.2d, v22.2d, v6.2d
  221e88:      	add	v19.2d, v23.2d, v19.2d
  221e8c:      	add	v4.2d, v20.2d, v4.2d
  221e90:      	add	v7.2d, v7.2d, v21.2d
  221e94:      	add	v1.2d, v17.2d, v1.2d
  221e98:      	add	v3.2d, v18.2d, v3.2d
  221e9c:      	add	v0.2d, v5.2d, v0.2d
  221ea0:      	add	v2.2d, v16.2d, v2.2d
  221ea4:      	add	v1.2d, v7.2d, v1.2d
  221ea8:      	add	v0.2d, v0.2d, v2.2d
  221eac:      	add	v2.2d, v4.2d, v3.2d
  221eb0:      	add	v3.2d, v6.2d, v19.2d
  221eb4:      	add	v0.2d, v1.2d, v0.2d
  221eb8:      	add	v1.2d, v2.2d, v3.2d
  221ebc:      	add	v0.2d, v0.2d, v1.2d
  221ec0:      	addp	d0, v0.2d
  221ec4:      	fmov	x8, d0
  221ec8:      	add	x8, x8, #0x1
  221ecc:      	add	x21, x10, #0x1
  221ed0:      	cmp	x9, #0xf
  221ed4:      	b.eq	0x221f00 <brynja_ghash_timing::timed+0x7bc>
  221ed8:      	cmp	x21, x26
  221edc:      	b.eq	0x221f00 <brynja_ghash_timing::timed+0x7bc>
  221ee0:      	ldrb	w10, [x21], #0x1
  221ee4:      	ldrb	w11, [x28, x9]
  221ee8:      	add	x8, x8, #0x1
  221eec:      	eor	w10, w11, w10
  221ef0:      	strb	w10, [x28, x9]
  221ef4:      	add	x9, x9, #0x1
  221ef8:      	cmp	x9, #0xf
  221efc:      	b.ne	0x221ed8 <brynja_ghash_timing::timed+0x794>
  221f00:      	mov	x11, x8
  221f04:      	cmp	x11, #0x10
  221f08:      	b.ne	0x221d68 <brynja_ghash_timing::timed+0x624>
  221f0c:      	cmn	x23, #0x1
  221f10:      	b.eq	0x223d48 <brynja_ghash_timing::timed+0x2604>
  221f14:      	ldp	x9, x10, [sp, #0x38]
  221f18:      	add	x23, x23, #0x1
  221f1c:      	ldr	x11, [sp, #0x48]
  221f20:      	str	q28, [sp, #0x10]
  221f24:      	ldp	x8, x9, [x9]
  221f28:      	rev	x0, x11
  221f2c:      	rev	x1, x10
  221f30:      	rev	x2, x9
  221f34:      	rev	x3, x8
  221f38:      	bl	0x2266ac <brynja_crypto_cpu::ghash_pmull::multiply>
  221f3c:      	ldr	q28, [sp, #0x10]
  221f40:      	mov	x8, xzr
  221f44:      	mov	x11, xzr
  221f48:      	rev	x9, x0
  221f4c:      	rev	x10, x1
  221f50:      	stp	x10, x9, [sp, #0x40]
  221f54:      	b	0x221d68 <brynja_ghash_timing::timed+0x624>
  221f58:      	cmp	x11, #0xf
  221f5c:      	b.ls	0x221d74 <brynja_ghash_timing::timed+0x630>
  221f60:      	b	0x221f04 <brynja_ghash_timing::timed+0x7c0>
  221f64:      	ldr	x10, [sp, #0x20]
  221f68:      	mov	w9, #0x10               // =16
  221f6c:      	stp	x10, x9, [x29, #-0x50]
  221f70:      	sub	x9, x29, #0x50
  221f74:      	ldur	x9, [x29, #-0x48]
  221f78:      	subs	x24, x24, x9
  221f7c:      	b.lo	0x223b48 <brynja_ghash_timing::timed+0x2404>
  221f80:      	cbz	x9, 0x2221b0 <brynja_ghash_timing::timed+0xa6c>
  221f84:      	mov	w10, #0x1               // =1
  221f88:      	ldur	x21, [x29, #-0x50]
  221f8c:      	add	x25, sp, #0x40
  221f90:      	dup	v28.2d, x10
  221f94:      	add	x19, x25, #0x11
  221f98:      	orr	x28, x25, #0x1
  221f9c:      	add	x26, x21, x9
  221fa0:      	add	x27, x9, x21
  221fa4:      	mov	w20, #0xf               // =15
  221fa8:      	mov	w22, #0x20              // =32
  221fac:      	mov	x11, x8
  221fb0:      	b	0x221fbc <brynja_ghash_timing::timed+0x878>
  221fb4:      	cmp	x26, x21
  221fb8:      	b.eq	0x2221b0 <brynja_ghash_timing::timed+0xa6c>
  221fbc:      	cbnz	x11, 0x2221a4 <brynja_ghash_timing::timed+0xa60>
  221fc0:      	cmp	x21, x26
  221fc4:      	b.eq	0x2221b0 <brynja_ghash_timing::timed+0xa6c>
  221fc8:      	mvn	x9, x21
  221fcc:      	sub	x10, x20, x11
  221fd0:      	ldrb	w12, [x25, x11]
  221fd4:      	add	x9, x27, x9
  221fd8:      	cmp	x9, x10
  221fdc:      	csel	x9, x9, x10, lo
  221fe0:      	ldrb	w10, [x21]
  221fe4:      	add	x9, x9, #0x1
  221fe8:      	cmp	x9, #0x21
  221fec:      	eor	w10, w12, w10
  221ff0:      	strb	w10, [x25, x11]
  221ff4:      	b.hs	0x222010 <brynja_ghash_timing::timed+0x8cc>
  221ff8:      	mov	x9, x11
  221ffc:      	add	x8, x8, #0x1
  222000:      	add	x21, x21, #0x1
  222004:      	cmp	x11, #0xf
  222008:      	b.ne	0x222124 <brynja_ghash_timing::timed+0x9e0>
  22200c:      	b	0x22214c <brynja_ghash_timing::timed+0xa08>
  222010:      	ands	x10, x9, #0x1f
  222014:      	movi	v0.2d, #0000000000000000
  222018:      	movi	v4.2d, #0000000000000000
  22201c:      	movi	v6.2d, #0000000000000000
  222020:      	movi	v1.2d, #0000000000000000
  222024:      	csel	x10, x22, x10, eq
  222028:      	movi	v3.2d, #0000000000000000
  22202c:      	movi	v2.2d, #0000000000000000
  222030:      	sub	x12, x9, x10
  222034:      	movi	v19.2d, #0000000000000000
  222038:      	movi	v7.2d, #0000000000000000
  22203c:      	add	x10, x21, x12
  222040:      	movi	v20.2d, #0000000000000000
  222044:      	movi	v5.2d, #0000000000000000
  222048:      	add	x9, x11, x12
  22204c:      	movi	v22.2d, #0000000000000000
  222050:      	movi	v17.2d, #0000000000000000
  222054:      	movi	v18.2d, #0000000000000000
  222058:      	movi	v16.2d, #0000000000000000
  22205c:      	movi	v23.2d, #0000000000000000
  222060:      	fmov	d21, x8
  222064:      	add	x8, x19, x11
  222068:      	add	x11, x21, #0x11
  22206c:      	ldp	q24, q25, [x11, #-0x10]
  222070:      	add	v0.2d, v0.2d, v28.2d
  222074:      	ldp	q26, q27, [x8, #-0x10]
  222078:      	add	v4.2d, v4.2d, v28.2d
  22207c:      	add	v21.2d, v21.2d, v28.2d
  222080:      	add	v6.2d, v6.2d, v28.2d
  222084:      	add	v1.2d, v1.2d, v28.2d
  222088:      	add	v3.2d, v3.2d, v28.2d
  22208c:      	add	v2.2d, v2.2d, v28.2d
  222090:      	add	v19.2d, v19.2d, v28.2d
  222094:      	eor	v24.16b, v26.16b, v24.16b
  222098:      	eor	v25.16b, v27.16b, v25.16b
  22209c:      	subs	x12, x12, #0x20
  2220a0:      	add	v5.2d, v5.2d, v28.2d
  2220a4:      	add	v20.2d, v20.2d, v28.2d
  2220a8:      	add	x11, x11, #0x20
  2220ac:      	add	v7.2d, v7.2d, v28.2d
  2220b0:      	add	v22.2d, v22.2d, v28.2d
  2220b4:      	add	v17.2d, v17.2d, v28.2d
  2220b8:      	add	v18.2d, v18.2d, v28.2d
  2220bc:      	stp	q24, q25, [x8, #-0x10]
  2220c0:      	add	x8, x8, #0x20
  2220c4:      	add	v16.2d, v16.2d, v28.2d
  2220c8:      	add	v23.2d, v23.2d, v28.2d
  2220cc:      	b.ne	0x22206c <brynja_ghash_timing::timed+0x928>
  2220d0:      	add	v6.2d, v22.2d, v6.2d
  2220d4:      	add	v19.2d, v23.2d, v19.2d
  2220d8:      	add	v4.2d, v20.2d, v4.2d
  2220dc:      	add	v7.2d, v7.2d, v21.2d
  2220e0:      	add	v1.2d, v17.2d, v1.2d
  2220e4:      	add	v3.2d, v18.2d, v3.2d
  2220e8:      	add	v0.2d, v5.2d, v0.2d
  2220ec:      	add	v2.2d, v16.2d, v2.2d
  2220f0:      	add	v1.2d, v7.2d, v1.2d
  2220f4:      	add	v0.2d, v0.2d, v2.2d
  2220f8:      	add	v2.2d, v4.2d, v3.2d
  2220fc:      	add	v3.2d, v6.2d, v19.2d
  222100:      	add	v0.2d, v1.2d, v0.2d
  222104:      	add	v1.2d, v2.2d, v3.2d
  222108:      	add	v0.2d, v0.2d, v1.2d
  22210c:      	addp	d0, v0.2d
  222110:      	fmov	x8, d0
  222114:      	add	x8, x8, #0x1
  222118:      	add	x21, x10, #0x1
  22211c:      	cmp	x9, #0xf
  222120:      	b.eq	0x22214c <brynja_ghash_timing::timed+0xa08>
  222124:      	cmp	x21, x26
  222128:      	b.eq	0x22214c <brynja_ghash_timing::timed+0xa08>
  22212c:      	ldrb	w10, [x21], #0x1
  222130:      	ldrb	w11, [x28, x9]
  222134:      	add	x8, x8, #0x1
  222138:      	eor	w10, w11, w10
  22213c:      	strb	w10, [x28, x9]
  222140:      	add	x9, x9, #0x1
  222144:      	cmp	x9, #0xf
  222148:      	b.ne	0x222124 <brynja_ghash_timing::timed+0x9e0>
  22214c:      	mov	x11, x8
  222150:      	cmp	x11, #0x10
  222154:      	b.ne	0x221fb4 <brynja_ghash_timing::timed+0x870>
  222158:      	cmn	x23, #0x1
  22215c:      	b.eq	0x223d48 <brynja_ghash_timing::timed+0x2604>
  222160:      	ldp	x9, x10, [sp, #0x38]
  222164:      	add	x23, x23, #0x1
  222168:      	ldr	x11, [sp, #0x48]
  22216c:      	str	q28, [sp, #0x10]
  222170:      	ldp	x8, x9, [x9]
  222174:      	rev	x0, x11
  222178:      	rev	x1, x10
  22217c:      	rev	x2, x9
  222180:      	rev	x3, x8
  222184:      	bl	0x2266ac <brynja_crypto_cpu::ghash_pmull::multiply>
  222188:      	ldr	q28, [sp, #0x10]
  22218c:      	mov	x8, xzr
  222190:      	mov	x11, xzr
  222194:      	rev	x9, x0
  222198:      	rev	x10, x1
  22219c:      	stp	x10, x9, [sp, #0x40]
  2221a0:      	b	0x221fb4 <brynja_ghash_timing::timed+0x870>
  2221a4:      	cmp	x11, #0xf
  2221a8:      	b.ls	0x221fc0 <brynja_ghash_timing::timed+0x87c>
  2221ac:      	b	0x222150 <brynja_ghash_timing::timed+0xa0c>
  2221b0:      	ldr	x10, [sp, #0x20]
  2221b4:      	mov	w9, #0x10               // =16
  2221b8:      	stp	x10, x9, [x29, #-0x50]
  2221bc:      	sub	x9, x29, #0x50
  2221c0:      	ldur	x9, [x29, #-0x48]
  2221c4:      	subs	x24, x24, x9
  2221c8:      	b.lo	0x223b48 <brynja_ghash_timing::timed+0x2404>
  2221cc:      	cbz	x9, 0x2223fc <brynja_ghash_timing::timed+0xcb8>
  2221d0:      	mov	w10, #0x1               // =1
  2221d4:      	ldur	x21, [x29, #-0x50]
  2221d8:      	add	x25, sp, #0x40
  2221dc:      	dup	v28.2d, x10
  2221e0:      	add	x19, x25, #0x11
  2221e4:      	orr	x28, x25, #0x1
  2221e8:      	add	x26, x21, x9
  2221ec:      	add	x27, x9, x21
  2221f0:      	mov	w20, #0xf               // =15
  2221f4:      	mov	w22, #0x20              // =32
  2221f8:      	mov	x11, x8
  2221fc:      	b	0x222208 <brynja_ghash_timing::timed+0xac4>
  222200:      	cmp	x26, x21
  222204:      	b.eq	0x2223fc <brynja_ghash_timing::timed+0xcb8>
  222208:      	cbnz	x11, 0x2223f0 <brynja_ghash_timing::timed+0xcac>
  22220c:      	cmp	x21, x26
  222210:      	b.eq	0x2223fc <brynja_ghash_timing::timed+0xcb8>
  222214:      	mvn	x9, x21
  222218:      	sub	x10, x20, x11
  22221c:      	ldrb	w12, [x25, x11]
  222220:      	add	x9, x27, x9
  222224:      	cmp	x9, x10
  222228:      	csel	x9, x9, x10, lo
  22222c:      	ldrb	w10, [x21]
  222230:      	add	x9, x9, #0x1
  222234:      	cmp	x9, #0x21
  222238:      	eor	w10, w12, w10
  22223c:      	strb	w10, [x25, x11]
  222240:      	b.hs	0x22225c <brynja_ghash_timing::timed+0xb18>
  222244:      	mov	x9, x11
  222248:      	add	x8, x8, #0x1
  22224c:      	add	x21, x21, #0x1
  222250:      	cmp	x11, #0xf
  222254:      	b.ne	0x222370 <brynja_ghash_timing::timed+0xc2c>
  222258:      	b	0x222398 <brynja_ghash_timing::timed+0xc54>
  22225c:      	ands	x10, x9, #0x1f
  222260:      	movi	v0.2d, #0000000000000000
  222264:      	movi	v4.2d, #0000000000000000
  222268:      	movi	v6.2d, #0000000000000000
  22226c:      	movi	v1.2d, #0000000000000000
  222270:      	csel	x10, x22, x10, eq
  222274:      	movi	v3.2d, #0000000000000000
  222278:      	movi	v2.2d, #0000000000000000
  22227c:      	sub	x12, x9, x10
  222280:      	movi	v19.2d, #0000000000000000
  222284:      	movi	v7.2d, #0000000000000000
  222288:      	add	x10, x21, x12
  22228c:      	movi	v20.2d, #0000000000000000
  222290:      	movi	v5.2d, #0000000000000000
  222294:      	add	x9, x11, x12
  222298:      	movi	v22.2d, #0000000000000000
  22229c:      	movi	v17.2d, #0000000000000000
  2222a0:      	movi	v18.2d, #0000000000000000
  2222a4:      	movi	v16.2d, #0000000000000000
  2222a8:      	movi	v23.2d, #0000000000000000
  2222ac:      	fmov	d21, x8
  2222b0:      	add	x8, x19, x11
  2222b4:      	add	x11, x21, #0x11
  2222b8:      	ldp	q24, q25, [x11, #-0x10]
  2222bc:      	add	v0.2d, v0.2d, v28.2d
  2222c0:      	ldp	q26, q27, [x8, #-0x10]
  2222c4:      	add	v4.2d, v4.2d, v28.2d
  2222c8:      	add	v21.2d, v21.2d, v28.2d
  2222cc:      	add	v6.2d, v6.2d, v28.2d
  2222d0:      	add	v1.2d, v1.2d, v28.2d
  2222d4:      	add	v3.2d, v3.2d, v28.2d
  2222d8:      	add	v2.2d, v2.2d, v28.2d
  2222dc:      	add	v19.2d, v19.2d, v28.2d
  2222e0:      	eor	v24.16b, v26.16b, v24.16b
  2222e4:      	eor	v25.16b, v27.16b, v25.16b
  2222e8:      	subs	x12, x12, #0x20
  2222ec:      	add	v5.2d, v5.2d, v28.2d
  2222f0:      	add	v20.2d, v20.2d, v28.2d
  2222f4:      	add	x11, x11, #0x20
  2222f8:      	add	v7.2d, v7.2d, v28.2d
  2222fc:      	add	v22.2d, v22.2d, v28.2d
  222300:      	add	v17.2d, v17.2d, v28.2d
  222304:      	add	v18.2d, v18.2d, v28.2d
  222308:      	stp	q24, q25, [x8, #-0x10]
  22230c:      	add	x8, x8, #0x20
  222310:      	add	v16.2d, v16.2d, v28.2d
  222314:      	add	v23.2d, v23.2d, v28.2d
  222318:      	b.ne	0x2222b8 <brynja_ghash_timing::timed+0xb74>
  22231c:      	add	v6.2d, v22.2d, v6.2d
  222320:      	add	v19.2d, v23.2d, v19.2d
  222324:      	add	v4.2d, v20.2d, v4.2d
  222328:      	add	v7.2d, v7.2d, v21.2d
  22232c:      	add	v1.2d, v17.2d, v1.2d
  222330:      	add	v3.2d, v18.2d, v3.2d
  222334:      	add	v0.2d, v5.2d, v0.2d
  222338:      	add	v2.2d, v16.2d, v2.2d
  22233c:      	add	v1.2d, v7.2d, v1.2d
  222340:      	add	v0.2d, v0.2d, v2.2d
  222344:      	add	v2.2d, v4.2d, v3.2d
  222348:      	add	v3.2d, v6.2d, v19.2d
  22234c:      	add	v0.2d, v1.2d, v0.2d
  222350:      	add	v1.2d, v2.2d, v3.2d
  222354:      	add	v0.2d, v0.2d, v1.2d
  222358:      	addp	d0, v0.2d
  22235c:      	fmov	x8, d0
  222360:      	add	x8, x8, #0x1
  222364:      	add	x21, x10, #0x1
  222368:      	cmp	x9, #0xf
  22236c:      	b.eq	0x222398 <brynja_ghash_timing::timed+0xc54>
  222370:      	cmp	x21, x26
  222374:      	b.eq	0x222398 <brynja_ghash_timing::timed+0xc54>
  222378:      	ldrb	w10, [x21], #0x1
  22237c:      	ldrb	w11, [x28, x9]
  222380:      	add	x8, x8, #0x1
  222384:      	eor	w10, w11, w10
  222388:      	strb	w10, [x28, x9]
  22238c:      	add	x9, x9, #0x1
  222390:      	cmp	x9, #0xf
  222394:      	b.ne	0x222370 <brynja_ghash_timing::timed+0xc2c>
  222398:      	mov	x11, x8
  22239c:      	cmp	x11, #0x10
  2223a0:      	b.ne	0x222200 <brynja_ghash_timing::timed+0xabc>
  2223a4:      	cmn	x23, #0x1
  2223a8:      	b.eq	0x223d48 <brynja_ghash_timing::timed+0x2604>
  2223ac:      	ldp	x9, x10, [sp, #0x38]
  2223b0:      	add	x23, x23, #0x1
  2223b4:      	ldr	x11, [sp, #0x48]
  2223b8:      	str	q28, [sp, #0x10]
  2223bc:      	ldp	x8, x9, [x9]
  2223c0:      	rev	x0, x11
  2223c4:      	rev	x1, x10
  2223c8:      	rev	x2, x9
  2223cc:      	rev	x3, x8
  2223d0:      	bl	0x2266ac <brynja_crypto_cpu::ghash_pmull::multiply>
  2223d4:      	ldr	q28, [sp, #0x10]
  2223d8:      	mov	x8, xzr
  2223dc:      	mov	x11, xzr
  2223e0:      	rev	x9, x0
  2223e4:      	rev	x10, x1
  2223e8:      	stp	x10, x9, [sp, #0x40]
  2223ec:      	b	0x222200 <brynja_ghash_timing::timed+0xabc>
  2223f0:      	cmp	x11, #0xf
  2223f4:      	b.ls	0x22220c <brynja_ghash_timing::timed+0xac8>
  2223f8:      	b	0x22239c <brynja_ghash_timing::timed+0xc58>
  2223fc:      	ldr	x10, [sp, #0x20]
  222400:      	mov	w9, #0x10               // =16
  222404:      	stp	x10, x9, [x29, #-0x50]
  222408:      	sub	x9, x29, #0x50
  22240c:      	ldur	x9, [x29, #-0x48]
  222410:      	subs	x24, x24, x9
  222414:      	b.lo	0x223b48 <brynja_ghash_timing::timed+0x2404>
  222418:      	cbz	x9, 0x222648 <brynja_ghash_timing::timed+0xf04>
  22241c:      	mov	w10, #0x1               // =1
  222420:      	ldur	x21, [x29, #-0x50]
  222424:      	add	x25, sp, #0x40
  222428:      	dup	v28.2d, x10
  22242c:      	add	x19, x25, #0x11
  222430:      	orr	x28, x25, #0x1
  222434:      	add	x26, x21, x9
  222438:      	add	x27, x9, x21
  22243c:      	mov	w20, #0xf               // =15
  222440:      	mov	w22, #0x20              // =32
  222444:      	mov	x11, x8
  222448:      	b	0x222494 <brynja_ghash_timing::timed+0xd50>
  22244c:      	ldp	x9, x10, [sp, #0x38]
  222450:      	add	x23, x23, #0x1
  222454:      	ldr	x11, [sp, #0x48]
  222458:      	str	q28, [sp, #0x10]
  22245c:      	ldp	x8, x9, [x9]
  222460:      	rev	x0, x11
  222464:      	rev	x1, x10
  222468:      	rev	x2, x9
  22246c:      	rev	x3, x8
  222470:      	bl	0x2266ac <brynja_crypto_cpu::ghash_pmull::multiply>
  222474:      	ldr	q28, [sp, #0x10]
  222478:      	mov	x8, xzr
  22247c:      	mov	x11, xzr
  222480:      	rev	x9, x0
  222484:      	rev	x10, x1
  222488:      	stp	x10, x9, [sp, #0x40]
  22248c:      	cmp	x26, x21
  222490:      	b.eq	0x222648 <brynja_ghash_timing::timed+0xf04>
  222494:      	cbnz	x11, 0x22263c <brynja_ghash_timing::timed+0xef8>
  222498:      	cmp	x21, x26
  22249c:      	b.eq	0x222648 <brynja_ghash_timing::timed+0xf04>
  2224a0:      	mvn	x9, x21
  2224a4:      	sub	x10, x20, x11
  2224a8:      	ldrb	w12, [x25, x11]
  2224ac:      	add	x9, x27, x9
  2224b0:      	cmp	x9, x10
  2224b4:      	csel	x9, x9, x10, lo
  2224b8:      	ldrb	w10, [x21]
  2224bc:      	add	x9, x9, #0x1
  2224c0:      	cmp	x9, #0x21
  2224c4:      	eor	w10, w12, w10
  2224c8:      	strb	w10, [x25, x11]
  2224cc:      	b.hs	0x2224e8 <brynja_ghash_timing::timed+0xda4>
  2224d0:      	mov	x9, x11
  2224d4:      	add	x8, x8, #0x1
  2224d8:      	add	x21, x21, #0x1
  2224dc:      	cmp	x11, #0xf
  2224e0:      	b.ne	0x2225fc <brynja_ghash_timing::timed+0xeb8>
  2224e4:      	b	0x222624 <brynja_ghash_timing::timed+0xee0>
  2224e8:      	ands	x10, x9, #0x1f
  2224ec:      	movi	v0.2d, #0000000000000000
  2224f0:      	movi	v4.2d, #0000000000000000
  2224f4:      	movi	v6.2d, #0000000000000000
  2224f8:      	movi	v1.2d, #0000000000000000
  2224fc:      	csel	x10, x22, x10, eq
  222500:      	movi	v3.2d, #0000000000000000
  222504:      	movi	v2.2d, #0000000000000000
  222508:      	sub	x12, x9, x10
  22250c:      	movi	v19.2d, #0000000000000000
  222510:      	movi	v7.2d, #0000000000000000
  222514:      	add	x10, x21, x12
  222518:      	movi	v20.2d, #0000000000000000
  22251c:      	movi	v5.2d, #0000000000000000
  222520:      	add	x9, x11, x12
  222524:      	movi	v22.2d, #0000000000000000
  222528:      	movi	v17.2d, #0000000000000000
  22252c:      	movi	v18.2d, #0000000000000000
  222530:      	movi	v16.2d, #0000000000000000
  222534:      	movi	v23.2d, #0000000000000000
  222538:      	fmov	d21, x8
  22253c:      	add	x8, x19, x11
  222540:      	add	x11, x21, #0x11
  222544:      	ldp	q24, q25, [x11, #-0x10]
  222548:      	add	v0.2d, v0.2d, v28.2d
  22254c:      	ldp	q26, q27, [x8, #-0x10]
  222550:      	add	v4.2d, v4.2d, v28.2d
  222554:      	add	v21.2d, v21.2d, v28.2d
  222558:      	add	v6.2d, v6.2d, v28.2d
  22255c:      	add	v1.2d, v1.2d, v28.2d
  222560:      	add	v3.2d, v3.2d, v28.2d
  222564:      	add	v2.2d, v2.2d, v28.2d
  222568:      	add	v19.2d, v19.2d, v28.2d
  22256c:      	eor	v24.16b, v26.16b, v24.16b
  222570:      	eor	v25.16b, v27.16b, v25.16b
  222574:      	subs	x12, x12, #0x20
  222578:      	add	v5.2d, v5.2d, v28.2d
  22257c:      	add	v20.2d, v20.2d, v28.2d
  222580:      	add	x11, x11, #0x20
  222584:      	add	v7.2d, v7.2d, v28.2d
  222588:      	add	v22.2d, v22.2d, v28.2d
  22258c:      	add	v17.2d, v17.2d, v28.2d
  222590:      	add	v18.2d, v18.2d, v28.2d
  222594:      	stp	q24, q25, [x8, #-0x10]
  222598:      	add	x8, x8, #0x20
  22259c:      	add	v16.2d, v16.2d, v28.2d
  2225a0:      	add	v23.2d, v23.2d, v28.2d
  2225a4:      	b.ne	0x222544 <brynja_ghash_timing::timed+0xe00>
  2225a8:      	add	v6.2d, v22.2d, v6.2d
  2225ac:      	add	v19.2d, v23.2d, v19.2d
  2225b0:      	add	v4.2d, v20.2d, v4.2d
  2225b4:      	add	v7.2d, v7.2d, v21.2d
  2225b8:      	add	v1.2d, v17.2d, v1.2d
  2225bc:      	add	v3.2d, v18.2d, v3.2d
  2225c0:      	add	v0.2d, v5.2d, v0.2d
  2225c4:      	add	v2.2d, v16.2d, v2.2d
  2225c8:      	add	v1.2d, v7.2d, v1.2d
  2225cc:      	add	v0.2d, v0.2d, v2.2d
  2225d0:      	add	v2.2d, v4.2d, v3.2d
  2225d4:      	add	v3.2d, v6.2d, v19.2d
  2225d8:      	add	v0.2d, v1.2d, v0.2d
  2225dc:      	add	v1.2d, v2.2d, v3.2d
  2225e0:      	add	v0.2d, v0.2d, v1.2d
  2225e4:      	addp	d0, v0.2d
  2225e8:      	fmov	x8, d0
  2225ec:      	add	x8, x8, #0x1
  2225f0:      	add	x21, x10, #0x1
  2225f4:      	cmp	x9, #0xf
  2225f8:      	b.eq	0x222624 <brynja_ghash_timing::timed+0xee0>
  2225fc:      	cmp	x21, x26
  222600:      	b.eq	0x222624 <brynja_ghash_timing::timed+0xee0>
  222604:      	ldrb	w10, [x21], #0x1
  222608:      	ldrb	w11, [x28, x9]
  22260c:      	add	x8, x8, #0x1
  222610:      	eor	w10, w11, w10
  222614:      	strb	w10, [x28, x9]
  222618:      	add	x9, x9, #0x1
  22261c:      	cmp	x9, #0xf
  222620:      	b.ne	0x2225fc <brynja_ghash_timing::timed+0xeb8>
  222624:      	mov	x11, x8
  222628:      	cmp	x11, #0x10
  22262c:      	b.ne	0x22248c <brynja_ghash_timing::timed+0xd48>
  222630:      	cmn	x23, #0x1
  222634:      	b.eq	0x223d48 <brynja_ghash_timing::timed+0x2604>
  222638:      	b	0x22244c <brynja_ghash_timing::timed+0xd08>
  22263c:      	cmp	x11, #0xf
  222640:      	b.ls	0x222498 <brynja_ghash_timing::timed+0xd54>
  222644:      	b	0x222628 <brynja_ghash_timing::timed+0xee4>
  222648:      	ldr	x10, [sp, #0x20]
  22264c:      	mov	w9, #0x10               // =16
  222650:      	stp	x10, x9, [x29, #-0x50]
  222654:      	sub	x9, x29, #0x50
  222658:      	ldur	x9, [x29, #-0x48]
  22265c:      	subs	x24, x24, x9
  222660:      	b.lo	0x223b48 <brynja_ghash_timing::timed+0x2404>
  222664:      	cbz	x9, 0x222894 <brynja_ghash_timing::timed+0x1150>
  222668:      	mov	w10, #0x1               // =1
  22266c:      	ldur	x21, [x29, #-0x50]
  222670:      	add	x25, sp, #0x40
  222674:      	dup	v28.2d, x10
  222678:      	add	x19, x25, #0x11
  22267c:      	orr	x28, x25, #0x1
  222680:      	add	x26, x21, x9
  222684:      	add	x27, x9, x21
  222688:      	mov	w20, #0xf               // =15
  22268c:      	mov	w22, #0x20              // =32
  222690:      	mov	x11, x8
  222694:      	b	0x2226a0 <brynja_ghash_timing::timed+0xf5c>
  222698:      	cmp	x26, x21
  22269c:      	b.eq	0x222894 <brynja_ghash_timing::timed+0x1150>
  2226a0:      	cbnz	x11, 0x222888 <brynja_ghash_timing::timed+0x1144>
  2226a4:      	cmp	x21, x26
  2226a8:      	b.eq	0x222894 <brynja_ghash_timing::timed+0x1150>
  2226ac:      	mvn	x9, x21
  2226b0:      	sub	x10, x20, x11
  2226b4:      	ldrb	w12, [x25, x11]
  2226b8:      	add	x9, x27, x9
  2226bc:      	cmp	x9, x10
  2226c0:      	csel	x9, x9, x10, lo
  2226c4:      	ldrb	w10, [x21]
  2226c8:      	add	x9, x9, #0x1
  2226cc:      	cmp	x9, #0x21
  2226d0:      	eor	w10, w12, w10
  2226d4:      	strb	w10, [x25, x11]
  2226d8:      	b.hs	0x2226f4 <brynja_ghash_timing::timed+0xfb0>
  2226dc:      	mov	x9, x11
  2226e0:      	add	x8, x8, #0x1
  2226e4:      	add	x21, x21, #0x1
  2226e8:      	cmp	x11, #0xf
  2226ec:      	b.ne	0x222808 <brynja_ghash_timing::timed+0x10c4>
  2226f0:      	b	0x222830 <brynja_ghash_timing::timed+0x10ec>
  2226f4:      	ands	x10, x9, #0x1f
  2226f8:      	movi	v0.2d, #0000000000000000
  2226fc:      	movi	v4.2d, #0000000000000000
  222700:      	movi	v6.2d, #0000000000000000
  222704:      	movi	v1.2d, #0000000000000000
  222708:      	csel	x10, x22, x10, eq
  22270c:      	movi	v3.2d, #0000000000000000
  222710:      	movi	v2.2d, #0000000000000000
  222714:      	sub	x12, x9, x10
  222718:      	movi	v19.2d, #0000000000000000
  22271c:      	movi	v7.2d, #0000000000000000
  222720:      	add	x10, x21, x12
  222724:      	movi	v20.2d, #0000000000000000
  222728:      	movi	v5.2d, #0000000000000000
  22272c:      	add	x9, x11, x12
  222730:      	movi	v22.2d, #0000000000000000
  222734:      	movi	v17.2d, #0000000000000000
  222738:      	movi	v18.2d, #0000000000000000
  22273c:      	movi	v16.2d, #0000000000000000
  222740:      	movi	v23.2d, #0000000000000000
  222744:      	fmov	d21, x8
  222748:      	add	x8, x19, x11
  22274c:      	add	x11, x21, #0x11
  222750:      	ldp	q24, q25, [x11, #-0x10]
  222754:      	add	v0.2d, v0.2d, v28.2d
  222758:      	ldp	q26, q27, [x8, #-0x10]
  22275c:      	add	v4.2d, v4.2d, v28.2d
  222760:      	add	v21.2d, v21.2d, v28.2d
  222764:      	add	v6.2d, v6.2d, v28.2d
  222768:      	add	v1.2d, v1.2d, v28.2d
  22276c:      	add	v3.2d, v3.2d, v28.2d
  222770:      	add	v2.2d, v2.2d, v28.2d
  222774:      	add	v19.2d, v19.2d, v28.2d
  222778:      	eor	v24.16b, v26.16b, v24.16b
  22277c:      	eor	v25.16b, v27.16b, v25.16b
  222780:      	subs	x12, x12, #0x20
  222784:      	add	v5.2d, v5.2d, v28.2d
  222788:      	add	v20.2d, v20.2d, v28.2d
  22278c:      	add	x11, x11, #0x20
  222790:      	add	v7.2d, v7.2d, v28.2d
  222794:      	add	v22.2d, v22.2d, v28.2d
  222798:      	add	v17.2d, v17.2d, v28.2d
  22279c:      	add	v18.2d, v18.2d, v28.2d
  2227a0:      	stp	q24, q25, [x8, #-0x10]
  2227a4:      	add	x8, x8, #0x20
  2227a8:      	add	v16.2d, v16.2d, v28.2d
  2227ac:      	add	v23.2d, v23.2d, v28.2d
  2227b0:      	b.ne	0x222750 <brynja_ghash_timing::timed+0x100c>
  2227b4:      	add	v6.2d, v22.2d, v6.2d
  2227b8:      	add	v19.2d, v23.2d, v19.2d
  2227bc:      	add	v4.2d, v20.2d, v4.2d
  2227c0:      	add	v7.2d, v7.2d, v21.2d
  2227c4:      	add	v1.2d, v17.2d, v1.2d
  2227c8:      	add	v3.2d, v18.2d, v3.2d
  2227cc:      	add	v0.2d, v5.2d, v0.2d
  2227d0:      	add	v2.2d, v16.2d, v2.2d
  2227d4:      	add	v1.2d, v7.2d, v1.2d
  2227d8:      	add	v0.2d, v0.2d, v2.2d
  2227dc:      	add	v2.2d, v4.2d, v3.2d
  2227e0:      	add	v3.2d, v6.2d, v19.2d
  2227e4:      	add	v0.2d, v1.2d, v0.2d
  2227e8:      	add	v1.2d, v2.2d, v3.2d
  2227ec:      	add	v0.2d, v0.2d, v1.2d
  2227f0:      	addp	d0, v0.2d
  2227f4:      	fmov	x8, d0
  2227f8:      	add	x8, x8, #0x1
  2227fc:      	add	x21, x10, #0x1
  222800:      	cmp	x9, #0xf
  222804:      	b.eq	0x222830 <brynja_ghash_timing::timed+0x10ec>
  222808:      	cmp	x21, x26
  22280c:      	b.eq	0x222830 <brynja_ghash_timing::timed+0x10ec>
  222810:      	ldrb	w10, [x21], #0x1
  222814:      	ldrb	w11, [x28, x9]
  222818:      	add	x8, x8, #0x1
  22281c:      	eor	w10, w11, w10
  222820:      	strb	w10, [x28, x9]
  222824:      	add	x9, x9, #0x1
  222828:      	cmp	x9, #0xf
  22282c:      	b.ne	0x222808 <brynja_ghash_timing::timed+0x10c4>
  222830:      	mov	x11, x8
  222834:      	cmp	x11, #0x10
  222838:      	b.ne	0x222698 <brynja_ghash_timing::timed+0xf54>
  22283c:      	cmn	x23, #0x1
  222840:      	b.eq	0x223d48 <brynja_ghash_timing::timed+0x2604>
  222844:      	ldp	x9, x10, [sp, #0x38]
  222848:      	add	x23, x23, #0x1
  22284c:      	ldr	x11, [sp, #0x48]
  222850:      	str	q28, [sp, #0x10]
  222854:      	ldp	x8, x9, [x9]
  222858:      	rev	x0, x11
  22285c:      	rev	x1, x10
  222860:      	rev	x2, x9
  222864:      	rev	x3, x8
  222868:      	bl	0x2266ac <brynja_crypto_cpu::ghash_pmull::multiply>
  22286c:      	ldr	q28, [sp, #0x10]
  222870:      	mov	x8, xzr
  222874:      	mov	x11, xzr
  222878:      	rev	x9, x0
  22287c:      	rev	x10, x1
  222880:      	stp	x10, x9, [sp, #0x40]
  222884:      	b	0x222698 <brynja_ghash_timing::timed+0xf54>
  222888:      	cmp	x11, #0xf
  22288c:      	b.ls	0x2226a4 <brynja_ghash_timing::timed+0xf60>
  222890:      	b	0x222834 <brynja_ghash_timing::timed+0x10f0>
  222894:      	ldr	x10, [sp, #0x20]
  222898:      	mov	w9, #0x10               // =16
  22289c:      	stp	x10, x9, [x29, #-0x50]
  2228a0:      	sub	x9, x29, #0x50
  2228a4:      	ldur	x9, [x29, #-0x48]
  2228a8:      	subs	x24, x24, x9
  2228ac:      	b.lo	0x223b48 <brynja_ghash_timing::timed+0x2404>
  2228b0:      	cbz	x9, 0x222ae0 <brynja_ghash_timing::timed+0x139c>
  2228b4:      	mov	w10, #0x1               // =1
  2228b8:      	ldur	x21, [x29, #-0x50]
  2228bc:      	add	x25, sp, #0x40
  2228c0:      	dup	v28.2d, x10
  2228c4:      	add	x19, x25, #0x11
  2228c8:      	orr	x28, x25, #0x1
  2228cc:      	add	x26, x21, x9
  2228d0:      	add	x27, x9, x21
  2228d4:      	mov	w20, #0xf               // =15
  2228d8:      	mov	w22, #0x20              // =32
  2228dc:      	mov	x11, x8
  2228e0:      	b	0x2228ec <brynja_ghash_timing::timed+0x11a8>
  2228e4:      	cmp	x26, x21
  2228e8:      	b.eq	0x222ae0 <brynja_ghash_timing::timed+0x139c>
  2228ec:      	cbnz	x11, 0x222ad4 <brynja_ghash_timing::timed+0x1390>
  2228f0:      	cmp	x21, x26
  2228f4:      	b.eq	0x222ae0 <brynja_ghash_timing::timed+0x139c>
  2228f8:      	mvn	x9, x21
  2228fc:      	sub	x10, x20, x11
  222900:      	ldrb	w12, [x25, x11]
  222904:      	add	x9, x27, x9
  222908:      	cmp	x9, x10
  22290c:      	csel	x9, x9, x10, lo
  222910:      	ldrb	w10, [x21]
  222914:      	add	x9, x9, #0x1
  222918:      	cmp	x9, #0x21
  22291c:      	eor	w10, w12, w10
  222920:      	strb	w10, [x25, x11]
  222924:      	b.hs	0x222940 <brynja_ghash_timing::timed+0x11fc>
  222928:      	mov	x9, x11
  22292c:      	add	x8, x8, #0x1
  222930:      	add	x21, x21, #0x1
  222934:      	cmp	x11, #0xf
  222938:      	b.ne	0x222a54 <brynja_ghash_timing::timed+0x1310>
  22293c:      	b	0x222a7c <brynja_ghash_timing::timed+0x1338>
  222940:      	ands	x10, x9, #0x1f
  222944:      	movi	v0.2d, #0000000000000000
  222948:      	movi	v4.2d, #0000000000000000
  22294c:      	movi	v6.2d, #0000000000000000
  222950:      	movi	v1.2d, #0000000000000000
  222954:      	csel	x10, x22, x10, eq
  222958:      	movi	v3.2d, #0000000000000000
  22295c:      	movi	v2.2d, #0000000000000000
  222960:      	sub	x12, x9, x10
  222964:      	movi	v19.2d, #0000000000000000
  222968:      	movi	v7.2d, #0000000000000000
  22296c:      	add	x10, x21, x12
  222970:      	movi	v20.2d, #0000000000000000
  222974:      	movi	v5.2d, #0000000000000000
  222978:      	add	x9, x11, x12
  22297c:      	movi	v22.2d, #0000000000000000
  222980:      	movi	v17.2d, #0000000000000000
  222984:      	movi	v18.2d, #0000000000000000
  222988:      	movi	v16.2d, #0000000000000000
  22298c:      	movi	v23.2d, #0000000000000000
  222990:      	fmov	d21, x8
  222994:      	add	x8, x19, x11
  222998:      	add	x11, x21, #0x11
  22299c:      	ldp	q24, q25, [x11, #-0x10]
  2229a0:      	add	v0.2d, v0.2d, v28.2d
  2229a4:      	ldp	q26, q27, [x8, #-0x10]
  2229a8:      	add	v4.2d, v4.2d, v28.2d
  2229ac:      	add	v21.2d, v21.2d, v28.2d
  2229b0:      	add	v6.2d, v6.2d, v28.2d
  2229b4:      	add	v1.2d, v1.2d, v28.2d
  2229b8:      	add	v3.2d, v3.2d, v28.2d
  2229bc:      	add	v2.2d, v2.2d, v28.2d
  2229c0:      	add	v19.2d, v19.2d, v28.2d
  2229c4:      	eor	v24.16b, v26.16b, v24.16b
  2229c8:      	eor	v25.16b, v27.16b, v25.16b
  2229cc:      	subs	x12, x12, #0x20
  2229d0:      	add	v5.2d, v5.2d, v28.2d
  2229d4:      	add	v20.2d, v20.2d, v28.2d
  2229d8:      	add	x11, x11, #0x20
  2229dc:      	add	v7.2d, v7.2d, v28.2d
  2229e0:      	add	v22.2d, v22.2d, v28.2d
  2229e4:      	add	v17.2d, v17.2d, v28.2d
  2229e8:      	add	v18.2d, v18.2d, v28.2d
  2229ec:      	stp	q24, q25, [x8, #-0x10]
  2229f0:      	add	x8, x8, #0x20
  2229f4:      	add	v16.2d, v16.2d, v28.2d
  2229f8:      	add	v23.2d, v23.2d, v28.2d
  2229fc:      	b.ne	0x22299c <brynja_ghash_timing::timed+0x1258>
  222a00:      	add	v6.2d, v22.2d, v6.2d
  222a04:      	add	v19.2d, v23.2d, v19.2d
  222a08:      	add	v4.2d, v20.2d, v4.2d
  222a0c:      	add	v7.2d, v7.2d, v21.2d
  222a10:      	add	v1.2d, v17.2d, v1.2d
  222a14:      	add	v3.2d, v18.2d, v3.2d
  222a18:      	add	v0.2d, v5.2d, v0.2d
  222a1c:      	add	v2.2d, v16.2d, v2.2d
  222a20:      	add	v1.2d, v7.2d, v1.2d
  222a24:      	add	v0.2d, v0.2d, v2.2d
  222a28:      	add	v2.2d, v4.2d, v3.2d
  222a2c:      	add	v3.2d, v6.2d, v19.2d
  222a30:      	add	v0.2d, v1.2d, v0.2d
  222a34:      	add	v1.2d, v2.2d, v3.2d
  222a38:      	add	v0.2d, v0.2d, v1.2d
  222a3c:      	addp	d0, v0.2d
  222a40:      	fmov	x8, d0
  222a44:      	add	x8, x8, #0x1
  222a48:      	add	x21, x10, #0x1
  222a4c:      	cmp	x9, #0xf
  222a50:      	b.eq	0x222a7c <brynja_ghash_timing::timed+0x1338>
  222a54:      	cmp	x21, x26
  222a58:      	b.eq	0x222a7c <brynja_ghash_timing::timed+0x1338>
  222a5c:      	ldrb	w10, [x21], #0x1
  222a60:      	ldrb	w11, [x28, x9]
  222a64:      	add	x8, x8, #0x1
  222a68:      	eor	w10, w11, w10
  222a6c:      	strb	w10, [x28, x9]
  222a70:      	add	x9, x9, #0x1
  222a74:      	cmp	x9, #0xf
  222a78:      	b.ne	0x222a54 <brynja_ghash_timing::timed+0x1310>
  222a7c:      	mov	x11, x8
  222a80:      	cmp	x11, #0x10
  222a84:      	b.ne	0x2228e4 <brynja_ghash_timing::timed+0x11a0>
  222a88:      	cmn	x23, #0x1
  222a8c:      	b.eq	0x223d48 <brynja_ghash_timing::timed+0x2604>
  222a90:      	ldp	x9, x10, [sp, #0x38]
  222a94:      	add	x23, x23, #0x1
  222a98:      	ldr	x11, [sp, #0x48]
  222a9c:      	str	q28, [sp, #0x10]
  222aa0:      	ldp	x8, x9, [x9]
  222aa4:      	rev	x0, x11
  222aa8:      	rev	x1, x10
  222aac:      	rev	x2, x9
  222ab0:      	rev	x3, x8
  222ab4:      	bl	0x2266ac <brynja_crypto_cpu::ghash_pmull::multiply>
  222ab8:      	ldr	q28, [sp, #0x10]
  222abc:      	mov	x8, xzr
  222ac0:      	mov	x11, xzr
  222ac4:      	rev	x9, x0
  222ac8:      	rev	x10, x1
  222acc:      	stp	x10, x9, [sp, #0x40]
  222ad0:      	b	0x2228e4 <brynja_ghash_timing::timed+0x11a0>
  222ad4:      	cmp	x11, #0xf
  222ad8:      	b.ls	0x2228f0 <brynja_ghash_timing::timed+0x11ac>
  222adc:      	b	0x222a80 <brynja_ghash_timing::timed+0x133c>
  222ae0:      	ldr	x10, [sp, #0x20]
  222ae4:      	mov	w9, #0x10               // =16
  222ae8:      	stp	x10, x9, [x29, #-0x50]
  222aec:      	sub	x9, x29, #0x50
  222af0:      	ldur	x9, [x29, #-0x48]
  222af4:      	subs	x24, x24, x9
  222af8:      	b.lo	0x223b48 <brynja_ghash_timing::timed+0x2404>
  222afc:      	cbz	x9, 0x222d2c <brynja_ghash_timing::timed+0x15e8>
  222b00:      	mov	w10, #0x1               // =1
  222b04:      	ldur	x21, [x29, #-0x50]
  222b08:      	add	x25, sp, #0x40
  222b0c:      	dup	v28.2d, x10
  222b10:      	add	x19, x25, #0x11
  222b14:      	orr	x28, x25, #0x1
  222b18:      	add	x26, x21, x9
  222b1c:      	add	x27, x9, x21
  222b20:      	mov	w20, #0xf               // =15
  222b24:      	mov	w22, #0x20              // =32
  222b28:      	mov	x11, x8
  222b2c:      	b	0x222b38 <brynja_ghash_timing::timed+0x13f4>
  222b30:      	cmp	x26, x21
  222b34:      	b.eq	0x222d2c <brynja_ghash_timing::timed+0x15e8>
  222b38:      	cbnz	x11, 0x222d20 <brynja_ghash_timing::timed+0x15dc>
  222b3c:      	cmp	x21, x26
  222b40:      	b.eq	0x222d2c <brynja_ghash_timing::timed+0x15e8>
  222b44:      	mvn	x9, x21
  222b48:      	sub	x10, x20, x11
  222b4c:      	ldrb	w12, [x25, x11]
  222b50:      	add	x9, x27, x9
  222b54:      	cmp	x9, x10
  222b58:      	csel	x9, x9, x10, lo
  222b5c:      	ldrb	w10, [x21]
  222b60:      	add	x9, x9, #0x1
  222b64:      	cmp	x9, #0x21
  222b68:      	eor	w10, w12, w10
  222b6c:      	strb	w10, [x25, x11]
  222b70:      	b.hs	0x222b8c <brynja_ghash_timing::timed+0x1448>
  222b74:      	mov	x9, x11
  222b78:      	add	x8, x8, #0x1
  222b7c:      	add	x21, x21, #0x1
  222b80:      	cmp	x11, #0xf
  222b84:      	b.ne	0x222ca0 <brynja_ghash_timing::timed+0x155c>
  222b88:      	b	0x222cc8 <brynja_ghash_timing::timed+0x1584>
  222b8c:      	ands	x10, x9, #0x1f
  222b90:      	movi	v0.2d, #0000000000000000
  222b94:      	movi	v4.2d, #0000000000000000
  222b98:      	movi	v6.2d, #0000000000000000
  222b9c:      	movi	v1.2d, #0000000000000000
  222ba0:      	csel	x10, x22, x10, eq
  222ba4:      	movi	v3.2d, #0000000000000000
  222ba8:      	movi	v2.2d, #0000000000000000
  222bac:      	sub	x12, x9, x10
  222bb0:      	movi	v19.2d, #0000000000000000
  222bb4:      	movi	v7.2d, #0000000000000000
  222bb8:      	add	x10, x21, x12
  222bbc:      	movi	v20.2d, #0000000000000000
  222bc0:      	movi	v5.2d, #0000000000000000
  222bc4:      	add	x9, x11, x12
  222bc8:      	movi	v22.2d, #0000000000000000
  222bcc:      	movi	v17.2d, #0000000000000000
  222bd0:      	movi	v18.2d, #0000000000000000
  222bd4:      	movi	v16.2d, #0000000000000000
  222bd8:      	movi	v23.2d, #0000000000000000
  222bdc:      	fmov	d21, x8
  222be0:      	add	x8, x19, x11
  222be4:      	add	x11, x21, #0x11
  222be8:      	ldp	q24, q25, [x11, #-0x10]
  222bec:      	add	v0.2d, v0.2d, v28.2d
  222bf0:      	ldp	q26, q27, [x8, #-0x10]
  222bf4:      	add	v4.2d, v4.2d, v28.2d
  222bf8:      	add	v21.2d, v21.2d, v28.2d
  222bfc:      	add	v6.2d, v6.2d, v28.2d
  222c00:      	add	v1.2d, v1.2d, v28.2d
  222c04:      	add	v3.2d, v3.2d, v28.2d
  222c08:      	add	v2.2d, v2.2d, v28.2d
  222c0c:      	add	v19.2d, v19.2d, v28.2d
  222c10:      	eor	v24.16b, v26.16b, v24.16b
  222c14:      	eor	v25.16b, v27.16b, v25.16b
  222c18:      	subs	x12, x12, #0x20
  222c1c:      	add	v5.2d, v5.2d, v28.2d
  222c20:      	add	v20.2d, v20.2d, v28.2d
  222c24:      	add	x11, x11, #0x20
  222c28:      	add	v7.2d, v7.2d, v28.2d
  222c2c:      	add	v22.2d, v22.2d, v28.2d
  222c30:      	add	v17.2d, v17.2d, v28.2d
  222c34:      	add	v18.2d, v18.2d, v28.2d
  222c38:      	stp	q24, q25, [x8, #-0x10]
  222c3c:      	add	x8, x8, #0x20
  222c40:      	add	v16.2d, v16.2d, v28.2d
  222c44:      	add	v23.2d, v23.2d, v28.2d
  222c48:      	b.ne	0x222be8 <brynja_ghash_timing::timed+0x14a4>
  222c4c:      	add	v6.2d, v22.2d, v6.2d
  222c50:      	add	v19.2d, v23.2d, v19.2d
  222c54:      	add	v4.2d, v20.2d, v4.2d
  222c58:      	add	v7.2d, v7.2d, v21.2d
  222c5c:      	add	v1.2d, v17.2d, v1.2d
  222c60:      	add	v3.2d, v18.2d, v3.2d
  222c64:      	add	v0.2d, v5.2d, v0.2d
  222c68:      	add	v2.2d, v16.2d, v2.2d
  222c6c:      	add	v1.2d, v7.2d, v1.2d
  222c70:      	add	v0.2d, v0.2d, v2.2d
  222c74:      	add	v2.2d, v4.2d, v3.2d
  222c78:      	add	v3.2d, v6.2d, v19.2d
  222c7c:      	add	v0.2d, v1.2d, v0.2d
  222c80:      	add	v1.2d, v2.2d, v3.2d
  222c84:      	add	v0.2d, v0.2d, v1.2d
  222c88:      	addp	d0, v0.2d
  222c8c:      	fmov	x8, d0
  222c90:      	add	x8, x8, #0x1
  222c94:      	add	x21, x10, #0x1
  222c98:      	cmp	x9, #0xf
  222c9c:      	b.eq	0x222cc8 <brynja_ghash_timing::timed+0x1584>
  222ca0:      	cmp	x21, x26
  222ca4:      	b.eq	0x222cc8 <brynja_ghash_timing::timed+0x1584>
  222ca8:      	ldrb	w10, [x21], #0x1
  222cac:      	ldrb	w11, [x28, x9]
  222cb0:      	add	x8, x8, #0x1
  222cb4:      	eor	w10, w11, w10
  222cb8:      	strb	w10, [x28, x9]
  222cbc:      	add	x9, x9, #0x1
  222cc0:      	cmp	x9, #0xf
  222cc4:      	b.ne	0x222ca0 <brynja_ghash_timing::timed+0x155c>
  222cc8:      	mov	x11, x8
  222ccc:      	cmp	x11, #0x10
  222cd0:      	b.ne	0x222b30 <brynja_ghash_timing::timed+0x13ec>
  222cd4:      	cmn	x23, #0x1
  222cd8:      	b.eq	0x223d48 <brynja_ghash_timing::timed+0x2604>
  222cdc:      	ldp	x9, x10, [sp, #0x38]
  222ce0:      	add	x23, x23, #0x1
  222ce4:      	ldr	x11, [sp, #0x48]
  222ce8:      	str	q28, [sp, #0x10]
  222cec:      	ldp	x8, x9, [x9]
  222cf0:      	rev	x0, x11
  222cf4:      	rev	x1, x10
  222cf8:      	rev	x2, x9
  222cfc:      	rev	x3, x8
  222d00:      	bl	0x2266ac <brynja_crypto_cpu::ghash_pmull::multiply>
  222d04:      	ldr	q28, [sp, #0x10]
  222d08:      	mov	x8, xzr
  222d0c:      	mov	x11, xzr
  222d10:      	rev	x9, x0
  222d14:      	rev	x10, x1
  222d18:      	stp	x10, x9, [sp, #0x40]
  222d1c:      	b	0x222b30 <brynja_ghash_timing::timed+0x13ec>
  222d20:      	cmp	x11, #0xf
  222d24:      	b.ls	0x222b3c <brynja_ghash_timing::timed+0x13f8>
  222d28:      	b	0x222ccc <brynja_ghash_timing::timed+0x1588>
  222d2c:      	ldr	x10, [sp, #0x20]
  222d30:      	mov	w9, #0x10               // =16
  222d34:      	stp	x10, x9, [x29, #-0x50]
  222d38:      	sub	x9, x29, #0x50
  222d3c:      	ldur	x9, [x29, #-0x48]
  222d40:      	subs	x24, x24, x9
  222d44:      	b.lo	0x223b48 <brynja_ghash_timing::timed+0x2404>
  222d48:      	cbz	x9, 0x222f78 <brynja_ghash_timing::timed+0x1834>
  222d4c:      	mov	w10, #0x1               // =1
  222d50:      	ldur	x21, [x29, #-0x50]
  222d54:      	add	x25, sp, #0x40
  222d58:      	dup	v28.2d, x10
  222d5c:      	add	x19, x25, #0x11
  222d60:      	orr	x28, x25, #0x1
  222d64:      	add	x26, x21, x9
  222d68:      	add	x27, x9, x21
  222d6c:      	mov	w20, #0xf               // =15
  222d70:      	mov	w22, #0x20              // =32
  222d74:      	mov	x11, x8
  222d78:      	b	0x222d84 <brynja_ghash_timing::timed+0x1640>
  222d7c:      	cmp	x26, x21
  222d80:      	b.eq	0x222f78 <brynja_ghash_timing::timed+0x1834>
  222d84:      	cbnz	x11, 0x222f6c <brynja_ghash_timing::timed+0x1828>
  222d88:      	cmp	x21, x26
  222d8c:      	b.eq	0x222f78 <brynja_ghash_timing::timed+0x1834>
  222d90:      	mvn	x9, x21
  222d94:      	sub	x10, x20, x11
  222d98:      	ldrb	w12, [x25, x11]
  222d9c:      	add	x9, x27, x9
  222da0:      	cmp	x9, x10
  222da4:      	csel	x9, x9, x10, lo
  222da8:      	ldrb	w10, [x21]
  222dac:      	add	x9, x9, #0x1
  222db0:      	cmp	x9, #0x21
  222db4:      	eor	w10, w12, w10
  222db8:      	strb	w10, [x25, x11]
  222dbc:      	b.hs	0x222dd8 <brynja_ghash_timing::timed+0x1694>
  222dc0:      	mov	x9, x11
  222dc4:      	add	x8, x8, #0x1
  222dc8:      	add	x21, x21, #0x1
  222dcc:      	cmp	x11, #0xf
  222dd0:      	b.ne	0x222eec <brynja_ghash_timing::timed+0x17a8>
  222dd4:      	b	0x222f14 <brynja_ghash_timing::timed+0x17d0>
  222dd8:      	ands	x10, x9, #0x1f
  222ddc:      	movi	v0.2d, #0000000000000000
  222de0:      	movi	v4.2d, #0000000000000000
  222de4:      	movi	v6.2d, #0000000000000000
  222de8:      	movi	v1.2d, #0000000000000000
  222dec:      	csel	x10, x22, x10, eq
  222df0:      	movi	v3.2d, #0000000000000000
  222df4:      	movi	v2.2d, #0000000000000000
  222df8:      	sub	x12, x9, x10
  222dfc:      	movi	v19.2d, #0000000000000000
  222e00:      	movi	v7.2d, #0000000000000000
  222e04:      	add	x10, x21, x12
  222e08:      	movi	v20.2d, #0000000000000000
  222e0c:      	movi	v5.2d, #0000000000000000
  222e10:      	add	x9, x11, x12
  222e14:      	movi	v22.2d, #0000000000000000
  222e18:      	movi	v17.2d, #0000000000000000
  222e1c:      	movi	v18.2d, #0000000000000000
  222e20:      	movi	v16.2d, #0000000000000000
  222e24:      	movi	v23.2d, #0000000000000000
  222e28:      	fmov	d21, x8
  222e2c:      	add	x8, x19, x11
  222e30:      	add	x11, x21, #0x11
  222e34:      	ldp	q24, q25, [x11, #-0x10]
  222e38:      	add	v0.2d, v0.2d, v28.2d
  222e3c:      	ldp	q26, q27, [x8, #-0x10]
  222e40:      	add	v4.2d, v4.2d, v28.2d
  222e44:      	add	v21.2d, v21.2d, v28.2d
  222e48:      	add	v6.2d, v6.2d, v28.2d
  222e4c:      	add	v1.2d, v1.2d, v28.2d
  222e50:      	add	v3.2d, v3.2d, v28.2d
  222e54:      	add	v2.2d, v2.2d, v28.2d
  222e58:      	add	v19.2d, v19.2d, v28.2d
  222e5c:      	eor	v24.16b, v26.16b, v24.16b
  222e60:      	eor	v25.16b, v27.16b, v25.16b
  222e64:      	subs	x12, x12, #0x20
  222e68:      	add	v5.2d, v5.2d, v28.2d
  222e6c:      	add	v20.2d, v20.2d, v28.2d
  222e70:      	add	x11, x11, #0x20
  222e74:      	add	v7.2d, v7.2d, v28.2d
  222e78:      	add	v22.2d, v22.2d, v28.2d
  222e7c:      	add	v17.2d, v17.2d, v28.2d
  222e80:      	add	v18.2d, v18.2d, v28.2d
  222e84:      	stp	q24, q25, [x8, #-0x10]
  222e88:      	add	x8, x8, #0x20
  222e8c:      	add	v16.2d, v16.2d, v28.2d
  222e90:      	add	v23.2d, v23.2d, v28.2d
  222e94:      	b.ne	0x222e34 <brynja_ghash_timing::timed+0x16f0>
  222e98:      	add	v6.2d, v22.2d, v6.2d
  222e9c:      	add	v19.2d, v23.2d, v19.2d
  222ea0:      	add	v4.2d, v20.2d, v4.2d
  222ea4:      	add	v7.2d, v7.2d, v21.2d
  222ea8:      	add	v1.2d, v17.2d, v1.2d
  222eac:      	add	v3.2d, v18.2d, v3.2d
  222eb0:      	add	v0.2d, v5.2d, v0.2d
  222eb4:      	add	v2.2d, v16.2d, v2.2d
  222eb8:      	add	v1.2d, v7.2d, v1.2d
  222ebc:      	add	v0.2d, v0.2d, v2.2d
  222ec0:      	add	v2.2d, v4.2d, v3.2d
  222ec4:      	add	v3.2d, v6.2d, v19.2d
  222ec8:      	add	v0.2d, v1.2d, v0.2d
  222ecc:      	add	v1.2d, v2.2d, v3.2d
  222ed0:      	add	v0.2d, v0.2d, v1.2d
  222ed4:      	addp	d0, v0.2d
  222ed8:      	fmov	x8, d0
  222edc:      	add	x8, x8, #0x1
  222ee0:      	add	x21, x10, #0x1
  222ee4:      	cmp	x9, #0xf
  222ee8:      	b.eq	0x222f14 <brynja_ghash_timing::timed+0x17d0>
  222eec:      	cmp	x21, x26
  222ef0:      	b.eq	0x222f14 <brynja_ghash_timing::timed+0x17d0>
  222ef4:      	ldrb	w10, [x21], #0x1
  222ef8:      	ldrb	w11, [x28, x9]
  222efc:      	add	x8, x8, #0x1
  222f00:      	eor	w10, w11, w10
  222f04:      	strb	w10, [x28, x9]
  222f08:      	add	x9, x9, #0x1
  222f0c:      	cmp	x9, #0xf
  222f10:      	b.ne	0x222eec <brynja_ghash_timing::timed+0x17a8>
  222f14:      	mov	x11, x8
  222f18:      	cmp	x11, #0x10
  222f1c:      	b.ne	0x222d7c <brynja_ghash_timing::timed+0x1638>
  222f20:      	cmn	x23, #0x1
  222f24:      	b.eq	0x223d48 <brynja_ghash_timing::timed+0x2604>
  222f28:      	ldp	x9, x10, [sp, #0x38]
  222f2c:      	add	x23, x23, #0x1
  222f30:      	ldr	x11, [sp, #0x48]
  222f34:      	str	q28, [sp, #0x10]
  222f38:      	ldp	x8, x9, [x9]
  222f3c:      	rev	x0, x11
  222f40:      	rev	x1, x10
  222f44:      	rev	x2, x9
  222f48:      	rev	x3, x8
  222f4c:      	bl	0x2266ac <brynja_crypto_cpu::ghash_pmull::multiply>
  222f50:      	ldr	q28, [sp, #0x10]
  222f54:      	mov	x8, xzr
  222f58:      	mov	x11, xzr
  222f5c:      	rev	x9, x0
  222f60:      	rev	x10, x1
  222f64:      	stp	x10, x9, [sp, #0x40]
  222f68:      	b	0x222d7c <brynja_ghash_timing::timed+0x1638>
  222f6c:      	cmp	x11, #0xf
  222f70:      	b.ls	0x222d88 <brynja_ghash_timing::timed+0x1644>
  222f74:      	b	0x222f18 <brynja_ghash_timing::timed+0x17d4>
  222f78:      	ldr	x10, [sp, #0x20]
  222f7c:      	mov	w9, #0x10               // =16
  222f80:      	stp	x10, x9, [x29, #-0x50]
  222f84:      	sub	x9, x29, #0x50
  222f88:      	ldur	x9, [x29, #-0x48]
  222f8c:      	subs	x24, x24, x9
  222f90:      	b.lo	0x223b48 <brynja_ghash_timing::timed+0x2404>
  222f94:      	cbz	x9, 0x2231c4 <brynja_ghash_timing::timed+0x1a80>
  222f98:      	mov	w10, #0x1               // =1
  222f9c:      	ldur	x21, [x29, #-0x50]
  222fa0:      	add	x25, sp, #0x40
  222fa4:      	dup	v28.2d, x10
  222fa8:      	add	x19, x25, #0x11
  222fac:      	orr	x28, x25, #0x1
  222fb0:      	add	x26, x21, x9
  222fb4:      	add	x27, x9, x21
  222fb8:      	mov	w20, #0xf               // =15
  222fbc:      	mov	w22, #0x20              // =32
  222fc0:      	mov	x11, x8
  222fc4:      	b	0x222fd0 <brynja_ghash_timing::timed+0x188c>
  222fc8:      	cmp	x26, x21
  222fcc:      	b.eq	0x2231c4 <brynja_ghash_timing::timed+0x1a80>
  222fd0:      	cbnz	x11, 0x2231b8 <brynja_ghash_timing::timed+0x1a74>
  222fd4:      	cmp	x21, x26
  222fd8:      	b.eq	0x2231c4 <brynja_ghash_timing::timed+0x1a80>
  222fdc:      	mvn	x9, x21
  222fe0:      	sub	x10, x20, x11
  222fe4:      	ldrb	w12, [x25, x11]
  222fe8:      	add	x9, x27, x9
  222fec:      	cmp	x9, x10
  222ff0:      	csel	x9, x9, x10, lo
  222ff4:      	ldrb	w10, [x21]
  222ff8:      	add	x9, x9, #0x1
  222ffc:      	cmp	x9, #0x21
  223000:      	eor	w10, w12, w10
  223004:      	strb	w10, [x25, x11]
  223008:      	b.hs	0x223024 <brynja_ghash_timing::timed+0x18e0>
  22300c:      	mov	x9, x11
  223010:      	add	x8, x8, #0x1
  223014:      	add	x21, x21, #0x1
  223018:      	cmp	x11, #0xf
  22301c:      	b.ne	0x223138 <brynja_ghash_timing::timed+0x19f4>
  223020:      	b	0x223160 <brynja_ghash_timing::timed+0x1a1c>
  223024:      	ands	x10, x9, #0x1f
  223028:      	movi	v0.2d, #0000000000000000
  22302c:      	movi	v4.2d, #0000000000000000
  223030:      	movi	v6.2d, #0000000000000000
  223034:      	movi	v1.2d, #0000000000000000
  223038:      	csel	x10, x22, x10, eq
  22303c:      	movi	v3.2d, #0000000000000000
  223040:      	movi	v2.2d, #0000000000000000
  223044:      	sub	x12, x9, x10
  223048:      	movi	v19.2d, #0000000000000000
  22304c:      	movi	v7.2d, #0000000000000000
  223050:      	add	x10, x21, x12
  223054:      	movi	v20.2d, #0000000000000000
  223058:      	movi	v5.2d, #0000000000000000
  22305c:      	add	x9, x11, x12
  223060:      	movi	v22.2d, #0000000000000000
  223064:      	movi	v17.2d, #0000000000000000
  223068:      	movi	v18.2d, #0000000000000000
  22306c:      	movi	v16.2d, #0000000000000000
  223070:      	movi	v23.2d, #0000000000000000
  223074:      	fmov	d21, x8
  223078:      	add	x8, x19, x11
  22307c:      	add	x11, x21, #0x11
  223080:      	ldp	q24, q25, [x11, #-0x10]
  223084:      	add	v0.2d, v0.2d, v28.2d
  223088:      	ldp	q26, q27, [x8, #-0x10]
  22308c:      	add	v4.2d, v4.2d, v28.2d
  223090:      	add	v21.2d, v21.2d, v28.2d
  223094:      	add	v6.2d, v6.2d, v28.2d
  223098:      	add	v1.2d, v1.2d, v28.2d
  22309c:      	add	v3.2d, v3.2d, v28.2d
  2230a0:      	add	v2.2d, v2.2d, v28.2d
  2230a4:      	add	v19.2d, v19.2d, v28.2d
  2230a8:      	eor	v24.16b, v26.16b, v24.16b
  2230ac:      	eor	v25.16b, v27.16b, v25.16b
  2230b0:      	subs	x12, x12, #0x20
  2230b4:      	add	v5.2d, v5.2d, v28.2d
  2230b8:      	add	v20.2d, v20.2d, v28.2d
  2230bc:      	add	x11, x11, #0x20
  2230c0:      	add	v7.2d, v7.2d, v28.2d
  2230c4:      	add	v22.2d, v22.2d, v28.2d
  2230c8:      	add	v17.2d, v17.2d, v28.2d
  2230cc:      	add	v18.2d, v18.2d, v28.2d
  2230d0:      	stp	q24, q25, [x8, #-0x10]
  2230d4:      	add	x8, x8, #0x20
  2230d8:      	add	v16.2d, v16.2d, v28.2d
  2230dc:      	add	v23.2d, v23.2d, v28.2d
  2230e0:      	b.ne	0x223080 <brynja_ghash_timing::timed+0x193c>
  2230e4:      	add	v6.2d, v22.2d, v6.2d
  2230e8:      	add	v19.2d, v23.2d, v19.2d
  2230ec:      	add	v4.2d, v20.2d, v4.2d
  2230f0:      	add	v7.2d, v7.2d, v21.2d
  2230f4:      	add	v1.2d, v17.2d, v1.2d
  2230f8:      	add	v3.2d, v18.2d, v3.2d
  2230fc:      	add	v0.2d, v5.2d, v0.2d
  223100:      	add	v2.2d, v16.2d, v2.2d
  223104:      	add	v1.2d, v7.2d, v1.2d
  223108:      	add	v0.2d, v0.2d, v2.2d
  22310c:      	add	v2.2d, v4.2d, v3.2d
  223110:      	add	v3.2d, v6.2d, v19.2d
  223114:      	add	v0.2d, v1.2d, v0.2d
  223118:      	add	v1.2d, v2.2d, v3.2d
  22311c:      	add	v0.2d, v0.2d, v1.2d
  223120:      	addp	d0, v0.2d
  223124:      	fmov	x8, d0
  223128:      	add	x8, x8, #0x1
  22312c:      	add	x21, x10, #0x1
  223130:      	cmp	x9, #0xf
  223134:      	b.eq	0x223160 <brynja_ghash_timing::timed+0x1a1c>
  223138:      	cmp	x21, x26
  22313c:      	b.eq	0x223160 <brynja_ghash_timing::timed+0x1a1c>
  223140:      	ldrb	w10, [x21], #0x1
  223144:      	ldrb	w11, [x28, x9]
  223148:      	add	x8, x8, #0x1
  22314c:      	eor	w10, w11, w10
  223150:      	strb	w10, [x28, x9]
  223154:      	add	x9, x9, #0x1
  223158:      	cmp	x9, #0xf
  22315c:      	b.ne	0x223138 <brynja_ghash_timing::timed+0x19f4>
  223160:      	mov	x11, x8
  223164:      	cmp	x11, #0x10
  223168:      	b.ne	0x222fc8 <brynja_ghash_timing::timed+0x1884>
  22316c:      	cmn	x23, #0x1
  223170:      	b.eq	0x223d48 <brynja_ghash_timing::timed+0x2604>
  223174:      	ldp	x9, x10, [sp, #0x38]
  223178:      	add	x23, x23, #0x1
  22317c:      	ldr	x11, [sp, #0x48]
  223180:      	str	q28, [sp, #0x10]
  223184:      	ldp	x8, x9, [x9]
  223188:      	rev	x0, x11
  22318c:      	rev	x1, x10
  223190:      	rev	x2, x9
  223194:      	rev	x3, x8
  223198:      	bl	0x2266ac <brynja_crypto_cpu::ghash_pmull::multiply>
  22319c:      	ldr	q28, [sp, #0x10]
  2231a0:      	mov	x8, xzr
  2231a4:      	mov	x11, xzr
  2231a8:      	rev	x9, x0
  2231ac:      	rev	x10, x1
  2231b0:      	stp	x10, x9, [sp, #0x40]
  2231b4:      	b	0x222fc8 <brynja_ghash_timing::timed+0x1884>
  2231b8:      	cmp	x11, #0xf
  2231bc:      	b.ls	0x222fd4 <brynja_ghash_timing::timed+0x1890>
  2231c0:      	b	0x223164 <brynja_ghash_timing::timed+0x1a20>
  2231c4:      	ldr	x10, [sp, #0x20]
  2231c8:      	mov	w9, #0x10               // =16
  2231cc:      	stp	x10, x9, [x29, #-0x50]
  2231d0:      	sub	x9, x29, #0x50
  2231d4:      	ldur	x9, [x29, #-0x48]
  2231d8:      	subs	x24, x24, x9
  2231dc:      	b.lo	0x223b48 <brynja_ghash_timing::timed+0x2404>
  2231e0:      	cbz	x9, 0x223410 <brynja_ghash_timing::timed+0x1ccc>
  2231e4:      	mov	w10, #0x1               // =1
  2231e8:      	ldur	x21, [x29, #-0x50]
  2231ec:      	add	x25, sp, #0x40
  2231f0:      	dup	v28.2d, x10
  2231f4:      	add	x19, x25, #0x11
  2231f8:      	orr	x28, x25, #0x1
  2231fc:      	add	x26, x21, x9
  223200:      	add	x27, x9, x21
  223204:      	mov	w20, #0xf               // =15
  223208:      	mov	w22, #0x20              // =32
  22320c:      	mov	x11, x8
  223210:      	b	0x22321c <brynja_ghash_timing::timed+0x1ad8>
  223214:      	cmp	x26, x21
  223218:      	b.eq	0x223410 <brynja_ghash_timing::timed+0x1ccc>
  22321c:      	cbnz	x11, 0x223404 <brynja_ghash_timing::timed+0x1cc0>
  223220:      	cmp	x21, x26
  223224:      	b.eq	0x223410 <brynja_ghash_timing::timed+0x1ccc>
  223228:      	mvn	x9, x21
  22322c:      	sub	x10, x20, x11
  223230:      	ldrb	w12, [x25, x11]
  223234:      	add	x9, x27, x9
  223238:      	cmp	x9, x10
  22323c:      	csel	x9, x9, x10, lo
  223240:      	ldrb	w10, [x21]
  223244:      	add	x9, x9, #0x1
  223248:      	cmp	x9, #0x21
  22324c:      	eor	w10, w12, w10
  223250:      	strb	w10, [x25, x11]
  223254:      	b.hs	0x223270 <brynja_ghash_timing::timed+0x1b2c>
  223258:      	mov	x9, x11
  22325c:      	add	x8, x8, #0x1
  223260:      	add	x21, x21, #0x1
  223264:      	cmp	x11, #0xf
  223268:      	b.ne	0x223384 <brynja_ghash_timing::timed+0x1c40>
  22326c:      	b	0x2233ac <brynja_ghash_timing::timed+0x1c68>
  223270:      	ands	x10, x9, #0x1f
  223274:      	movi	v0.2d, #0000000000000000
  223278:      	movi	v4.2d, #0000000000000000
  22327c:      	movi	v6.2d, #0000000000000000
  223280:      	movi	v1.2d, #0000000000000000
  223284:      	csel	x10, x22, x10, eq
  223288:      	movi	v3.2d, #0000000000000000
  22328c:      	movi	v2.2d, #0000000000000000
  223290:      	sub	x12, x9, x10
  223294:      	movi	v19.2d, #0000000000000000
  223298:      	movi	v7.2d, #0000000000000000
  22329c:      	add	x10, x21, x12
  2232a0:      	movi	v20.2d, #0000000000000000
  2232a4:      	movi	v5.2d, #0000000000000000
  2232a8:      	add	x9, x11, x12
  2232ac:      	movi	v22.2d, #0000000000000000
  2232b0:      	movi	v17.2d, #0000000000000000
  2232b4:      	movi	v18.2d, #0000000000000000
  2232b8:      	movi	v16.2d, #0000000000000000
  2232bc:      	movi	v23.2d, #0000000000000000
  2232c0:      	fmov	d21, x8
  2232c4:      	add	x8, x19, x11
  2232c8:      	add	x11, x21, #0x11
  2232cc:      	ldp	q24, q25, [x11, #-0x10]
  2232d0:      	add	v0.2d, v0.2d, v28.2d
  2232d4:      	ldp	q26, q27, [x8, #-0x10]
  2232d8:      	add	v4.2d, v4.2d, v28.2d
  2232dc:      	add	v21.2d, v21.2d, v28.2d
  2232e0:      	add	v6.2d, v6.2d, v28.2d
  2232e4:      	add	v1.2d, v1.2d, v28.2d
  2232e8:      	add	v3.2d, v3.2d, v28.2d
  2232ec:      	add	v2.2d, v2.2d, v28.2d
  2232f0:      	add	v19.2d, v19.2d, v28.2d
  2232f4:      	eor	v24.16b, v26.16b, v24.16b
  2232f8:      	eor	v25.16b, v27.16b, v25.16b
  2232fc:      	subs	x12, x12, #0x20
  223300:      	add	v5.2d, v5.2d, v28.2d
  223304:      	add	v20.2d, v20.2d, v28.2d
  223308:      	add	x11, x11, #0x20
  22330c:      	add	v7.2d, v7.2d, v28.2d
  223310:      	add	v22.2d, v22.2d, v28.2d
  223314:      	add	v17.2d, v17.2d, v28.2d
  223318:      	add	v18.2d, v18.2d, v28.2d
  22331c:      	stp	q24, q25, [x8, #-0x10]
  223320:      	add	x8, x8, #0x20
  223324:      	add	v16.2d, v16.2d, v28.2d
  223328:      	add	v23.2d, v23.2d, v28.2d
  22332c:      	b.ne	0x2232cc <brynja_ghash_timing::timed+0x1b88>
  223330:      	add	v6.2d, v22.2d, v6.2d
  223334:      	add	v19.2d, v23.2d, v19.2d
  223338:      	add	v4.2d, v20.2d, v4.2d
  22333c:      	add	v7.2d, v7.2d, v21.2d
  223340:      	add	v1.2d, v17.2d, v1.2d
  223344:      	add	v3.2d, v18.2d, v3.2d
  223348:      	add	v0.2d, v5.2d, v0.2d
  22334c:      	add	v2.2d, v16.2d, v2.2d
  223350:      	add	v1.2d, v7.2d, v1.2d
  223354:      	add	v0.2d, v0.2d, v2.2d
  223358:      	add	v2.2d, v4.2d, v3.2d
  22335c:      	add	v3.2d, v6.2d, v19.2d
  223360:      	add	v0.2d, v1.2d, v0.2d
  223364:      	add	v1.2d, v2.2d, v3.2d
  223368:      	add	v0.2d, v0.2d, v1.2d
  22336c:      	addp	d0, v0.2d
  223370:      	fmov	x8, d0
  223374:      	add	x8, x8, #0x1
  223378:      	add	x21, x10, #0x1
  22337c:      	cmp	x9, #0xf
  223380:      	b.eq	0x2233ac <brynja_ghash_timing::timed+0x1c68>
  223384:      	cmp	x21, x26
  223388:      	b.eq	0x2233ac <brynja_ghash_timing::timed+0x1c68>
  22338c:      	ldrb	w10, [x21], #0x1
  223390:      	ldrb	w11, [x28, x9]
  223394:      	add	x8, x8, #0x1
  223398:      	eor	w10, w11, w10
  22339c:      	strb	w10, [x28, x9]
  2233a0:      	add	x9, x9, #0x1
  2233a4:      	cmp	x9, #0xf
  2233a8:      	b.ne	0x223384 <brynja_ghash_timing::timed+0x1c40>
  2233ac:      	mov	x11, x8
  2233b0:      	cmp	x11, #0x10
  2233b4:      	b.ne	0x223214 <brynja_ghash_timing::timed+0x1ad0>
  2233b8:      	cmn	x23, #0x1
  2233bc:      	b.eq	0x223d48 <brynja_ghash_timing::timed+0x2604>
  2233c0:      	ldp	x9, x10, [sp, #0x38]
  2233c4:      	add	x23, x23, #0x1
  2233c8:      	ldr	x11, [sp, #0x48]
  2233cc:      	str	q28, [sp, #0x10]
  2233d0:      	ldp	x8, x9, [x9]
  2233d4:      	rev	x0, x11
  2233d8:      	rev	x1, x10
  2233dc:      	rev	x2, x9
  2233e0:      	rev	x3, x8
  2233e4:      	bl	0x2266ac <brynja_crypto_cpu::ghash_pmull::multiply>
  2233e8:      	ldr	q28, [sp, #0x10]
  2233ec:      	mov	x8, xzr
  2233f0:      	mov	x11, xzr
  2233f4:      	rev	x9, x0
  2233f8:      	rev	x10, x1
  2233fc:      	stp	x10, x9, [sp, #0x40]
  223400:      	b	0x223214 <brynja_ghash_timing::timed+0x1ad0>
  223404:      	cmp	x11, #0xf
  223408:      	b.ls	0x223220 <brynja_ghash_timing::timed+0x1adc>
  22340c:      	b	0x2233b0 <brynja_ghash_timing::timed+0x1c6c>
  223410:      	ldr	x10, [sp, #0x20]
  223414:      	mov	w9, #0x10               // =16
  223418:      	stp	x10, x9, [x29, #-0x50]
  22341c:      	sub	x9, x29, #0x50
  223420:      	ldur	x9, [x29, #-0x48]
  223424:      	subs	x24, x24, x9
  223428:      	b.lo	0x223b48 <brynja_ghash_timing::timed+0x2404>
  22342c:      	cbz	x9, 0x22365c <brynja_ghash_timing::timed+0x1f18>
  223430:      	mov	w10, #0x1               // =1
  223434:      	ldur	x21, [x29, #-0x50]
  223438:      	add	x25, sp, #0x40
  22343c:      	dup	v28.2d, x10
  223440:      	add	x19, x25, #0x11
  223444:      	orr	x28, x25, #0x1
  223448:      	add	x26, x21, x9
  22344c:      	add	x27, x9, x21
  223450:      	mov	w20, #0xf               // =15
  223454:      	mov	w22, #0x20              // =32
  223458:      	mov	x11, x8
  22345c:      	str	q28, [sp, #0x10]
  223460:      	b	0x2234a8 <brynja_ghash_timing::timed+0x1d64>
  223464:      	ldp	x9, x10, [sp, #0x38]
  223468:      	add	x23, x23, #0x1
  22346c:      	ldr	x11, [sp, #0x48]
  223470:      	ldp	x8, x9, [x9]
  223474:      	rev	x0, x11
  223478:      	rev	x1, x10
  22347c:      	rev	x2, x9
  223480:      	rev	x3, x8
  223484:      	bl	0x2266ac <brynja_crypto_cpu::ghash_pmull::multiply>
  223488:      	ldr	q28, [sp, #0x10]
  22348c:      	mov	x8, xzr
  223490:      	mov	x11, xzr
  223494:      	rev	x9, x0
  223498:      	rev	x10, x1
  22349c:      	stp	x10, x9, [sp, #0x40]
  2234a0:      	cmp	x26, x21
  2234a4:      	b.eq	0x22365c <brynja_ghash_timing::timed+0x1f18>
  2234a8:      	cbnz	x11, 0x223650 <brynja_ghash_timing::timed+0x1f0c>
  2234ac:      	cmp	x21, x26
  2234b0:      	b.eq	0x22365c <brynja_ghash_timing::timed+0x1f18>
  2234b4:      	mvn	x9, x21
  2234b8:      	sub	x10, x20, x11
  2234bc:      	ldrb	w12, [x25, x11]
  2234c0:      	add	x9, x27, x9
  2234c4:      	cmp	x9, x10
  2234c8:      	csel	x9, x9, x10, lo
  2234cc:      	ldrb	w10, [x21]
  2234d0:      	add	x9, x9, #0x1
  2234d4:      	cmp	x9, #0x21
  2234d8:      	eor	w10, w12, w10
  2234dc:      	strb	w10, [x25, x11]
  2234e0:      	b.hs	0x2234fc <brynja_ghash_timing::timed+0x1db8>
  2234e4:      	mov	x9, x11
  2234e8:      	add	x8, x8, #0x1
  2234ec:      	add	x21, x21, #0x1
  2234f0:      	cmp	x11, #0xf
  2234f4:      	b.ne	0x223610 <brynja_ghash_timing::timed+0x1ecc>
  2234f8:      	b	0x223638 <brynja_ghash_timing::timed+0x1ef4>
  2234fc:      	ands	x10, x9, #0x1f
  223500:      	movi	v0.2d, #0000000000000000
  223504:      	movi	v4.2d, #0000000000000000
  223508:      	movi	v6.2d, #0000000000000000
  22350c:      	movi	v1.2d, #0000000000000000
  223510:      	csel	x10, x22, x10, eq
  223514:      	movi	v3.2d, #0000000000000000
  223518:      	movi	v2.2d, #0000000000000000
  22351c:      	sub	x12, x9, x10
  223520:      	movi	v19.2d, #0000000000000000
  223524:      	movi	v7.2d, #0000000000000000
  223528:      	add	x10, x21, x12
  22352c:      	movi	v20.2d, #0000000000000000
  223530:      	movi	v5.2d, #0000000000000000
  223534:      	add	x9, x11, x12
  223538:      	movi	v22.2d, #0000000000000000
  22353c:      	movi	v17.2d, #0000000000000000
  223540:      	movi	v18.2d, #0000000000000000
  223544:      	movi	v16.2d, #0000000000000000
  223548:      	movi	v23.2d, #0000000000000000
  22354c:      	fmov	d21, x8
  223550:      	add	x8, x19, x11
  223554:      	add	x11, x21, #0x11
  223558:      	ldp	q24, q25, [x11, #-0x10]
  22355c:      	add	v0.2d, v0.2d, v28.2d
  223560:      	ldp	q26, q27, [x8, #-0x10]
  223564:      	add	v4.2d, v4.2d, v28.2d
  223568:      	add	v21.2d, v21.2d, v28.2d
  22356c:      	add	v6.2d, v6.2d, v28.2d
  223570:      	add	v1.2d, v1.2d, v28.2d
  223574:      	add	v3.2d, v3.2d, v28.2d
  223578:      	add	v2.2d, v2.2d, v28.2d
  22357c:      	add	v19.2d, v19.2d, v28.2d
  223580:      	eor	v24.16b, v26.16b, v24.16b
  223584:      	eor	v25.16b, v27.16b, v25.16b
  223588:      	subs	x12, x12, #0x20
  22358c:      	add	v5.2d, v5.2d, v28.2d
  223590:      	add	v20.2d, v20.2d, v28.2d
  223594:      	add	x11, x11, #0x20
  223598:      	add	v7.2d, v7.2d, v28.2d
  22359c:      	add	v22.2d, v22.2d, v28.2d
  2235a0:      	add	v17.2d, v17.2d, v28.2d
  2235a4:      	add	v18.2d, v18.2d, v28.2d
  2235a8:      	stp	q24, q25, [x8, #-0x10]
  2235ac:      	add	x8, x8, #0x20
  2235b0:      	add	v16.2d, v16.2d, v28.2d
  2235b4:      	add	v23.2d, v23.2d, v28.2d
  2235b8:      	b.ne	0x223558 <brynja_ghash_timing::timed+0x1e14>
  2235bc:      	add	v6.2d, v22.2d, v6.2d
  2235c0:      	add	v19.2d, v23.2d, v19.2d
  2235c4:      	add	v4.2d, v20.2d, v4.2d
  2235c8:      	add	v7.2d, v7.2d, v21.2d
  2235cc:      	add	v1.2d, v17.2d, v1.2d
  2235d0:      	add	v3.2d, v18.2d, v3.2d
  2235d4:      	add	v0.2d, v5.2d, v0.2d
  2235d8:      	add	v2.2d, v16.2d, v2.2d
  2235dc:      	add	v1.2d, v7.2d, v1.2d
  2235e0:      	add	v0.2d, v0.2d, v2.2d
  2235e4:      	add	v2.2d, v4.2d, v3.2d
  2235e8:      	add	v3.2d, v6.2d, v19.2d
  2235ec:      	add	v0.2d, v1.2d, v0.2d
  2235f0:      	add	v1.2d, v2.2d, v3.2d
  2235f4:      	add	v0.2d, v0.2d, v1.2d
  2235f8:      	addp	d0, v0.2d
  2235fc:      	fmov	x8, d0
  223600:      	add	x8, x8, #0x1
  223604:      	add	x21, x10, #0x1
  223608:      	cmp	x9, #0xf
  22360c:      	b.eq	0x223638 <brynja_ghash_timing::timed+0x1ef4>
  223610:      	cmp	x21, x26
  223614:      	b.eq	0x223638 <brynja_ghash_timing::timed+0x1ef4>
  223618:      	ldrb	w10, [x21], #0x1
  22361c:      	ldrb	w11, [x28, x9]
  223620:      	add	x8, x8, #0x1
  223624:      	eor	w10, w11, w10
  223628:      	strb	w10, [x28, x9]
  22362c:      	add	x9, x9, #0x1
  223630:      	cmp	x9, #0xf
  223634:      	b.ne	0x223610 <brynja_ghash_timing::timed+0x1ecc>
  223638:      	mov	x11, x8
  22363c:      	cmp	x11, #0x10
  223640:      	b.ne	0x2234a0 <brynja_ghash_timing::timed+0x1d5c>
  223644:      	cmn	x23, #0x1
  223648:      	b.eq	0x223d48 <brynja_ghash_timing::timed+0x2604>
  22364c:      	b	0x223464 <brynja_ghash_timing::timed+0x1d20>
  223650:      	cmp	x11, #0xf
  223654:      	b.ls	0x2234ac <brynja_ghash_timing::timed+0x1d68>
  223658:      	b	0x22363c <brynja_ghash_timing::timed+0x1ef8>
  22365c:      	ldr	x10, [sp, #0x20]
  223660:      	mov	w9, #0x10               // =16
  223664:      	stp	x10, x9, [x29, #-0x50]
  223668:      	sub	x9, x29, #0x50
  22366c:      	ldur	x9, [x29, #-0x48]
  223670:      	subs	x24, x24, x9
  223674:      	b.lo	0x223b48 <brynja_ghash_timing::timed+0x2404>
  223678:      	cbz	x9, 0x2238a8 <brynja_ghash_timing::timed+0x2164>
  22367c:      	mov	w10, #0x1               // =1
  223680:      	ldur	x21, [x29, #-0x50]
  223684:      	add	x25, sp, #0x40
  223688:      	dup	v0.2d, x10
  22368c:      	add	x19, x25, #0x11
  223690:      	orr	x28, x25, #0x1
  223694:      	add	x26, x21, x9
  223698:      	add	x27, x9, x21
  22369c:      	mov	w20, #0xf               // =15
  2236a0:      	mov	w22, #0x20              // =32
  2236a4:      	mov	x11, x8
  2236a8:      	str	q0, [sp, #0x10]
  2236ac:      	b	0x2236b8 <brynja_ghash_timing::timed+0x1f74>
  2236b0:      	cmp	x26, x21
  2236b4:      	b.eq	0x2238a8 <brynja_ghash_timing::timed+0x2164>
  2236b8:      	cbnz	x11, 0x22389c <brynja_ghash_timing::timed+0x2158>
  2236bc:      	cmp	x21, x26
  2236c0:      	b.eq	0x2238a8 <brynja_ghash_timing::timed+0x2164>
  2236c4:      	mvn	x9, x21
  2236c8:      	sub	x10, x20, x11
  2236cc:      	ldrb	w12, [x25, x11]
  2236d0:      	add	x9, x27, x9
  2236d4:      	cmp	x9, x10
  2236d8:      	csel	x9, x9, x10, lo
  2236dc:      	ldrb	w10, [x21]
  2236e0:      	add	x9, x9, #0x1
  2236e4:      	cmp	x9, #0x21
  2236e8:      	eor	w10, w12, w10
  2236ec:      	strb	w10, [x25, x11]
  2236f0:      	b.hs	0x22370c <brynja_ghash_timing::timed+0x1fc8>
  2236f4:      	mov	x9, x11
  2236f8:      	add	x8, x8, #0x1
  2236fc:      	add	x21, x21, #0x1
  223700:      	cmp	x11, #0xf
  223704:      	b.ne	0x223824 <brynja_ghash_timing::timed+0x20e0>
  223708:      	b	0x22384c <brynja_ghash_timing::timed+0x2108>
  22370c:      	ands	x10, x9, #0x1f
  223710:      	movi	v0.2d, #0000000000000000
  223714:      	movi	v4.2d, #0000000000000000
  223718:      	movi	v6.2d, #0000000000000000
  22371c:      	movi	v1.2d, #0000000000000000
  223720:      	csel	x10, x22, x10, eq
  223724:      	movi	v3.2d, #0000000000000000
  223728:      	movi	v2.2d, #0000000000000000
  22372c:      	sub	x12, x9, x10
  223730:      	movi	v19.2d, #0000000000000000
  223734:      	movi	v7.2d, #0000000000000000
  223738:      	ldr	q28, [sp, #0x10]
  22373c:      	movi	v20.2d, #0000000000000000
  223740:      	movi	v5.2d, #0000000000000000
  223744:      	add	x10, x21, x12
  223748:      	movi	v22.2d, #0000000000000000
  22374c:      	movi	v17.2d, #0000000000000000
  223750:      	add	x9, x11, x12
  223754:      	movi	v18.2d, #0000000000000000
  223758:      	movi	v16.2d, #0000000000000000
  22375c:      	movi	v23.2d, #0000000000000000
  223760:      	fmov	d21, x8
  223764:      	add	x8, x19, x11
  223768:      	add	x11, x21, #0x11
  22376c:      	ldp	q24, q25, [x11, #-0x10]
  223770:      	add	v0.2d, v0.2d, v28.2d
  223774:      	ldp	q26, q27, [x8, #-0x10]
  223778:      	add	v4.2d, v4.2d, v28.2d
  22377c:      	add	v21.2d, v21.2d, v28.2d
  223780:      	add	v6.2d, v6.2d, v28.2d
  223784:      	add	v1.2d, v1.2d, v28.2d
  223788:      	add	v3.2d, v3.2d, v28.2d
  22378c:      	add	v2.2d, v2.2d, v28.2d
  223790:      	add	v19.2d, v19.2d, v28.2d
  223794:      	eor	v24.16b, v26.16b, v24.16b
  223798:      	eor	v25.16b, v27.16b, v25.16b
  22379c:      	subs	x12, x12, #0x20
  2237a0:      	add	v5.2d, v5.2d, v28.2d
  2237a4:      	add	v20.2d, v20.2d, v28.2d
  2237a8:      	add	x11, x11, #0x20
  2237ac:      	add	v7.2d, v7.2d, v28.2d
  2237b0:      	add	v22.2d, v22.2d, v28.2d
  2237b4:      	add	v17.2d, v17.2d, v28.2d
  2237b8:      	add	v18.2d, v18.2d, v28.2d
  2237bc:      	stp	q24, q25, [x8, #-0x10]
  2237c0:      	add	x8, x8, #0x20
  2237c4:      	add	v16.2d, v16.2d, v28.2d
  2237c8:      	add	v23.2d, v23.2d, v28.2d
  2237cc:      	b.ne	0x22376c <brynja_ghash_timing::timed+0x2028>
  2237d0:      	add	v6.2d, v22.2d, v6.2d
  2237d4:      	add	v19.2d, v23.2d, v19.2d
  2237d8:      	add	v4.2d, v20.2d, v4.2d
  2237dc:      	add	v7.2d, v7.2d, v21.2d
  2237e0:      	add	v1.2d, v17.2d, v1.2d
  2237e4:      	add	v3.2d, v18.2d, v3.2d
  2237e8:      	add	v0.2d, v5.2d, v0.2d
  2237ec:      	add	v2.2d, v16.2d, v2.2d
  2237f0:      	add	v1.2d, v7.2d, v1.2d
  2237f4:      	add	v0.2d, v0.2d, v2.2d
  2237f8:      	add	v2.2d, v4.2d, v3.2d
  2237fc:      	add	v3.2d, v6.2d, v19.2d
  223800:      	add	v0.2d, v1.2d, v0.2d
  223804:      	add	v1.2d, v2.2d, v3.2d
  223808:      	add	v0.2d, v0.2d, v1.2d
  22380c:      	addp	d0, v0.2d
  223810:      	fmov	x8, d0
  223814:      	add	x8, x8, #0x1
  223818:      	add	x21, x10, #0x1
  22381c:      	cmp	x9, #0xf
  223820:      	b.eq	0x22384c <brynja_ghash_timing::timed+0x2108>
  223824:      	cmp	x21, x26
  223828:      	b.eq	0x22384c <brynja_ghash_timing::timed+0x2108>
  22382c:      	ldrb	w10, [x21], #0x1
  223830:      	ldrb	w11, [x28, x9]
  223834:      	add	x8, x8, #0x1
  223838:      	eor	w10, w11, w10
  22383c:      	strb	w10, [x28, x9]
  223840:      	add	x9, x9, #0x1
  223844:      	cmp	x9, #0xf
  223848:      	b.ne	0x223824 <brynja_ghash_timing::timed+0x20e0>
  22384c:      	mov	x11, x8
  223850:      	cmp	x11, #0x10
  223854:      	b.ne	0x2236b0 <brynja_ghash_timing::timed+0x1f6c>
  223858:      	cmn	x23, #0x1
  22385c:      	b.eq	0x223d48 <brynja_ghash_timing::timed+0x2604>
  223860:      	ldp	x9, x10, [sp, #0x38]
  223864:      	add	x23, x23, #0x1
  223868:      	ldr	x11, [sp, #0x48]
  22386c:      	ldp	x8, x9, [x9]
  223870:      	rev	x0, x11
  223874:      	rev	x1, x10
  223878:      	rev	x2, x9
  22387c:      	rev	x3, x8
  223880:      	bl	0x2266ac <brynja_crypto_cpu::ghash_pmull::multiply>
  223884:      	mov	x8, xzr
  223888:      	mov	x11, xzr
  22388c:      	rev	x9, x0
  223890:      	rev	x10, x1
  223894:      	stp	x10, x9, [sp, #0x40]
  223898:      	b	0x2236b0 <brynja_ghash_timing::timed+0x1f6c>
  22389c:      	cmp	x11, #0xf
  2238a0:      	b.ls	0x2236bc <brynja_ghash_timing::timed+0x1f78>
  2238a4:      	b	0x223850 <brynja_ghash_timing::timed+0x210c>
  2238a8:      	ldr	x10, [sp, #0x20]
  2238ac:      	mov	w9, #0x10               // =16
  2238b0:      	stp	x10, x9, [x29, #-0x50]
  2238b4:      	sub	x9, x29, #0x50
  2238b8:      	ldur	x9, [x29, #-0x48]
  2238bc:      	subs	x24, x24, x9
  2238c0:      	b.lo	0x223b48 <brynja_ghash_timing::timed+0x2404>
  2238c4:      	cbz	x9, 0x223af4 <brynja_ghash_timing::timed+0x23b0>
  2238c8:      	mov	w10, #0x1               // =1
  2238cc:      	ldur	x21, [x29, #-0x50]
  2238d0:      	add	x25, sp, #0x40
  2238d4:      	dup	v0.2d, x10
  2238d8:      	add	x19, x25, #0x11
  2238dc:      	orr	x28, x25, #0x1
  2238e0:      	add	x26, x21, x9
  2238e4:      	add	x27, x9, x21
  2238e8:      	mov	w20, #0xf               // =15
  2238ec:      	mov	w22, #0x20              // =32
  2238f0:      	mov	x11, x8
  2238f4:      	str	q0, [sp, #0x10]
  2238f8:      	b	0x223904 <brynja_ghash_timing::timed+0x21c0>
  2238fc:      	cmp	x26, x21
  223900:      	b.eq	0x223af4 <brynja_ghash_timing::timed+0x23b0>
  223904:      	cbnz	x11, 0x223ae8 <brynja_ghash_timing::timed+0x23a4>
  223908:      	cmp	x21, x26
  22390c:      	b.eq	0x223af4 <brynja_ghash_timing::timed+0x23b0>
  223910:      	mvn	x9, x21
  223914:      	sub	x10, x20, x11
  223918:      	ldrb	w12, [x25, x11]
  22391c:      	add	x9, x27, x9
  223920:      	cmp	x9, x10
  223924:      	csel	x9, x9, x10, lo
  223928:      	ldrb	w10, [x21]
  22392c:      	add	x9, x9, #0x1
  223930:      	cmp	x9, #0x21
  223934:      	eor	w10, w12, w10
  223938:      	strb	w10, [x25, x11]
  22393c:      	b.hs	0x223958 <brynja_ghash_timing::timed+0x2214>
  223940:      	mov	x9, x11
  223944:      	add	x8, x8, #0x1
  223948:      	add	x21, x21, #0x1
  22394c:      	cmp	x11, #0xf
  223950:      	b.ne	0x223a70 <brynja_ghash_timing::timed+0x232c>
  223954:      	b	0x223a98 <brynja_ghash_timing::timed+0x2354>
  223958:      	ands	x10, x9, #0x1f
  22395c:      	movi	v0.2d, #0000000000000000
  223960:      	movi	v4.2d, #0000000000000000
  223964:      	movi	v6.2d, #0000000000000000
  223968:      	movi	v1.2d, #0000000000000000
  22396c:      	csel	x10, x22, x10, eq
  223970:      	movi	v3.2d, #0000000000000000
  223974:      	movi	v2.2d, #0000000000000000
  223978:      	sub	x12, x9, x10
  22397c:      	movi	v19.2d, #0000000000000000
  223980:      	movi	v7.2d, #0000000000000000
  223984:      	ldr	q28, [sp, #0x10]
  223988:      	movi	v20.2d, #0000000000000000
  22398c:      	movi	v5.2d, #0000000000000000
  223990:      	add	x10, x21, x12
  223994:      	movi	v22.2d, #0000000000000000
  223998:      	movi	v17.2d, #0000000000000000
  22399c:      	add	x9, x11, x12
  2239a0:      	movi	v18.2d, #0000000000000000
  2239a4:      	movi	v16.2d, #0000000000000000
  2239a8:      	movi	v23.2d, #0000000000000000
  2239ac:      	fmov	d21, x8
  2239b0:      	add	x8, x19, x11
  2239b4:      	add	x11, x21, #0x11
  2239b8:      	ldp	q24, q25, [x11, #-0x10]
  2239bc:      	add	v0.2d, v0.2d, v28.2d
  2239c0:      	ldp	q26, q27, [x8, #-0x10]
  2239c4:      	add	v4.2d, v4.2d, v28.2d
  2239c8:      	add	v21.2d, v21.2d, v28.2d
  2239cc:      	add	v6.2d, v6.2d, v28.2d
  2239d0:      	add	v1.2d, v1.2d, v28.2d
  2239d4:      	add	v3.2d, v3.2d, v28.2d
  2239d8:      	add	v2.2d, v2.2d, v28.2d
  2239dc:      	add	v19.2d, v19.2d, v28.2d
  2239e0:      	eor	v24.16b, v26.16b, v24.16b
  2239e4:      	eor	v25.16b, v27.16b, v25.16b
  2239e8:      	subs	x12, x12, #0x20
  2239ec:      	add	v5.2d, v5.2d, v28.2d
  2239f0:      	add	v20.2d, v20.2d, v28.2d
  2239f4:      	add	x11, x11, #0x20
  2239f8:      	add	v7.2d, v7.2d, v28.2d
  2239fc:      	add	v22.2d, v22.2d, v28.2d
  223a00:      	add	v17.2d, v17.2d, v28.2d
  223a04:      	add	v18.2d, v18.2d, v28.2d
  223a08:      	stp	q24, q25, [x8, #-0x10]
  223a0c:      	add	x8, x8, #0x20
  223a10:      	add	v16.2d, v16.2d, v28.2d
  223a14:      	add	v23.2d, v23.2d, v28.2d
  223a18:      	b.ne	0x2239b8 <brynja_ghash_timing::timed+0x2274>
  223a1c:      	add	v6.2d, v22.2d, v6.2d
  223a20:      	add	v19.2d, v23.2d, v19.2d
  223a24:      	add	v4.2d, v20.2d, v4.2d
  223a28:      	add	v7.2d, v7.2d, v21.2d
  223a2c:      	add	v1.2d, v17.2d, v1.2d
  223a30:      	add	v3.2d, v18.2d, v3.2d
  223a34:      	add	v0.2d, v5.2d, v0.2d
  223a38:      	add	v2.2d, v16.2d, v2.2d
  223a3c:      	add	v1.2d, v7.2d, v1.2d
  223a40:      	add	v0.2d, v0.2d, v2.2d
  223a44:      	add	v2.2d, v4.2d, v3.2d
  223a48:      	add	v3.2d, v6.2d, v19.2d
  223a4c:      	add	v0.2d, v1.2d, v0.2d
  223a50:      	add	v1.2d, v2.2d, v3.2d
  223a54:      	add	v0.2d, v0.2d, v1.2d
  223a58:      	addp	d0, v0.2d
  223a5c:      	fmov	x8, d0
  223a60:      	add	x8, x8, #0x1
  223a64:      	add	x21, x10, #0x1
  223a68:      	cmp	x9, #0xf
  223a6c:      	b.eq	0x223a98 <brynja_ghash_timing::timed+0x2354>
  223a70:      	cmp	x21, x26
  223a74:      	b.eq	0x223a98 <brynja_ghash_timing::timed+0x2354>
  223a78:      	ldrb	w10, [x21], #0x1
  223a7c:      	ldrb	w11, [x28, x9]
  223a80:      	add	x8, x8, #0x1
  223a84:      	eor	w10, w11, w10
  223a88:      	strb	w10, [x28, x9]
  223a8c:      	add	x9, x9, #0x1
  223a90:      	cmp	x9, #0xf
  223a94:      	b.ne	0x223a70 <brynja_ghash_timing::timed+0x232c>
  223a98:      	mov	x11, x8
  223a9c:      	cmp	x11, #0x10
  223aa0:      	b.ne	0x2238fc <brynja_ghash_timing::timed+0x21b8>
  223aa4:      	cmn	x23, #0x1
  223aa8:      	b.eq	0x223d48 <brynja_ghash_timing::timed+0x2604>
  223aac:      	ldp	x9, x10, [sp, #0x38]
  223ab0:      	add	x23, x23, #0x1
  223ab4:      	ldr	x11, [sp, #0x48]
  223ab8:      	ldp	x8, x9, [x9]
  223abc:      	rev	x0, x11
  223ac0:      	rev	x1, x10
  223ac4:      	rev	x2, x9
  223ac8:      	rev	x3, x8
  223acc:      	bl	0x2266ac <brynja_crypto_cpu::ghash_pmull::multiply>
  223ad0:      	mov	x8, xzr
  223ad4:      	mov	x11, xzr
  223ad8:      	rev	x9, x0
  223adc:      	rev	x10, x1
  223ae0:      	stp	x10, x9, [sp, #0x40]
  223ae4:      	b	0x2238fc <brynja_ghash_timing::timed+0x21b8>
  223ae8:      	cmp	x11, #0xf
  223aec:      	b.ls	0x223908 <brynja_ghash_timing::timed+0x21c4>
  223af0:      	b	0x223a9c <brynja_ghash_timing::timed+0x2358>
  223af4:      	ldr	x10, [sp, #0x20]
  223af8:      	mov	w9, #0x10               // =16
  223afc:      	stp	x10, x9, [x29, #-0x50]
  223b00:      	sub	x9, x29, #0x50
  223b04:      	ldur	x9, [x29, #-0x48]
  223b08:      	subs	x21, x24, x9
  223b0c:      	b.lo	0x223b48 <brynja_ghash_timing::timed+0x2404>
  223b10:      	cbz	x9, 0x223d74 <brynja_ghash_timing::timed+0x2630>
  223b14:      	mov	w10, #0x1               // =1
  223b18:      	ldur	x28, [x29, #-0x50]
  223b1c:      	add	x24, sp, #0x40
  223b20:      	dup	v0.2d, x10
  223b24:      	add	x19, x24, #0x11
  223b28:      	orr	x27, x24, #0x1
  223b2c:      	add	x25, x28, x9
  223b30:      	add	x26, x9, x28
  223b34:      	mov	w20, #0xf               // =15
  223b38:      	mov	w22, #0x20              // =32
  223b3c:      	mov	x11, x8
  223b40:      	str	q0, [sp, #0x20]
  223b44:      	b	0x223b58 <brynja_ghash_timing::timed+0x2414>
  223b48:      	mov	w8, #0x5                // =5
  223b4c:      	b	0x223d4c <brynja_ghash_timing::timed+0x2608>
  223b50:      	cmp	x25, x28
  223b54:      	b.eq	0x223d74 <brynja_ghash_timing::timed+0x2630>
  223b58:      	cbnz	x11, 0x223d3c <brynja_ghash_timing::timed+0x25f8>
  223b5c:      	cmp	x28, x25
  223b60:      	b.eq	0x223d74 <brynja_ghash_timing::timed+0x2630>
  223b64:      	mvn	x9, x28
  223b68:      	sub	x10, x20, x11
  223b6c:      	ldrb	w12, [x24, x11]
  223b70:      	add	x9, x26, x9
  223b74:      	cmp	x9, x10
  223b78:      	csel	x9, x9, x10, lo
  223b7c:      	ldrb	w10, [x28]
  223b80:      	add	x9, x9, #0x1
  223b84:      	cmp	x9, #0x21
  223b88:      	eor	w10, w12, w10
  223b8c:      	strb	w10, [x24, x11]
  223b90:      	b.hs	0x223bac <brynja_ghash_timing::timed+0x2468>
  223b94:      	mov	x9, x11
  223b98:      	add	x8, x8, #0x1
  223b9c:      	add	x28, x28, #0x1
  223ba0:      	cmp	x11, #0xf
  223ba4:      	b.ne	0x223cc4 <brynja_ghash_timing::timed+0x2580>
  223ba8:      	b	0x223cec <brynja_ghash_timing::timed+0x25a8>
  223bac:      	ands	x10, x9, #0x1f
  223bb0:      	movi	v0.2d, #0000000000000000
  223bb4:      	movi	v4.2d, #0000000000000000
  223bb8:      	movi	v6.2d, #0000000000000000
  223bbc:      	movi	v1.2d, #0000000000000000
  223bc0:      	csel	x10, x22, x10, eq
  223bc4:      	movi	v3.2d, #0000000000000000
  223bc8:      	movi	v2.2d, #0000000000000000
  223bcc:      	sub	x12, x9, x10
  223bd0:      	movi	v19.2d, #0000000000000000
  223bd4:      	movi	v7.2d, #0000000000000000
  223bd8:      	ldr	q28, [sp, #0x20]
  223bdc:      	movi	v20.2d, #0000000000000000
  223be0:      	movi	v5.2d, #0000000000000000
  223be4:      	add	x10, x28, x12
  223be8:      	movi	v22.2d, #0000000000000000
  223bec:      	movi	v17.2d, #0000000000000000
  223bf0:      	add	x9, x11, x12
  223bf4:      	movi	v18.2d, #0000000000000000
  223bf8:      	movi	v16.2d, #0000000000000000
  223bfc:      	movi	v23.2d, #0000000000000000
  223c00:      	fmov	d21, x8
  223c04:      	add	x8, x19, x11
  223c08:      	add	x11, x28, #0x11
  223c0c:      	ldp	q24, q25, [x11, #-0x10]
  223c10:      	add	v0.2d, v0.2d, v28.2d
  223c14:      	ldp	q26, q27, [x8, #-0x10]
  223c18:      	add	v4.2d, v4.2d, v28.2d
  223c1c:      	add	v21.2d, v21.2d, v28.2d
  223c20:      	add	v6.2d, v6.2d, v28.2d
  223c24:      	add	v1.2d, v1.2d, v28.2d
  223c28:      	add	v3.2d, v3.2d, v28.2d
  223c2c:      	add	v2.2d, v2.2d, v28.2d
  223c30:      	add	v19.2d, v19.2d, v28.2d
  223c34:      	eor	v24.16b, v26.16b, v24.16b
  223c38:      	eor	v25.16b, v27.16b, v25.16b
  223c3c:      	subs	x12, x12, #0x20
  223c40:      	add	v5.2d, v5.2d, v28.2d
  223c44:      	add	v20.2d, v20.2d, v28.2d
  223c48:      	add	x11, x11, #0x20
  223c4c:      	add	v7.2d, v7.2d, v28.2d
  223c50:      	add	v22.2d, v22.2d, v28.2d
  223c54:      	add	v17.2d, v17.2d, v28.2d
  223c58:      	add	v18.2d, v18.2d, v28.2d
  223c5c:      	stp	q24, q25, [x8, #-0x10]
  223c60:      	add	x8, x8, #0x20
  223c64:      	add	v16.2d, v16.2d, v28.2d
  223c68:      	add	v23.2d, v23.2d, v28.2d
  223c6c:      	b.ne	0x223c0c <brynja_ghash_timing::timed+0x24c8>
  223c70:      	add	v6.2d, v22.2d, v6.2d
  223c74:      	add	v19.2d, v23.2d, v19.2d
  223c78:      	add	v4.2d, v20.2d, v4.2d
  223c7c:      	add	v7.2d, v7.2d, v21.2d
  223c80:      	add	v1.2d, v17.2d, v1.2d
  223c84:      	add	v3.2d, v18.2d, v3.2d
  223c88:      	add	v0.2d, v5.2d, v0.2d
  223c8c:      	add	v2.2d, v16.2d, v2.2d
  223c90:      	add	v1.2d, v7.2d, v1.2d
  223c94:      	add	v0.2d, v0.2d, v2.2d
  223c98:      	add	v2.2d, v4.2d, v3.2d
  223c9c:      	add	v3.2d, v6.2d, v19.2d
  223ca0:      	add	v0.2d, v1.2d, v0.2d
  223ca4:      	add	v1.2d, v2.2d, v3.2d
  223ca8:      	add	v0.2d, v0.2d, v1.2d
  223cac:      	addp	d0, v0.2d
  223cb0:      	fmov	x8, d0
  223cb4:      	add	x8, x8, #0x1
  223cb8:      	add	x28, x10, #0x1
  223cbc:      	cmp	x9, #0xf
  223cc0:      	b.eq	0x223cec <brynja_ghash_timing::timed+0x25a8>
  223cc4:      	cmp	x28, x25
  223cc8:      	b.eq	0x223cec <brynja_ghash_timing::timed+0x25a8>
  223ccc:      	ldrb	w10, [x28], #0x1
  223cd0:      	ldrb	w11, [x27, x9]
  223cd4:      	add	x8, x8, #0x1
  223cd8:      	eor	w10, w11, w10
  223cdc:      	strb	w10, [x27, x9]
  223ce0:      	add	x9, x9, #0x1
  223ce4:      	cmp	x9, #0xf
  223ce8:      	b.ne	0x223cc4 <brynja_ghash_timing::timed+0x2580>
  223cec:      	mov	x11, x8
  223cf0:      	cmp	x11, #0x10
  223cf4:      	b.ne	0x223b50 <brynja_ghash_timing::timed+0x240c>
  223cf8:      	cmn	x23, #0x1
  223cfc:      	b.eq	0x223d48 <brynja_ghash_timing::timed+0x2604>
  223d00:      	ldp	x9, x10, [sp, #0x38]
  223d04:      	add	x23, x23, #0x1
  223d08:      	ldr	x11, [sp, #0x48]
  223d0c:      	ldp	x8, x9, [x9]
  223d10:      	rev	x0, x11
  223d14:      	rev	x1, x10
  223d18:      	rev	x2, x9
  223d1c:      	rev	x3, x8
  223d20:      	bl	0x2266ac <brynja_crypto_cpu::ghash_pmull::multiply>
  223d24:      	mov	x8, xzr
  223d28:      	mov	x11, xzr
  223d2c:      	rev	x9, x0
  223d30:      	rev	x10, x1
  223d34:      	stp	x10, x9, [sp, #0x40]
  223d38:      	b	0x223b50 <brynja_ghash_timing::timed+0x240c>
  223d3c:      	cmp	x11, #0xf
  223d40:      	b.ls	0x223b5c <brynja_ghash_timing::timed+0x2418>
  223d44:      	b	0x223cf0 <brynja_ghash_timing::timed+0x25ac>
  223d48:      	mov	w8, #0x4                // =4
  223d4c:      	nop
  223d50:      	adr	x0, 0x203cc3 <core::unicode::unicode_data::cf::SHORT_OFFSET_RUNS+0xab3>
  223d54:      	nop
  223d58:      	adr	x3, 0x279548 <gettid+0x279548>
  223d5c:      	nop
  223d60:      	adr	x4, 0x279530 <gettid+0x279530>
  223d64:      	add	x2, sp, #0x60
  223d68:      	mov	w1, #0x2b               // =43
  223d6c:      	strb	w8, [sp, #0x60]
  223d70:      	bl	0x229670 <core::result::unwrap_failed>
  223d74:      	ldr	x9, [sp, #0x38]
  223d78:      	stp	x8, x21, [x29, #-0x50]
  223d7c:      	add	x8, sp, #0x40
  223d80:      	add	x0, sp, #0x60
  223d84:      	sub	x1, x29, #0x50
  223d88:      	add	x2, sp, #0x50
  223d8c:      	stp	x9, x8, [x29, #-0x40]
  223d90:      	mov	w8, #0x2                // =2
  223d94:      	stur	x23, [x29, #-0x30]
  223d98:      	sturb	w8, [x29, #-0x28]
  223d9c:      	bl	0x226608 <<brynja_crypto::ghash::Ghash>::finish>
  223da0:      	ldrb	w8, [sp, #0x60]
  223da4:      	tbnz	w8, #0x0, 0x223e44 <brynja_ghash_timing::timed+0x2700>
  223da8:      	ldp	x0, x1, [sp, #0x68]
  223dac:      	cmp	x0, #0x0
  223db0:      	csinc	x8, x0, xzr, ne
  223db4:      	csel	x9, xzr, x1, eq
  223db8:      	stp	x8, x9, [x29, #-0x50]
  223dbc:      	sub	x8, x29, #0x50
  223dc0:      	cbz	x0, 0x223dc8 <brynja_ghash_timing::timed+0x2684>
  223dc4:      	bl	0x226598 <brynja_core::secret_memory_volatile::zeroize_region_volatile>
  223dc8:      	bl	0x2539b4 <<std::sys::pal::unix::time::Timespec>::now>
  223dcc:      	ldr	x8, [sp, #0x8]
  223dd0:      	stur	x0, [x29, #-0x18]
  223dd4:      	sub	x0, x29, #0x50
  223dd8:      	stur	w1, [x29, #-0x10]
  223ddc:      	sub	x1, x29, #0x18
  223de0:      	add	x2, sp, #0x60
  223de4:      	str	x8, [sp, #0x60]
  223de8:      	ldr	w8, [sp, #0x4]
  223dec:      	str	w8, [sp, #0x68]
  223df0:      	bl	0x2538c4 <<std::sys::pal::unix::time::Timespec>::sub_timespec>
  223df4:      	ldur	x8, [x29, #-0x48]
  223df8:      	mov	w9, #0xca00             // =51712
  223dfc:      	ldur	w11, [x29, #-0x50]
  223e00:      	movk	w9, #0x3b9a, lsl #16
  223e04:      	mul	x10, x8, x9
  223e08:      	umulh	x8, x8, x9
  223e0c:      	ldur	w9, [x29, #-0x40]
  223e10:      	adds	x9, x10, x9
  223e14:      	cinc	x8, x8, hs
  223e18:      	cmp	w11, #0x0
  223e1c:      	csel	x1, xzr, x8, ne
  223e20:      	csel	x0, xzr, x9, ne
  223e24:      	ldp	x20, x19, [sp, #0x120]
  223e28:      	ldp	x22, x21, [sp, #0x110]
  223e2c:      	ldp	x24, x23, [sp, #0x100]
  223e30:      	ldp	x26, x25, [sp, #0xf0]
  223e34:      	ldp	x28, x27, [sp, #0xe0]
  223e38:      	ldp	x29, x30, [sp, #0xd0]
  223e3c:      	add	sp, sp, #0x130
  223e40:      	ret
  223e44:      	ldrb	w8, [sp, #0x61]
  223e48:      	nop
  223e4c:      	adr	x0, 0x203cc3 <core::unicode::unicode_data::cf::SHORT_OFFSET_RUNS+0xab3>
  223e50:      	nop
  223e54:      	adr	x3, 0x279548 <gettid+0x279548>
  223e58:      	nop
  223e5c:      	adr	x4, 0x279518 <gettid+0x279518>
  223e60:      	sub	x2, x29, #0x50
  223e64:      	mov	w1, #0x2b               // =43
  223e68:      	sturb	w8, [x29, #-0x50]
  223e6c:      	bl	0x229670 <core::result::unwrap_failed>
00000000002266ac <brynja_crypto_cpu::ghash_pmull::multiply>:
  2266ac:      	rbit	x8, x2
  2266b0:      	rbit	x9, x0
  2266b4:      	rbit	x10, x1
  2266b8:      	rbit	x11, x3
  2266bc:      	fmov	d0, x8
  2266c0:      	fmov	d1, x9
  2266c4:      	eor	x9, x9, x10
  2266c8:      	fmov	d2, x11
  2266cc:      	eor	x8, x8, x11
  2266d0:      	fmov	d3, x8
  2266d4:      	pmull	v0.1q, v1.1d, v0.1d
  2266d8:      	fmov	d1, x10
  2266dc:      	pmull	v1.1q, v1.1d, v2.1d
  2266e0:      	fmov	d2, x9
  2266e4:      	mov	x12, v0.d[1]
  2266e8:      	fmov	x11, d0
  2266ec:      	pmull	v2.1q, v2.1d, v3.1d
  2266f0:      	eor	v3.16b, v1.16b, v0.16b
  2266f4:      	fmov	x9, d1
  2266f8:      	mov	x13, v1.d[1]
  2266fc:      	lsr	x8, x12, #63
  226700:      	eor	x8, x8, x12, lsr #62
  226704:      	eor	v2.16b, v3.16b, v2.16b
  226708:      	eor	x8, x8, x12, lsr #57
  22670c:      	mov	x10, v2.d[1]
  226710:      	eor	x9, x9, x8, lsl #2
  226714:      	eor	x9, x9, x8, lsl #1
  226718:      	eor	x10, x10, x11
  22671c:      	fmov	x11, d2
  226720:      	eor	x9, x9, x8, lsl #7
  226724:      	extr	x14, x12, x10, #0x3f
  226728:      	extr	x15, x12, x10, #0x3e
  22672c:      	extr	x16, x12, x10, #0x39
  226730:      	eor	x8, x8, x10
  226734:      	eor	x9, x9, x10, lsl #2
  226738:      	eor	x11, x13, x11
  22673c:      	eor	x11, x11, x15
  226740:      	eor	x13, x14, x16
  226744:      	eor	x9, x9, x10, lsl #1
  226748:      	eor	x11, x11, x13
  22674c:      	eor	x9, x9, x10, lsl #7
  226750:      	eor	x8, x9, x8
  226754:      	eor	x9, x11, x12
  226758:      	rbit	x0, x9
  22675c:      	rbit	x1, x8
  226760:      	ret
