00000001000012c4 <brynja_ghash_timing::timed>:
1000012c4:     	sub	sp, sp, #0xc0
1000012c8:     	stp	x22, x21, [sp, #0x90]
1000012cc:     	stp	x20, x19, [sp, #0xa0]
1000012d0:     	stp	x29, x30, [sp, #0xb0]
1000012d4:     	add	x29, sp, #0xb0
1000012d8:     	mov	x19, x1
1000012dc:     	stp	xzr, xzr, [sp]
1000012e0:     	stp	xzr, xzr, [sp, #0x10]
1000012e4:     	str	x0, [sp, #0x50]
1000012e8:     	add	x8, sp, #0x50
1000012ec:     	ldr	x20, [sp, #0x50]
1000012f0:     	mov	w22, #0x10              ; =16
1000012f4:     	mov	x21, sp
1000012f8:     	mov	x0, sp
1000012fc:     	mov	w1, #0x10               ; =16
100001300:     	bl	0x100003a3c <brynja_core::secret_memory_volatile::zeroize_region_volatile>
100001304:     	mov	x8, #0xa392             ; =41874
100001308:     	movk	x8, #0x60b6, lsl #16
10000130c:     	movk	x8, #0xdace, lsl #32
100001310:     	movk	x8, #0x388, lsl #48
100001314:     	mov	x9, #0xfe78             ; =65144
100001318:     	movk	x9, #0x71b2, lsl #16
10000131c:     	movk	x9, #0xc2b9, lsl #32
100001320:     	movk	x9, #0xf328, lsl #48
100001324:     	stp	x9, x8, [x29, #-0x50]
100001328:     	sub	x8, x29, #0x50
10000132c:     	mov	x8, #0x2c3b             ; =11323
100001330:     	movk	x8, #0xef8a, lsl #16
100001334:     	movk	x8, #0x4bd4, lsl #32
100001338:     	movk	x8, #0x66e9, lsl #48
10000133c:     	mov	x9, #0x2b2e             ; =11054
100001340:     	movk	x9, #0xca34, lsl #16
100001344:     	movk	x9, #0xfa59, lsl #32
100001348:     	movk	x9, #0x884c, lsl #48
10000134c:     	stp	x9, x8, [x29, #-0x40]
100001350:     	sub	x8, x29, #0x40
100001354:     	ldp	x9, x8, [x29, #-0x50]
100001358:     	ldp	x11, x10, [x29, #-0x40]
10000135c:     	rbit	x9, x9
100001360:     	rbit	x8, x8
100001364:     	eor	x12, x9, x8
100001368:     	fmov	d0, x9
10000136c:     	fmov	d1, x8
100001370:     	rbit	x8, x11
100001374:     	rbit	x9, x10
100001378:     	eor	x10, x8, x9
10000137c:     	fmov	d2, x8
100001380:     	fmov	d3, x9
100001384:     	pmull.1q	v1, v1, v3
100001388:     	mov.d	x8, v1[1]
10000138c:     	pmull.1q	v0, v0, v2
100001390:     	fmov	d2, x12
100001394:     	fmov	d3, x10
100001398:     	pmull.1q	v2, v2, v3
10000139c:     	eor3.16b	v2, v1, v2, v0
1000013a0:     	fmov	x9, d1
1000013a4:     	mov.d	x10, v0[1]
1000013a8:     	fmov	x11, d0
1000013ac:     	mov.d	x12, v2[1]
1000013b0:     	eor	x11, x12, x11
1000013b4:     	extr	x12, x10, x11, #0x3f
1000013b8:     	fmov	x13, d2
1000013bc:     	extr	x14, x10, x11, #0x3e
1000013c0:     	extr	x15, x10, x11, #0x39
1000013c4:     	lsr	x16, x10, #63
1000013c8:     	eor	x16, x16, x10, lsr #62
1000013cc:     	eor	x16, x16, x10, lsr #57
1000013d0:     	eor	x9, x9, x16, lsl #2
1000013d4:     	eor	x9, x9, x16, lsl #1
1000013d8:     	eor	x9, x9, x16, lsl #7
1000013dc:     	eor	x8, x8, x13
1000013e0:     	eor	x8, x8, x14
1000013e4:     	eor	x9, x9, x11, lsl #2
1000013e8:     	eor	x9, x9, x11, lsl #1
1000013ec:     	eor	x12, x12, x15
1000013f0:     	eor	x8, x8, x12
1000013f4:     	eor	x9, x9, x11, lsl #7
1000013f8:     	eor	x11, x16, x11
1000013fc:     	mov	x12, #0xa134            ; =41268
100001400:     	movk	x12, #0x160d, lsl #16
100001404:     	movk	x12, #0xcaca, lsl #32
100001408:     	movk	x12, #0xed7b, lsl #48
10000140c:     	eor	x10, x10, x12
100001410:     	eor	x8, x8, x10
100001414:     	mov	x10, #0x747a            ; =29818
100001418:     	movk	x10, #0x62e3, lsl #16
10000141c:     	movk	x10, #0xe89, lsl #32
100001420:     	movk	x10, #0x1146, lsl #48
100001424:     	eor	x10, x11, x10
100001428:     	eor	x9, x9, x10
10000142c:     	orr	x8, x9, x8
100001430:     	cmp	x8, #0x0
100001434:     	mov	w8, #0x2                ; =2
100001438:     	csinv	w8, w8, wzr, eq
10000143c:     	stp	x21, xzr, [sp, #0x38]
100001440:     	strb	w8, [sp, #0x48]
100001444:     	str	x20, [sp, #0x30]
100001448:     	adrp	x8, 0x100034000 <core::str::pattern::simd_contains::{closure#2}+0x60>
10000144c:     	ldr	q0, [x8, #0xf60]
100001450:     	str	q0, [sp, #0x20]
100001454:     	bl	0x10002dc64 <<std::sys::pal::unix::time::Timespec>::now>
100001458:     	mov	x20, x0
10000145c:     	mov	x21, x1
100001460:     	stp	x19, x22, [x29, #-0x40]
100001464:     	sub	x8, x29, #0x40
100001468:     	ldp	x1, x2, [x29, #-0x40]
10000146c:     	add	x0, sp, #0x20
100001470:     	bl	0x100003b54 <<brynja_crypto::ghash::Ghash>::update>
100001474:     	mov	w22, #0xff              ; =255
100001478:     	bics	wzr, w22, w0
10000147c:     	b.ne	0x100001700 <brynja_ghash_timing::timed+0x43c>
100001480:     	mov	w8, #0x10               ; =16
100001484:     	stp	x19, x8, [x29, #-0x40]
100001488:     	sub	x8, x29, #0x40
10000148c:     	ldp	x1, x2, [x29, #-0x40]
100001490:     	add	x0, sp, #0x20
100001494:     	bl	0x100003b54 <<brynja_crypto::ghash::Ghash>::update>
100001498:     	bics	wzr, w22, w0
10000149c:     	b.ne	0x100001700 <brynja_ghash_timing::timed+0x43c>
1000014a0:     	mov	w8, #0x10               ; =16
1000014a4:     	stp	x19, x8, [x29, #-0x40]
1000014a8:     	sub	x8, x29, #0x40
1000014ac:     	ldp	x1, x2, [x29, #-0x40]
1000014b0:     	add	x0, sp, #0x20
1000014b4:     	bl	0x100003b54 <<brynja_crypto::ghash::Ghash>::update>
1000014b8:     	bics	wzr, w22, w0
1000014bc:     	b.ne	0x100001700 <brynja_ghash_timing::timed+0x43c>
1000014c0:     	mov	w8, #0x10               ; =16
1000014c4:     	stp	x19, x8, [x29, #-0x40]
1000014c8:     	sub	x8, x29, #0x40
1000014cc:     	ldp	x1, x2, [x29, #-0x40]
1000014d0:     	add	x0, sp, #0x20
1000014d4:     	bl	0x100003b54 <<brynja_crypto::ghash::Ghash>::update>
1000014d8:     	bics	wzr, w22, w0
1000014dc:     	b.ne	0x100001700 <brynja_ghash_timing::timed+0x43c>
1000014e0:     	mov	w8, #0x10               ; =16
1000014e4:     	stp	x19, x8, [x29, #-0x40]
1000014e8:     	sub	x8, x29, #0x40
1000014ec:     	ldp	x1, x2, [x29, #-0x40]
1000014f0:     	add	x0, sp, #0x20
1000014f4:     	bl	0x100003b54 <<brynja_crypto::ghash::Ghash>::update>
1000014f8:     	bics	wzr, w22, w0
1000014fc:     	b.ne	0x100001700 <brynja_ghash_timing::timed+0x43c>
100001500:     	mov	w8, #0x10               ; =16
100001504:     	stp	x19, x8, [x29, #-0x40]
100001508:     	sub	x8, x29, #0x40
10000150c:     	ldp	x1, x2, [x29, #-0x40]
100001510:     	add	x0, sp, #0x20
100001514:     	bl	0x100003b54 <<brynja_crypto::ghash::Ghash>::update>
100001518:     	bics	wzr, w22, w0
10000151c:     	b.ne	0x100001700 <brynja_ghash_timing::timed+0x43c>
100001520:     	mov	w8, #0x10               ; =16
100001524:     	stp	x19, x8, [x29, #-0x40]
100001528:     	sub	x8, x29, #0x40
10000152c:     	ldp	x1, x2, [x29, #-0x40]
100001530:     	add	x0, sp, #0x20
100001534:     	bl	0x100003b54 <<brynja_crypto::ghash::Ghash>::update>
100001538:     	bics	wzr, w22, w0
10000153c:     	b.ne	0x100001700 <brynja_ghash_timing::timed+0x43c>
100001540:     	mov	w8, #0x10               ; =16
100001544:     	stp	x19, x8, [x29, #-0x40]
100001548:     	sub	x8, x29, #0x40
10000154c:     	ldp	x1, x2, [x29, #-0x40]
100001550:     	add	x0, sp, #0x20
100001554:     	bl	0x100003b54 <<brynja_crypto::ghash::Ghash>::update>
100001558:     	bics	wzr, w22, w0
10000155c:     	b.ne	0x100001700 <brynja_ghash_timing::timed+0x43c>
100001560:     	mov	w8, #0x10               ; =16
100001564:     	stp	x19, x8, [x29, #-0x40]
100001568:     	sub	x8, x29, #0x40
10000156c:     	ldp	x1, x2, [x29, #-0x40]
100001570:     	add	x0, sp, #0x20
100001574:     	bl	0x100003b54 <<brynja_crypto::ghash::Ghash>::update>
100001578:     	bics	wzr, w22, w0
10000157c:     	b.ne	0x100001700 <brynja_ghash_timing::timed+0x43c>
100001580:     	mov	w8, #0x10               ; =16
100001584:     	stp	x19, x8, [x29, #-0x40]
100001588:     	sub	x8, x29, #0x40
10000158c:     	ldp	x1, x2, [x29, #-0x40]
100001590:     	add	x0, sp, #0x20
100001594:     	bl	0x100003b54 <<brynja_crypto::ghash::Ghash>::update>
100001598:     	bics	wzr, w22, w0
10000159c:     	b.ne	0x100001700 <brynja_ghash_timing::timed+0x43c>
1000015a0:     	mov	w8, #0x10               ; =16
1000015a4:     	stp	x19, x8, [x29, #-0x40]
1000015a8:     	sub	x8, x29, #0x40
1000015ac:     	ldp	x1, x2, [x29, #-0x40]
1000015b0:     	add	x0, sp, #0x20
1000015b4:     	bl	0x100003b54 <<brynja_crypto::ghash::Ghash>::update>
1000015b8:     	bics	wzr, w22, w0
1000015bc:     	b.ne	0x100001700 <brynja_ghash_timing::timed+0x43c>
1000015c0:     	mov	w8, #0x10               ; =16
1000015c4:     	stp	x19, x8, [x29, #-0x40]
1000015c8:     	sub	x8, x29, #0x40
1000015cc:     	ldp	x1, x2, [x29, #-0x40]
1000015d0:     	add	x0, sp, #0x20
1000015d4:     	bl	0x100003b54 <<brynja_crypto::ghash::Ghash>::update>
1000015d8:     	bics	wzr, w22, w0
1000015dc:     	b.ne	0x100001700 <brynja_ghash_timing::timed+0x43c>
1000015e0:     	mov	w8, #0x10               ; =16
1000015e4:     	stp	x19, x8, [x29, #-0x40]
1000015e8:     	sub	x8, x29, #0x40
1000015ec:     	ldp	x1, x2, [x29, #-0x40]
1000015f0:     	add	x0, sp, #0x20
1000015f4:     	bl	0x100003b54 <<brynja_crypto::ghash::Ghash>::update>
1000015f8:     	bics	wzr, w22, w0
1000015fc:     	b.ne	0x100001700 <brynja_ghash_timing::timed+0x43c>
100001600:     	mov	w8, #0x10               ; =16
100001604:     	stp	x19, x8, [x29, #-0x40]
100001608:     	sub	x8, x29, #0x40
10000160c:     	ldp	x1, x2, [x29, #-0x40]
100001610:     	add	x0, sp, #0x20
100001614:     	bl	0x100003b54 <<brynja_crypto::ghash::Ghash>::update>
100001618:     	bics	wzr, w22, w0
10000161c:     	b.ne	0x100001700 <brynja_ghash_timing::timed+0x43c>
100001620:     	mov	w8, #0x10               ; =16
100001624:     	stp	x19, x8, [x29, #-0x40]
100001628:     	sub	x8, x29, #0x40
10000162c:     	ldp	x1, x2, [x29, #-0x40]
100001630:     	add	x0, sp, #0x20
100001634:     	bl	0x100003b54 <<brynja_crypto::ghash::Ghash>::update>
100001638:     	bics	wzr, w22, w0
10000163c:     	b.ne	0x100001700 <brynja_ghash_timing::timed+0x43c>
100001640:     	mov	w8, #0x10               ; =16
100001644:     	stp	x19, x8, [x29, #-0x40]
100001648:     	sub	x8, x29, #0x40
10000164c:     	ldp	x1, x2, [x29, #-0x40]
100001650:     	add	x0, sp, #0x20
100001654:     	bl	0x100003b54 <<brynja_crypto::ghash::Ghash>::update>
100001658:     	bics	wzr, w22, w0
10000165c:     	b.ne	0x100001700 <brynja_ghash_timing::timed+0x43c>
100001660:     	sub	x0, x29, #0x40
100001664:     	add	x1, sp, #0x20
100001668:     	add	x2, sp, #0x10
10000166c:     	bl	0x100003aac <<brynja_crypto::ghash::Ghash>::finish>
100001670:     	ldurb	w8, [x29, #-0x40]
100001674:     	tbnz	w8, #0x0, 0x100001728 <brynja_ghash_timing::timed+0x464>
100001678:     	ldp	x0, x1, [x29, #-0x38]
10000167c:     	cmp	x0, #0x0
100001680:     	csel	x8, xzr, x1, eq
100001684:     	csinc	x9, x0, xzr, ne
100001688:     	stp	x9, x8, [x29, #-0x40]
10000168c:     	sub	x8, x29, #0x40
100001690:     	cbz	x0, 0x100001698 <brynja_ghash_timing::timed+0x3d4>
100001694:     	bl	0x100003a3c <brynja_core::secret_memory_volatile::zeroize_region_volatile>
100001698:     	bl	0x10002dc64 <<std::sys::pal::unix::time::Timespec>::now>
10000169c:     	str	x0, [sp, #0x50]
1000016a0:     	str	w1, [sp, #0x58]
1000016a4:     	stur	x20, [x29, #-0x50]
1000016a8:     	stur	w21, [x29, #-0x48]
1000016ac:     	sub	x0, x29, #0x40
1000016b0:     	add	x1, sp, #0x50
1000016b4:     	sub	x2, x29, #0x50
1000016b8:     	bl	0x10002db80 <<std::sys::pal::unix::time::Timespec>::sub_timespec>
1000016bc:     	ldur	w8, [x29, #-0x40]
1000016c0:     	ldur	x9, [x29, #-0x38]
1000016c4:     	ldur	w10, [x29, #-0x30]
1000016c8:     	mov	w11, #0xca00            ; =51712
1000016cc:     	movk	w11, #0x3b9a, lsl #16
1000016d0:     	umulh	x12, x9, x11
1000016d4:     	mul	x9, x9, x11
1000016d8:     	adds	x9, x9, x10
1000016dc:     	cinc	x10, x12, hs
1000016e0:     	cmp	w8, #0x0
1000016e4:     	csel	x1, xzr, x10, ne
1000016e8:     	csel	x0, xzr, x9, ne
1000016ec:     	ldp	x29, x30, [sp, #0xb0]
1000016f0:     	ldp	x20, x19, [sp, #0xa0]
1000016f4:     	ldp	x22, x21, [sp, #0x90]
1000016f8:     	add	sp, sp, #0xc0
1000016fc:     	ret
100001700:     	sturb	w0, [x29, #-0x50]
100001704:     	adrp	x0, 0x100037000 <core::unicode::unicode_data::white_space::WHITESPACE_MAP+0x39f>
100001708:     	add	x0, x0, #0x1dd
10000170c:     	adrp	x3, 0x100044000 <dyld_stub_binder+0x100044000>
100001710:     	add	x3, x3, #0xf0
100001714:     	adrp	x4, 0x100044000 <dyld_stub_binder+0x100044000>
100001718:     	add	x4, x4, #0xd8
10000171c:     	sub	x2, x29, #0x50
100001720:     	mov	w1, #0x2b               ; =43
100001724:     	bl	0x10003038c <core::result::unwrap_failed>
100001728:     	ldurb	w8, [x29, #-0x3f]
10000172c:     	sturb	w8, [x29, #-0x50]
100001730:     	adrp	x0, 0x100037000 <core::unicode::unicode_data::white_space::WHITESPACE_MAP+0x39f>
100001734:     	add	x0, x0, #0x1dd
100001738:     	adrp	x3, 0x100044000 <dyld_stub_binder+0x100044000>
10000173c:     	add	x3, x3, #0xf0
100001740:     	adrp	x4, 0x100044000 <dyld_stub_binder+0x100044000>
100001744:     	add	x4, x4, #0xc0
100001748:     	sub	x2, x29, #0x50
10000174c:     	mov	w1, #0x2b               ; =43
100001750:     	bl	0x10003038c <core::result::unwrap_failed>
100001754:     	udf	#0x0
100001758:     	udf	#0x0
10000175c:     	udf	#0x0
100001760:     	udf	#0x0
100001764:     	udf	#0x0
100001768:     	udf	#0x0
10000176c:     	udf	#0x0
100001770:     	udf	#0x0
100001774:     	udf	#0x0
100001778:     	udf	#0x0
10000177c:     	udf	#0x0
100001780:     	udf	#0x0
0000000100003b54 <<brynja_crypto::ghash::Ghash>::update>:
100003b54:     	ldrb	w8, [x0, #0x28]
100003b58:     	cmp	w8, #0x2
100003b5c:     	b.ne	0x100003b74 <<brynja_crypto::ghash::Ghash>::update+0x20>
100003b60:     	ldr	x8, [x0, #0x8]
100003b64:     	subs	x8, x8, x2
100003b68:     	b.hs	0x100003b7c <<brynja_crypto::ghash::Ghash>::update+0x28>
100003b6c:     	mov	w0, #0x5                ; =5
100003b70:     	ret
100003b74:     	mov	w0, #0x4                ; =4
100003b78:     	ret
100003b7c:     	stp	x24, x23, [sp, #-0x30]!
100003b80:     	stp	x22, x21, [sp, #0x10]
100003b84:     	stp	x20, x19, [sp, #0x20]
100003b88:     	cbz	x2, 0x100003ee0 <<brynja_crypto::ghash::Ghash>::update+0x38c>
100003b8c:     	add	x9, x1, x2
100003b90:     	ldr	x4, [x0]
100003b94:     	ldp	x11, x10, [x0, #0x10]
100003b98:     	ldr	x12, [x0, #0x20]
100003b9c:     	add	x13, x0, #0x8
100003ba0:     	add	x14, x10, #0x1
100003ba4:     	add	x15, x10, #0x2
100003ba8:     	add	x16, x2, x1
100003bac:     	add	x17, x10, #0x11
100003bb0:     	mov	w2, #0xf                ; =15
100003bb4:     	mov	w3, #0x20               ; =32
100003bb8:     	mov	w5, #0x1                ; =1
100003bbc:     	dup.2d	v0, x5
100003bc0:     	mov	x5, x4
100003bc4:     	b	0x100003cb8 <<brynja_crypto::ghash::Ghash>::update+0x164>
100003bc8:     	mov	x4, #0x0                ; =0
100003bcc:     	mov	x5, #0x0                ; =0
100003bd0:     	ldp	x7, x6, [x11]
100003bd4:     	ldp	x20, x19, [x10]
100003bd8:     	rev	x7, x7
100003bdc:     	rev	x6, x6
100003be0:     	rev	x20, x20
100003be4:     	rev	x19, x19
100003be8:     	add	x12, x12, #0x1
100003bec:     	rbit	x19, x19
100003bf0:     	rbit	x20, x20
100003bf4:     	eor	x21, x19, x20
100003bf8:     	fmov	d1, x19
100003bfc:     	fmov	d2, x20
100003c00:     	rbit	x6, x6
100003c04:     	rbit	x7, x7
100003c08:     	eor	x19, x6, x7
100003c0c:     	fmov	d3, x6
100003c10:     	fmov	d4, x7
100003c14:     	pmull.1q	v2, v2, v4
100003c18:     	mov.d	x6, v2[1]
100003c1c:     	pmull.1q	v1, v1, v3
100003c20:     	mov.d	x7, v1[1]
100003c24:     	fmov	d3, x21
100003c28:     	fmov	d4, x19
100003c2c:     	pmull.1q	v3, v3, v4
100003c30:     	eor3.16b	v3, v2, v3, v1
100003c34:     	fmov	x19, d1
100003c38:     	mov.d	x20, v3[1]
100003c3c:     	eor	x19, x20, x19
100003c40:     	extr	x20, x7, x19, #0x3f
100003c44:     	fmov	x21, d3
100003c48:     	extr	x22, x7, x19, #0x3e
100003c4c:     	extr	x23, x7, x19, #0x39
100003c50:     	eor	x6, x6, x21
100003c54:     	fmov	x21, d2
100003c58:     	eor	x6, x6, x22
100003c5c:     	lsr	x22, x7, #63
100003c60:     	eor	x22, x22, x7, lsr #62
100003c64:     	eor	x22, x22, x7, lsr #57
100003c68:     	eor	x21, x21, x22, lsl #2
100003c6c:     	eor	x21, x21, x22, lsl #1
100003c70:     	eor	x21, x21, x22, lsl #7
100003c74:     	eor	x21, x21, x19, lsl #2
100003c78:     	eor	x21, x21, x19, lsl #1
100003c7c:     	eor	x20, x20, x23
100003c80:     	eor	x6, x6, x20
100003c84:     	eor	x20, x21, x19, lsl #7
100003c88:     	eor	x6, x6, x7
100003c8c:     	eor	x7, x22, x19
100003c90:     	eor	x7, x20, x7
100003c94:     	str	x12, [x0, #0x20]
100003c98:     	rev	x7, x7
100003c9c:     	rbit	x7, x7
100003ca0:     	rev	x6, x6
100003ca4:     	rbit	x6, x6
100003ca8:     	stp	x7, x6, [x10]
100003cac:     	str	xzr, [x0]
100003cb0:     	cmp	x9, x1
100003cb4:     	b.eq	0x100003ee0 <<brynja_crypto::ghash::Ghash>::update+0x38c>
100003cb8:     	cbnz	x5, 0x100003ec0 <<brynja_crypto::ghash::Ghash>::update+0x36c>
100003cbc:     	cmp	x1, x9
100003cc0:     	b.eq	0x100003ee0 <<brynja_crypto::ghash::Ghash>::update+0x38c>
100003cc4:     	ldrb	w6, [x1]
100003cc8:     	ldrb	w7, [x10, x5]
100003ccc:     	eor	w6, w7, w6
100003cd0:     	strb	w6, [x10, x5]
100003cd4:     	mvn	x6, x1
100003cd8:     	add	x7, x16, x6
100003cdc:     	sub	x6, x2, x5
100003ce0:     	cmp	x7, x6
100003ce4:     	csel	x6, x7, x6, lo
100003ce8:     	add	x6, x6, #0x1
100003cec:     	cmp	x6, #0x21
100003cf0:     	b.hs	0x100003d10 <<brynja_crypto::ghash::Ghash>::update+0x1bc>
100003cf4:     	mov	x6, x5
100003cf8:     	add	x4, x4, #0x1
100003cfc:     	add	x1, x1, #0x1
100003d00:     	str	x4, [x0]
100003d04:     	cmp	x5, #0xf
100003d08:     	b.ne	0x100003e7c <<brynja_crypto::ghash::Ghash>::update+0x328>
100003d0c:     	b	0x100003ea8 <<brynja_crypto::ghash::Ghash>::update+0x354>
100003d10:     	sub	x19, x2, x5
100003d14:     	cmp	x7, x19
100003d18:     	csel	x7, x7, x19, lo
100003d1c:     	add	x19, x15, x5
100003d20:     	add	x20, x19, x7
100003d24:     	add	x19, x1, #0x1
100003d28:     	add	x7, x1, x7
100003d2c:     	add	x21, x7, #0x2
100003d30:     	cmp	x0, x21
100003d34:     	ccmp	x19, x13, #0x2, lo
100003d38:     	cset	w7, lo
100003d3c:     	add	x22, x14, x5
100003d40:     	cmp	x22, x21
100003d44:     	ccmp	x19, x20, #0x2, lo
100003d48:     	cset	w19, lo
100003d4c:     	cmp	x22, x13
100003d50:     	ccmp	x0, x20, #0x2, lo
100003d54:     	b.lo	0x100003cf4 <<brynja_crypto::ghash::Ghash>::update+0x1a0>
100003d58:     	tbnz	w7, #0x0, 0x100003cf4 <<brynja_crypto::ghash::Ghash>::update+0x1a0>
100003d5c:     	tbnz	w19, #0x0, 0x100003cf4 <<brynja_crypto::ghash::Ghash>::update+0x1a0>
100003d60:     	ands	x7, x6, #0x1f
100003d64:     	csel	x7, x3, x7, eq
100003d68:     	sub	x19, x6, x7
100003d6c:     	add	x7, x1, x19
100003d70:     	add	x6, x5, x19
100003d74:     	movi.2d	v1, #0000000000000000
100003d78:     	movi.2d	v3, #0000000000000000
100003d7c:     	movi.2d	v7, #0000000000000000
100003d80:     	movi.2d	v2, #0000000000000000
100003d84:     	movi.2d	v6, #0000000000000000
100003d88:     	movi.2d	v5, #0000000000000000
100003d8c:     	fmov	d4, x4
100003d90:     	movi.2d	v17, #0000000000000000
100003d94:     	add	x4, x17, x5
100003d98:     	movi.2d	v16, #0000000000000000
100003d9c:     	add	x1, x1, #0x11
100003da0:     	movi.2d	v20, #0000000000000000
100003da4:     	movi.2d	v19, #0000000000000000
100003da8:     	movi.2d	v23, #0000000000000000
100003dac:     	movi.2d	v18, #0000000000000000
100003db0:     	movi.2d	v22, #0000000000000000
100003db4:     	movi.2d	v21, #0000000000000000
100003db8:     	movi.2d	v24, #0000000000000000
100003dbc:     	add.2d	v1, v1, v0
100003dc0:     	add.2d	v3, v3, v0
100003dc4:     	add.2d	v4, v4, v0
100003dc8:     	add.2d	v7, v7, v0
100003dcc:     	add.2d	v2, v2, v0
100003dd0:     	add.2d	v6, v6, v0
100003dd4:     	add.2d	v5, v5, v0
100003dd8:     	add.2d	v17, v17, v0
100003ddc:     	add.2d	v19, v19, v0
100003de0:     	add.2d	v20, v20, v0
100003de4:     	add.2d	v16, v16, v0
100003de8:     	add.2d	v23, v23, v0
100003dec:     	add.2d	v18, v18, v0
100003df0:     	add.2d	v22, v22, v0
100003df4:     	add.2d	v21, v21, v0
100003df8:     	add.2d	v24, v24, v0
100003dfc:     	ldp	q25, q26, [x1, #-0x10]
100003e00:     	ldp	q27, q28, [x4, #-0x10]
100003e04:     	eor.16b	v25, v27, v25
100003e08:     	eor.16b	v26, v28, v26
100003e0c:     	stp	q25, q26, [x4, #-0x10]
100003e10:     	add	x4, x4, #0x20
100003e14:     	add	x1, x1, #0x20
100003e18:     	subs	x19, x19, #0x20
100003e1c:     	b.ne	0x100003dbc <<brynja_crypto::ghash::Ghash>::update+0x268>
100003e20:     	add.2d	v7, v23, v7
100003e24:     	add.2d	v17, v24, v17
100003e28:     	add.2d	v3, v20, v3
100003e2c:     	add.2d	v6, v22, v6
100003e30:     	add.2d	v1, v19, v1
100003e34:     	add.2d	v5, v21, v5
100003e38:     	add.2d	v4, v16, v4
100003e3c:     	add.2d	v2, v18, v2
100003e40:     	add.2d	v2, v4, v2
100003e44:     	add.2d	v1, v1, v5
100003e48:     	add.2d	v1, v2, v1
100003e4c:     	add.2d	v2, v3, v6
100003e50:     	add.2d	v3, v7, v17
100003e54:     	add.2d	v2, v2, v3
100003e58:     	add.2d	v1, v1, v2
100003e5c:     	addp.2d	d1, v1
100003e60:     	str	d1, [x0]
100003e64:     	fmov	x4, d1
100003e68:     	add	x4, x4, #0x1
100003e6c:     	add	x1, x7, #0x1
100003e70:     	str	x4, [x0]
100003e74:     	cmp	x6, #0xf
100003e78:     	b.eq	0x100003ea8 <<brynja_crypto::ghash::Ghash>::update+0x354>
100003e7c:     	cmp	x1, x9
100003e80:     	b.eq	0x100003ea8 <<brynja_crypto::ghash::Ghash>::update+0x354>
100003e84:     	ldrb	w5, [x1], #0x1
100003e88:     	ldrb	w7, [x14, x6]
100003e8c:     	eor	w5, w7, w5
100003e90:     	strb	w5, [x14, x6]
100003e94:     	add	x4, x4, #0x1
100003e98:     	add	x6, x6, #0x1
100003e9c:     	str	x4, [x0]
100003ea0:     	cmp	x6, #0xf
100003ea4:     	b.ne	0x100003e7c <<brynja_crypto::ghash::Ghash>::update+0x328>
100003ea8:     	mov	x5, x4
100003eac:     	cmp	x5, #0x10
100003eb0:     	b.ne	0x100003cb0 <<brynja_crypto::ghash::Ghash>::update+0x15c>
100003eb4:     	cmn	x12, #0x1
100003eb8:     	b.eq	0x100003ecc <<brynja_crypto::ghash::Ghash>::update+0x378>
100003ebc:     	b	0x100003bc8 <<brynja_crypto::ghash::Ghash>::update+0x74>
100003ec0:     	cmp	x5, #0xf
100003ec4:     	b.ls	0x100003cbc <<brynja_crypto::ghash::Ghash>::update+0x168>
100003ec8:     	b	0x100003eac <<brynja_crypto::ghash::Ghash>::update+0x358>
100003ecc:     	mov	w0, #0x4                ; =4
100003ed0:     	ldp	x20, x19, [sp, #0x20]
100003ed4:     	ldp	x22, x21, [sp, #0x10]
100003ed8:     	ldp	x24, x23, [sp], #0x30
100003edc:     	ret
100003ee0:     	str	x8, [x0, #0x8]
100003ee4:     	mov	w0, #0xff               ; =255
100003ee8:     	ldp	x20, x19, [sp, #0x20]
100003eec:     	ldp	x22, x21, [sp, #0x10]
100003ef0:     	ldp	x24, x23, [sp], #0x30
100003ef4:     	ret
