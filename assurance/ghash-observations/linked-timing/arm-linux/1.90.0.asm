00000000002223f4 <brynja_ghash_timing::timed::h6da2234ae12ef399>:
  2223f4:      	sub	sp, sp, #0xc0
  2223f8:      	stp	x29, x30, [sp, #0x90]
  2223fc:      	stp	x22, x21, [sp, #0xa0]
  222400:      	stp	x20, x19, [sp, #0xb0]
  222404:      	add	x29, sp, #0x90
  222408:      	stp	xzr, xzr, [sp]
  22240c:      	sub	x8, x29, #0x20
  222410:      	mov	x19, x1
  222414:      	stp	xzr, xzr, [sp, #0x10]
  222418:      	mov	w1, #0x10               // =16
  22241c:      	stur	x0, [x29, #-0x20]
  222420:      	mov	x0, sp
  222424:      	ldur	x20, [x29, #-0x20]
  222428:      	bl	0x224484 <brynja_core::secret_memory_volatile::zeroize_region_volatile::ha96c9e6f1beacf35>
  22242c:      	adrp	x22, 0x28d000 <__stderr_FILE+0xb0>
  222430:      	ldr	x8, [x22, #0x190]
  222434:      	cbz	x8, 0x222820 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x42c>
  222438:      	ubfx	x21, x8, #3, #1
  22243c:      	ldr	x8, [x22, #0x190]
  222440:      	cbz	x8, 0x222830 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x43c>
  222444:      	ubfx	x8, x8, #1, #1
  222448:      	and	w8, w21, w8
  22244c:      	mov	w21, #0x4               // =4
  222450:      	cmp	w8, #0x1
  222454:      	b.ne	0x2224e8 <brynja_ghash_timing::timed::h6da2234ae12ef399+0xf4>
  222458:      	mov	x8, #0xa392             // =41874
  22245c:      	mov	x9, #0xfe78             // =65144
  222460:      	mov	x10, #0x2b2e            // =11054
  222464:      	movk	x8, #0x60b6, lsl #16
  222468:      	movk	x9, #0x71b2, lsl #16
  22246c:      	movk	x10, #0xca34, lsl #16
  222470:      	movk	x8, #0xdace, lsl #32
  222474:      	movk	x9, #0xc2b9, lsl #32
  222478:      	movk	x10, #0xfa59, lsl #32
  22247c:      	movk	x8, #0x388, lsl #48
  222480:      	movk	x9, #0xf328, lsl #48
  222484:      	movk	x10, #0x884c, lsl #48
  222488:      	stp	x9, x8, [x29, #-0x20]
  22248c:      	mov	x9, #0x2c3b             // =11323
  222490:      	sub	x8, x29, #0x20
  222494:      	movk	x9, #0xef8a, lsl #16
  222498:      	movk	x9, #0x4bd4, lsl #32
  22249c:      	ldp	x0, x1, [x29, #-0x20]
  2224a0:      	movk	x9, #0x66e9, lsl #48
  2224a4:      	stp	x10, x9, [x29, #-0x20]
  2224a8:      	ldp	x2, x3, [x29, #-0x20]
  2224ac:      	bl	0x2248e8 <brynja_crypto_cpu::ghash_pmull::multiply::h5983ec540555c984>
  2224b0:      	mov	x8, #0x6288             // =25224
  2224b4:      	mov	x9, #0xdeb7             // =57015
  2224b8:      	movk	x8, #0x9170, lsl #16
  2224bc:      	movk	x9, #0x5353, lsl #16
  2224c0:      	movk	x8, #0xc746, lsl #32
  2224c4:      	movk	x9, #0xb068, lsl #32
  2224c8:      	movk	x8, #0x5e2e, lsl #48
  2224cc:      	movk	x9, #0x2c85, lsl #48
  2224d0:      	eor	x8, x1, x8
  2224d4:      	eor	x9, x0, x9
  2224d8:      	orr	x8, x9, x8
  2224dc:      	cmp	x8, #0x0
  2224e0:      	mov	w8, #0x2                // =2
  2224e4:      	csel	w21, w8, w21, eq
  2224e8:      	adrp	x8, 0x200000 <__register_frame_info+0x200000>
  2224ec:      	mov	x9, sp
  2224f0:      	strb	w21, [sp, #0x48]
  2224f4:      	ldr	q0, [x8, #0x2e0]
  2224f8:      	str	x20, [sp, #0x30]
  2224fc:      	stp	x9, xzr, [sp, #0x38]
  222500:      	str	q0, [sp, #0x20]
  222504:      	bl	0x255294 <std::sys::pal::unix::time::Timespec::now::he34062c18c1247b7>
  222508:      	mov	w8, #0x10               // =16
  22250c:      	mov	x20, x0
  222510:      	mov	w21, w1
  222514:      	stp	x19, x8, [x29, #-0x20]
  222518:      	sub	x8, x29, #0x20
  22251c:      	add	x0, sp, #0x20
  222520:      	ldp	x8, x2, [x29, #-0x20]
  222524:      	mov	x1, x8
  222528:      	bl	0x2244f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62>
  22252c:      	and	w8, w0, #0xff
  222530:      	cmp	w8, #0x7
  222534:      	b.ne	0x2227f8 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x404>
  222538:      	mov	w8, #0x10               // =16
  22253c:      	add	x0, sp, #0x20
  222540:      	stp	x19, x8, [x29, #-0x20]
  222544:      	sub	x8, x29, #0x20
  222548:      	ldp	x1, x2, [x29, #-0x20]
  22254c:      	bl	0x2244f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62>
  222550:      	and	w8, w0, #0xff
  222554:      	cmp	w8, #0x7
  222558:      	b.ne	0x2227f8 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x404>
  22255c:      	mov	w8, #0x10               // =16
  222560:      	add	x0, sp, #0x20
  222564:      	stp	x19, x8, [x29, #-0x20]
  222568:      	sub	x8, x29, #0x20
  22256c:      	ldp	x1, x2, [x29, #-0x20]
  222570:      	bl	0x2244f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62>
  222574:      	and	w8, w0, #0xff
  222578:      	cmp	w8, #0x7
  22257c:      	b.ne	0x2227f8 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x404>
  222580:      	mov	w8, #0x10               // =16
  222584:      	add	x0, sp, #0x20
  222588:      	stp	x19, x8, [x29, #-0x20]
  22258c:      	sub	x8, x29, #0x20
  222590:      	ldp	x1, x2, [x29, #-0x20]
  222594:      	bl	0x2244f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62>
  222598:      	and	w8, w0, #0xff
  22259c:      	cmp	w8, #0x7
  2225a0:      	b.ne	0x2227f8 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x404>
  2225a4:      	mov	w8, #0x10               // =16
  2225a8:      	add	x0, sp, #0x20
  2225ac:      	stp	x19, x8, [x29, #-0x20]
  2225b0:      	sub	x8, x29, #0x20
  2225b4:      	ldp	x1, x2, [x29, #-0x20]
  2225b8:      	bl	0x2244f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62>
  2225bc:      	and	w8, w0, #0xff
  2225c0:      	cmp	w8, #0x7
  2225c4:      	b.ne	0x2227f8 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x404>
  2225c8:      	mov	w8, #0x10               // =16
  2225cc:      	add	x0, sp, #0x20
  2225d0:      	stp	x19, x8, [x29, #-0x20]
  2225d4:      	sub	x8, x29, #0x20
  2225d8:      	ldp	x1, x2, [x29, #-0x20]
  2225dc:      	bl	0x2244f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62>
  2225e0:      	and	w8, w0, #0xff
  2225e4:      	cmp	w8, #0x7
  2225e8:      	b.ne	0x2227f8 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x404>
  2225ec:      	mov	w8, #0x10               // =16
  2225f0:      	add	x0, sp, #0x20
  2225f4:      	stp	x19, x8, [x29, #-0x20]
  2225f8:      	sub	x8, x29, #0x20
  2225fc:      	ldp	x1, x2, [x29, #-0x20]
  222600:      	bl	0x2244f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62>
  222604:      	and	w8, w0, #0xff
  222608:      	cmp	w8, #0x7
  22260c:      	b.ne	0x2227f8 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x404>
  222610:      	mov	w8, #0x10               // =16
  222614:      	add	x0, sp, #0x20
  222618:      	stp	x19, x8, [x29, #-0x20]
  22261c:      	sub	x8, x29, #0x20
  222620:      	ldp	x1, x2, [x29, #-0x20]
  222624:      	bl	0x2244f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62>
  222628:      	and	w8, w0, #0xff
  22262c:      	cmp	w8, #0x7
  222630:      	b.ne	0x2227f8 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x404>
  222634:      	mov	w8, #0x10               // =16
  222638:      	add	x0, sp, #0x20
  22263c:      	stp	x19, x8, [x29, #-0x20]
  222640:      	sub	x8, x29, #0x20
  222644:      	ldp	x1, x2, [x29, #-0x20]
  222648:      	bl	0x2244f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62>
  22264c:      	and	w8, w0, #0xff
  222650:      	cmp	w8, #0x7
  222654:      	b.ne	0x2227f8 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x404>
  222658:      	mov	w8, #0x10               // =16
  22265c:      	add	x0, sp, #0x20
  222660:      	stp	x19, x8, [x29, #-0x20]
  222664:      	sub	x8, x29, #0x20
  222668:      	ldp	x1, x2, [x29, #-0x20]
  22266c:      	bl	0x2244f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62>
  222670:      	and	w8, w0, #0xff
  222674:      	cmp	w8, #0x7
  222678:      	b.ne	0x2227f8 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x404>
  22267c:      	mov	w8, #0x10               // =16
  222680:      	add	x0, sp, #0x20
  222684:      	stp	x19, x8, [x29, #-0x20]
  222688:      	sub	x8, x29, #0x20
  22268c:      	ldp	x1, x2, [x29, #-0x20]
  222690:      	bl	0x2244f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62>
  222694:      	and	w8, w0, #0xff
  222698:      	cmp	w8, #0x7
  22269c:      	b.ne	0x2227f8 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x404>
  2226a0:      	mov	w8, #0x10               // =16
  2226a4:      	add	x0, sp, #0x20
  2226a8:      	stp	x19, x8, [x29, #-0x20]
  2226ac:      	sub	x8, x29, #0x20
  2226b0:      	ldp	x1, x2, [x29, #-0x20]
  2226b4:      	bl	0x2244f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62>
  2226b8:      	and	w8, w0, #0xff
  2226bc:      	cmp	w8, #0x7
  2226c0:      	b.ne	0x2227f8 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x404>
  2226c4:      	mov	w8, #0x10               // =16
  2226c8:      	add	x0, sp, #0x20
  2226cc:      	stp	x19, x8, [x29, #-0x20]
  2226d0:      	sub	x8, x29, #0x20
  2226d4:      	ldp	x1, x2, [x29, #-0x20]
  2226d8:      	bl	0x2244f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62>
  2226dc:      	and	w8, w0, #0xff
  2226e0:      	cmp	w8, #0x7
  2226e4:      	b.ne	0x2227f8 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x404>
  2226e8:      	mov	w8, #0x10               // =16
  2226ec:      	add	x0, sp, #0x20
  2226f0:      	stp	x19, x8, [x29, #-0x20]
  2226f4:      	sub	x8, x29, #0x20
  2226f8:      	ldp	x1, x2, [x29, #-0x20]
  2226fc:      	bl	0x2244f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62>
  222700:      	and	w8, w0, #0xff
  222704:      	cmp	w8, #0x7
  222708:      	b.ne	0x2227f8 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x404>
  22270c:      	mov	w8, #0x10               // =16
  222710:      	add	x0, sp, #0x20
  222714:      	stp	x19, x8, [x29, #-0x20]
  222718:      	sub	x8, x29, #0x20
  22271c:      	ldp	x1, x2, [x29, #-0x20]
  222720:      	bl	0x2244f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62>
  222724:      	and	w8, w0, #0xff
  222728:      	cmp	w8, #0x7
  22272c:      	b.ne	0x2227f8 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x404>
  222730:      	mov	w8, #0x10               // =16
  222734:      	add	x0, sp, #0x20
  222738:      	stp	x19, x8, [x29, #-0x20]
  22273c:      	sub	x8, x29, #0x20
  222740:      	ldp	x1, x2, [x29, #-0x20]
  222744:      	bl	0x2244f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62>
  222748:      	and	w8, w0, #0xff
  22274c:      	cmp	w8, #0x7
  222750:      	b.ne	0x2227f8 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x404>
  222754:      	sub	x0, x29, #0x20
  222758:      	add	x1, sp, #0x20
  22275c:      	add	x2, sp, #0x10
  222760:      	bl	0x224844 <brynja_crypto::ghash::Ghash::finish::hf27297420a001d98>
  222764:      	ldurb	w8, [x29, #-0x20]
  222768:      	cmp	w8, #0x1
  22276c:      	b.eq	0x22284c <brynja_ghash_timing::timed::h6da2234ae12ef399+0x458>
  222770:      	ldp	x0, x1, [x29, #-0x18]
  222774:      	cmp	x0, #0x0
  222778:      	csinc	x8, x0, xzr, ne
  22277c:      	csel	x9, xzr, x1, eq
  222780:      	stp	x8, x9, [x29, #-0x20]
  222784:      	sub	x8, x29, #0x20
  222788:      	cbz	x0, 0x222790 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x39c>
  22278c:      	bl	0x224484 <brynja_core::secret_memory_volatile::zeroize_region_volatile::ha96c9e6f1beacf35>
  222790:      	bl	0x255294 <std::sys::pal::unix::time::Timespec::now::he34062c18c1247b7>
  222794:      	stur	x0, [x29, #-0x40]
  222798:      	sub	x0, x29, #0x20
  22279c:      	sub	x2, x29, #0x30
  2227a0:      	stur	w1, [x29, #-0x38]
  2227a4:      	sub	x1, x29, #0x40
  2227a8:      	stur	x20, [x29, #-0x30]
  2227ac:      	stur	w21, [x29, #-0x28]
  2227b0:      	bl	0x255c00 <std::sys::pal::unix::time::Timespec::sub_timespec::h1a5fa40430ea58bd>
  2227b4:      	ldur	x8, [x29, #-0x18]
  2227b8:      	mov	w9, #0xca00             // =51712
  2227bc:      	ldur	w11, [x29, #-0x20]
  2227c0:      	movk	w9, #0x3b9a, lsl #16
  2227c4:      	ldp	x20, x19, [sp, #0xb0]
  2227c8:      	mul	x10, x8, x9
  2227cc:      	ldp	x22, x21, [sp, #0xa0]
  2227d0:      	umulh	x8, x8, x9
  2227d4:      	ldur	w9, [x29, #-0x10]
  2227d8:      	ldp	x29, x30, [sp, #0x90]
  2227dc:      	adds	x9, x10, x9
  2227e0:      	cinc	x8, x8, hs
  2227e4:      	cmp	w11, #0x0
  2227e8:      	csel	x1, xzr, x8, ne
  2227ec:      	csel	x0, xzr, x9, ne
  2227f0:      	add	sp, sp, #0xc0
  2227f4:      	ret
  2227f8:      	sturb	w0, [x29, #-0x20]
  2227fc:      	nop
  222800:      	adr	x0, 0x202b91 <core::unicode::unicode_data::grapheme_extend::SHORT_OFFSET_RUNS::h46332ed5a9393272+0x55d>
  222804:      	nop
  222808:      	adr	x3, 0x27a3e0 <__register_frame_info+0x27a3e0>
  22280c:      	nop
  222810:      	adr	x4, 0x27a478 <__register_frame_info+0x27a478>
  222814:      	sub	x2, x29, #0x20
  222818:      	mov	w1, #0x2b               // =43
  22281c:      	bl	0x226e1c <core::result::unwrap_failed::h32b551aa3dff7cbc>
  222820:      	bl	0x256364 <std_detect::detect::cache::detect_and_initialize::hc4df1f5d10b6eedf>
  222824:      	ubfx	x21, x0, #3, #1
  222828:      	ldr	x8, [x22, #0x190]
  22282c:      	cbnz	x8, 0x222444 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x50>
  222830:      	bl	0x256364 <std_detect::detect::cache::detect_and_initialize::hc4df1f5d10b6eedf>
  222834:      	ubfx	x8, x0, #1, #1
  222838:      	and	w8, w21, w8
  22283c:      	mov	w21, #0x4               // =4
  222840:      	cmp	w8, #0x1
  222844:      	b.eq	0x222458 <brynja_ghash_timing::timed::h6da2234ae12ef399+0x64>
  222848:      	b	0x2224e8 <brynja_ghash_timing::timed::h6da2234ae12ef399+0xf4>
  22284c:      	ldurb	w8, [x29, #-0x1f]
  222850:      	nop
  222854:      	adr	x0, 0x202b91 <core::unicode::unicode_data::grapheme_extend::SHORT_OFFSET_RUNS::h46332ed5a9393272+0x55d>
  222858:      	nop
  22285c:      	adr	x3, 0x27a3e0 <__register_frame_info+0x27a3e0>
  222860:      	nop
  222864:      	adr	x4, 0x27a460 <__register_frame_info+0x27a460>
  222868:      	sub	x2, x29, #0x30
  22286c:      	mov	w1, #0x2b               // =43
  222870:      	sturb	w8, [x29, #-0x30]
  222874:      	bl	0x226e1c <core::result::unwrap_failed::h32b551aa3dff7cbc>
00000000002244f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62>:
  2244f0:      	ldrb	w8, [x0, #0x28]
  2244f4:      	cmp	w8, #0x2
  2244f8:      	b.ne	0x224530 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x40>
  2244fc:      	sub	sp, sp, #0x80
  224500:      	stp	x29, x30, [sp, #0x20]
  224504:      	stp	x28, x27, [sp, #0x30]
  224508:      	stp	x26, x25, [sp, #0x40]
  22450c:      	stp	x24, x23, [sp, #0x50]
  224510:      	stp	x22, x21, [sp, #0x60]
  224514:      	stp	x20, x19, [sp, #0x70]
  224518:      	add	x29, sp, #0x20
  22451c:      	ldr	x8, [x0, #0x8]
  224520:      	subs	x24, x8, x2
  224524:      	b.hs	0x224538 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x48>
  224528:      	mov	w0, #0x5                // =5
  22452c:      	b	0x224824 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x334>
  224530:      	mov	w0, #0x4                // =4
  224534:      	ret
  224538:      	cbz	x2, 0x22481c <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x32c>
  22453c:      	ldp	x28, x23, [x0, #0x10]
  224540:      	mov	w8, #0x1                // =1
  224544:      	ldr	x10, [x0]
  224548:      	dup	v28.2d, x8
  22454c:      	ldr	x21, [x0, #0x20]
  224550:      	add	x20, x1, x2
  224554:      	add	x3, x0, #0x8
  224558:      	add	x2, x2, x1
  22455c:      	add	x25, x23, #0x1
  224560:      	add	x17, x23, #0x2
  224564:      	add	x27, x23, #0x11
  224568:      	mov	w7, #0xf                // =15
  22456c:      	mov	w19, #0x20              // =32
  224570:      	mov	x11, x10
  224574:      	b	0x2245fc <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x10c>
  224578:      	ldp	x8, x9, [x28]
  22457c:      	mov	x22, x0
  224580:      	ldp	x10, x11, [x23]
  224584:      	mov	x26, x1
  224588:      	stp	x3, x2, [sp]
  22458c:      	add	x21, x21, #0x1
  224590:      	mov	x19, x17
  224594:      	rev	x2, x9
  224598:      	rev	x3, x8
  22459c:      	str	q28, [sp, #0x10]
  2245a0:      	rev	x8, x11
  2245a4:      	rev	x9, x10
  2245a8:      	mov	x0, x8
  2245ac:      	mov	x1, x9
  2245b0:      	bl	0x2248e8 <brynja_crypto_cpu::ghash_pmull::multiply::h5983ec540555c984>
  2245b4:      	ldp	x3, x2, [sp]
  2245b8:      	mov	x8, x0
  2245bc:      	ldr	q28, [sp, #0x10]
  2245c0:      	mov	x9, x1
  2245c4:      	mov	w7, #0xf                // =15
  2245c8:      	mov	x17, x19
  2245cc:      	mov	w19, #0x20              // =32
  2245d0:      	mov	x0, x22
  2245d4:      	mov	x1, x26
  2245d8:      	mov	x10, xzr
  2245dc:      	mov	x11, xzr
  2245e0:      	rev	x9, x9
  2245e4:      	rev	x8, x8
  2245e8:      	str	x21, [x22, #0x20]
  2245ec:      	stp	x9, x8, [x23]
  2245f0:      	str	xzr, [x22]
  2245f4:      	cmp	x20, x1
  2245f8:      	b.eq	0x22481c <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x32c>
  2245fc:      	cbnz	x11, 0x224808 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x318>
  224600:      	cmp	x1, x20
  224604:      	b.eq	0x22481c <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x32c>
  224608:      	mvn	x8, x1
  22460c:      	ldrb	w12, [x1]
  224610:      	ldrb	w13, [x23, x11]
  224614:      	add	x9, x2, x8
  224618:      	sub	x8, x7, x11
  22461c:      	cmp	x9, x8
  224620:      	eor	w12, w13, w12
  224624:      	strb	w12, [x23, x11]
  224628:      	csel	x8, x9, x8, lo
  22462c:      	add	x8, x8, #0x1
  224630:      	cmp	x8, #0x21
  224634:      	b.hs	0x224654 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x164>
  224638:      	mov	x8, x11
  22463c:      	add	x10, x10, #0x1
  224640:      	add	x1, x1, #0x1
  224644:      	cmp	x11, #0xf
  224648:      	str	x10, [x0]
  22464c:      	b.ne	0x2247c4 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x2d4>
  224650:      	b	0x2247f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x300>
  224654:      	sub	x12, x7, x11
  224658:      	add	x13, x1, #0x1
  22465c:      	add	x14, x25, x11
  224660:      	cmp	x9, x12
  224664:      	add	x15, x17, x11
  224668:      	csel	x9, x9, x12, lo
  22466c:      	add	x12, x1, x9
  224670:      	add	x15, x15, x9
  224674:      	add	x12, x12, #0x2
  224678:      	cmp	x0, x12
  22467c:      	ccmp	x13, x3, #0x2, lo
  224680:      	cset	w9, lo
  224684:      	cmp	x14, x12
  224688:      	ccmp	x13, x15, #0x2, lo
  22468c:      	cset	w12, lo
  224690:      	cmp	x14, x3
  224694:      	ccmp	x0, x15, #0x2, lo
  224698:      	b.lo	0x224638 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x148>
  22469c:      	tbnz	w9, #0x0, 0x224638 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x148>
  2246a0:      	tbnz	w12, #0x0, 0x224638 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x148>
  2246a4:      	movi	v0.2d, #0000000000000000
  2246a8:      	ands	x9, x8, #0x1f
  2246ac:      	movi	v1.2d, #0000000000000000
  2246b0:      	movi	v2.2d, #0000000000000000
  2246b4:      	movi	v7.2d, #0000000000000000
  2246b8:      	csel	x9, x19, x9, eq
  2246bc:      	movi	v4.2d, #0000000000000000
  2246c0:      	movi	v5.2d, #0000000000000000
  2246c4:      	add	x12, x1, #0x11
  2246c8:      	movi	v3.2d, #0000000000000000
  2246cc:      	movi	v17.2d, #0000000000000000
  2246d0:      	movi	v6.2d, #0000000000000000
  2246d4:      	mov	v0.d[0], x10
  2246d8:      	sub	x10, x8, x9
  2246dc:      	movi	v21.2d, #0000000000000000
  2246e0:      	movi	v16.2d, #0000000000000000
  2246e4:      	add	x9, x1, x10
  2246e8:      	add	x8, x11, x10
  2246ec:      	movi	v22.2d, #0000000000000000
  2246f0:      	movi	v19.2d, #0000000000000000
  2246f4:      	add	x11, x27, x11
  2246f8:      	movi	v20.2d, #0000000000000000
  2246fc:      	movi	v18.2d, #0000000000000000
  224700:      	movi	v23.2d, #0000000000000000
  224704:      	ldp	q24, q25, [x12, #-0x10]
  224708:      	add	v2.2d, v2.2d, v28.2d
  22470c:      	ldp	q26, q27, [x11, #-0x10]
  224710:      	add	v1.2d, v1.2d, v28.2d
  224714:      	add	v0.2d, v0.2d, v28.2d
  224718:      	add	v7.2d, v7.2d, v28.2d
  22471c:      	add	v4.2d, v4.2d, v28.2d
  224720:      	add	v5.2d, v5.2d, v28.2d
  224724:      	add	v3.2d, v3.2d, v28.2d
  224728:      	add	v17.2d, v17.2d, v28.2d
  22472c:      	eor	v24.16b, v26.16b, v24.16b
  224730:      	eor	v25.16b, v27.16b, v25.16b
  224734:      	subs	x10, x10, #0x20
  224738:      	add	v16.2d, v16.2d, v28.2d
  22473c:      	add	v21.2d, v21.2d, v28.2d
  224740:      	add	x12, x12, #0x20
  224744:      	add	v6.2d, v6.2d, v28.2d
  224748:      	add	v22.2d, v22.2d, v28.2d
  22474c:      	add	v19.2d, v19.2d, v28.2d
  224750:      	add	v20.2d, v20.2d, v28.2d
  224754:      	stp	q24, q25, [x11, #-0x10]
  224758:      	add	x11, x11, #0x20
  22475c:      	add	v18.2d, v18.2d, v28.2d
  224760:      	add	v23.2d, v23.2d, v28.2d
  224764:      	b.ne	0x224704 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x214>
  224768:      	add	v7.2d, v22.2d, v7.2d
  22476c:      	add	v17.2d, v23.2d, v17.2d
  224770:      	add	v1.2d, v21.2d, v1.2d
  224774:      	add	v0.2d, v6.2d, v0.2d
  224778:      	add	v4.2d, v19.2d, v4.2d
  22477c:      	add	v5.2d, v20.2d, v5.2d
  224780:      	add	v2.2d, v16.2d, v2.2d
  224784:      	add	v3.2d, v18.2d, v3.2d
  224788:      	add	v0.2d, v0.2d, v4.2d
  22478c:      	add	v1.2d, v1.2d, v5.2d
  224790:      	add	v2.2d, v2.2d, v3.2d
  224794:      	add	v3.2d, v7.2d, v17.2d
  224798:      	add	v0.2d, v0.2d, v2.2d
  22479c:      	add	v1.2d, v1.2d, v3.2d
  2247a0:      	add	v0.2d, v0.2d, v1.2d
  2247a4:      	addp	d0, v0.2d
  2247a8:      	fmov	x10, d0
  2247ac:      	str	d0, [x0]
  2247b0:      	add	x10, x10, #0x1
  2247b4:      	add	x1, x9, #0x1
  2247b8:      	cmp	x8, #0xf
  2247bc:      	str	x10, [x0]
  2247c0:      	b.eq	0x2247f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x300>
  2247c4:      	cmp	x1, x20
  2247c8:      	b.eq	0x2247f0 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x300>
  2247cc:      	ldrb	w9, [x1], #0x1
  2247d0:      	ldrb	w11, [x25, x8]
  2247d4:      	add	x10, x10, #0x1
  2247d8:      	eor	w9, w11, w9
  2247dc:      	strb	w9, [x25, x8]
  2247e0:      	add	x8, x8, #0x1
  2247e4:      	cmp	x8, #0xf
  2247e8:      	str	x10, [x0]
  2247ec:      	b.ne	0x2247c4 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x2d4>
  2247f0:      	mov	x11, x10
  2247f4:      	cmp	x11, #0x10
  2247f8:      	b.ne	0x2245f4 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x104>
  2247fc:      	cmn	x21, #0x1
  224800:      	b.eq	0x224814 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x324>
  224804:      	b	0x224578 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x88>
  224808:      	cmp	x11, #0xf
  22480c:      	b.ls	0x224600 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x110>
  224810:      	b	0x2247f4 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x304>
  224814:      	mov	w0, #0x4                // =4
  224818:      	b	0x224824 <brynja_crypto::ghash::Ghash::update::hbc0ec9dcd60b7d62+0x334>
  22481c:      	str	x24, [x0, #0x8]
  224820:      	mov	w0, #0x7                // =7
  224824:      	ldp	x20, x19, [sp, #0x70]
  224828:      	ldp	x22, x21, [sp, #0x60]
  22482c:      	ldp	x24, x23, [sp, #0x50]
  224830:      	ldp	x26, x25, [sp, #0x40]
  224834:      	ldp	x28, x27, [sp, #0x30]
  224838:      	ldp	x29, x30, [sp, #0x20]
  22483c:      	add	sp, sp, #0x80
  224840:      	ret
00000000002248e8 <brynja_crypto_cpu::ghash_pmull::multiply::h5983ec540555c984>:
  2248e8:      	rbit	x8, x2
  2248ec:      	rbit	x9, x0
  2248f0:      	rbit	x10, x1
  2248f4:      	rbit	x11, x3
  2248f8:      	fmov	d0, x8
  2248fc:      	fmov	d1, x9
  224900:      	fmov	d2, x10
  224904:      	eor	x9, x9, x10
  224908:      	eor	x8, x8, x11
  22490c:      	fmov	d3, x9
  224910:      	pmull	v0.1q, v1.1d, v0.1d
  224914:      	fmov	d1, x11
  224918:      	pmull	v1.1q, v2.1d, v1.1d
  22491c:      	fmov	d2, x8
  224920:      	mov	x12, v0.d[1]
  224924:      	fmov	x11, d0
  224928:      	pmull	v2.1q, v3.1d, v2.1d
  22492c:      	eor	v3.16b, v1.16b, v0.16b
  224930:      	fmov	x9, d1
  224934:      	mov	x13, v1.d[1]
  224938:      	lsr	x8, x12, #63
  22493c:      	eor	x8, x8, x12, lsr #62
  224940:      	eor	v2.16b, v3.16b, v2.16b
  224944:      	eor	x8, x8, x12, lsr #57
  224948:      	mov	x10, v2.d[1]
  22494c:      	eor	x9, x9, x8, lsl #2
  224950:      	eor	x9, x9, x8, lsl #1
  224954:      	eor	x10, x10, x11
  224958:      	fmov	x11, d2
  22495c:      	eor	x9, x9, x8, lsl #7
  224960:      	extr	x14, x12, x10, #0x3f
  224964:      	extr	x15, x12, x10, #0x3e
  224968:      	extr	x16, x12, x10, #0x39
  22496c:      	eor	x8, x8, x10
  224970:      	eor	x9, x9, x10, lsl #2
  224974:      	eor	x11, x13, x11
  224978:      	eor	x11, x11, x15
  22497c:      	eor	x13, x14, x16
  224980:      	eor	x9, x9, x10, lsl #1
  224984:      	eor	x11, x11, x13
  224988:      	eor	x9, x9, x10, lsl #7
  22498c:      	eor	x8, x9, x8
  224990:      	eor	x9, x11, x12
  224994:      	rbit	x0, x9
  224998:      	rbit	x1, x8
  22499c:      	ret
