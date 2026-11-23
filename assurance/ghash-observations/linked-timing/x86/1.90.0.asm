0000000000012320 <brynja_ghash_timing::timed::h720b496f80791f98>:
   12320:      	pushq	%rbp
   12321:      	pushq	%r15
   12323:      	pushq	%r14
   12325:      	pushq	%rbx
   12326:      	subq	$0x98, %rsp
   1232d:      	movq	%rsi, %rbx
   12330:      	xorps	%xmm0, %xmm0
   12333:      	movaps	%xmm0, 0x70(%rsp)
   12338:      	movaps	%xmm0, 0x80(%rsp)
   12340:      	movq	%rdi, (%rsp)
   12344:      	movq	%rsp, %rax
   12347:      	movq	(%rsp), %r15
   1234b:      	leaq	0x70(%rsp), %r14
   12350:      	movl	$0x10, %esi
   12355:      	movq	%r14, %rdi
   12358:      	callq	0x14370 <brynja_core::secret_memory_volatile::zeroize_region_volatile::h74c9935cebe3283e>
   1235d:      	movq	0x44814(%rip), %rax     # 0x56b78 <std_detect::detect::cache::CACHE::hb6755393302ff344 (.0)>
   12364:      	testq	%rax, %rax
   12367:      	je	0x127a0 <brynja_ghash_timing::timed::h720b496f80791f98+0x480>
   1236d:      	movb	$0x4, %cl
   1236f:      	testb	$0x2, %al
   12371:      	je	0x123ef <brynja_ghash_timing::timed::h720b496f80791f98+0xcf>
   12373:      	movabsq	$0x388dace60b6a392, %rax # imm = 0x388DACE60B6A392
   1237d:      	movq	%rax, 0x8(%rsp)
   12382:      	movabsq	$-0xcd73d468e4d0188, %rax # imm = 0xF328C2B971B2FE78
   1238c:      	movq	%rax, (%rsp)
   12390:      	movq	%rsp, %rax
   12393:      	movq	(%rsp), %rdi
   12397:      	movq	0x8(%rsp), %rsi
   1239c:      	movabsq	$0x66e94bd4ef8a2c3b, %rax # imm = 0x66E94BD4EF8A2C3B
   123a6:      	movq	%rax, 0x8(%rsp)
   123ab:      	movabsq	$-0x77b305a635cbd4d2, %rax # imm = 0x884CFA59CA342B2E
   123b5:      	movq	%rax, (%rsp)
   123b9:      	movq	%rsp, %rax
   123bc:      	movq	(%rsp), %rdx
   123c0:      	movq	0x8(%rsp), %rcx
   123c5:      	callq	0x14750 <brynja_crypto_cpu::ghash_pclmul::multiply::h8afef9e1d4b7828f>
   123ca:      	movabsq	$0x5e2ec74691706288, %rcx # imm = 0x5E2EC74691706288
   123d4:      	xorq	%rdx, %rcx
   123d7:      	movabsq	$0x2c85b0685353deb7, %rdx # imm = 0x2C85B0685353DEB7
   123e1:      	xorq	%rax, %rdx
   123e4:      	orq	%rcx, %rdx
   123e7:      	setne	%cl
   123ea:      	addb	%cl, %cl
   123ec:      	addb	$0x2, %cl
   123ef:      	movq	$0x0, 0x40(%rsp)
   123f8:      	movb	%cl, 0x48(%rsp)
   123fc:      	movq	%r15, 0x30(%rsp)
   12401:      	movq	%r14, 0x38(%rsp)
   12406:      	movq	$0x0, 0x20(%rsp)
   1240f:      	movq	$0x100, 0x28(%rsp)      # imm = 0x100
   12418:      	callq	0x503d0 <std::sys::pal::unix::time::Timespec::now::h224d2ca8dcd19161>
   1241d:      	movq	%rax, %r14
   12420:      	movl	%edx, %ebp
   12422:      	movq	%rbx, (%rsp)
   12426:      	movq	$0x10, 0x8(%rsp)
   1242f:      	movq	%rsp, %rax
   12432:      	movq	(%rsp), %rsi
   12436:      	movq	0x8(%rsp), %rdx
   1243b:      	leaq	0x20(%rsp), %rdi
   12440:      	callq	0x14430 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c>
   12445:      	cmpb	$0x7, %al
   12447:      	jne	0x1277b <brynja_ghash_timing::timed::h720b496f80791f98+0x45b>
   1244d:      	movq	%rbx, (%rsp)
   12451:      	movq	$0x10, 0x8(%rsp)
   1245a:      	movq	%rsp, %rax
   1245d:      	movq	(%rsp), %rsi
   12461:      	movq	0x8(%rsp), %rdx
   12466:      	leaq	0x20(%rsp), %rdi
   1246b:      	callq	0x14430 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c>
   12470:      	cmpb	$0x7, %al
   12472:      	jne	0x1277b <brynja_ghash_timing::timed::h720b496f80791f98+0x45b>
   12478:      	movq	%rbx, (%rsp)
   1247c:      	movq	$0x10, 0x8(%rsp)
   12485:      	movq	%rsp, %rax
   12488:      	movq	(%rsp), %rsi
   1248c:      	movq	0x8(%rsp), %rdx
   12491:      	leaq	0x20(%rsp), %rdi
   12496:      	callq	0x14430 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c>
   1249b:      	cmpb	$0x7, %al
   1249d:      	jne	0x1277b <brynja_ghash_timing::timed::h720b496f80791f98+0x45b>
   124a3:      	movq	%rbx, (%rsp)
   124a7:      	movq	$0x10, 0x8(%rsp)
   124b0:      	movq	%rsp, %rax
   124b3:      	movq	(%rsp), %rsi
   124b7:      	movq	0x8(%rsp), %rdx
   124bc:      	leaq	0x20(%rsp), %rdi
   124c1:      	callq	0x14430 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c>
   124c6:      	cmpb	$0x7, %al
   124c8:      	jne	0x1277b <brynja_ghash_timing::timed::h720b496f80791f98+0x45b>
   124ce:      	movq	%rbx, (%rsp)
   124d2:      	movq	$0x10, 0x8(%rsp)
   124db:      	movq	%rsp, %rax
   124de:      	movq	(%rsp), %rsi
   124e2:      	movq	0x8(%rsp), %rdx
   124e7:      	leaq	0x20(%rsp), %rdi
   124ec:      	callq	0x14430 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c>
   124f1:      	cmpb	$0x7, %al
   124f3:      	jne	0x1277b <brynja_ghash_timing::timed::h720b496f80791f98+0x45b>
   124f9:      	movq	%rbx, (%rsp)
   124fd:      	movq	$0x10, 0x8(%rsp)
   12506:      	movq	%rsp, %rax
   12509:      	movq	(%rsp), %rsi
   1250d:      	movq	0x8(%rsp), %rdx
   12512:      	leaq	0x20(%rsp), %rdi
   12517:      	callq	0x14430 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c>
   1251c:      	cmpb	$0x7, %al
   1251e:      	jne	0x1277b <brynja_ghash_timing::timed::h720b496f80791f98+0x45b>
   12524:      	movq	%rbx, (%rsp)
   12528:      	movq	$0x10, 0x8(%rsp)
   12531:      	movq	%rsp, %rax
   12534:      	movq	(%rsp), %rsi
   12538:      	movq	0x8(%rsp), %rdx
   1253d:      	leaq	0x20(%rsp), %rdi
   12542:      	callq	0x14430 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c>
   12547:      	cmpb	$0x7, %al
   12549:      	jne	0x1277b <brynja_ghash_timing::timed::h720b496f80791f98+0x45b>
   1254f:      	movq	%rbx, (%rsp)
   12553:      	movq	$0x10, 0x8(%rsp)
   1255c:      	movq	%rsp, %rax
   1255f:      	movq	(%rsp), %rsi
   12563:      	movq	0x8(%rsp), %rdx
   12568:      	leaq	0x20(%rsp), %rdi
   1256d:      	callq	0x14430 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c>
   12572:      	cmpb	$0x7, %al
   12574:      	jne	0x1277b <brynja_ghash_timing::timed::h720b496f80791f98+0x45b>
   1257a:      	movq	%rbx, (%rsp)
   1257e:      	movq	$0x10, 0x8(%rsp)
   12587:      	movq	%rsp, %rax
   1258a:      	movq	(%rsp), %rsi
   1258e:      	movq	0x8(%rsp), %rdx
   12593:      	leaq	0x20(%rsp), %rdi
   12598:      	callq	0x14430 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c>
   1259d:      	cmpb	$0x7, %al
   1259f:      	jne	0x1277b <brynja_ghash_timing::timed::h720b496f80791f98+0x45b>
   125a5:      	movq	%rbx, (%rsp)
   125a9:      	movq	$0x10, 0x8(%rsp)
   125b2:      	movq	%rsp, %rax
   125b5:      	movq	(%rsp), %rsi
   125b9:      	movq	0x8(%rsp), %rdx
   125be:      	leaq	0x20(%rsp), %rdi
   125c3:      	callq	0x14430 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c>
   125c8:      	cmpb	$0x7, %al
   125ca:      	jne	0x1277b <brynja_ghash_timing::timed::h720b496f80791f98+0x45b>
   125d0:      	movq	%rbx, (%rsp)
   125d4:      	movq	$0x10, 0x8(%rsp)
   125dd:      	movq	%rsp, %rax
   125e0:      	movq	(%rsp), %rsi
   125e4:      	movq	0x8(%rsp), %rdx
   125e9:      	leaq	0x20(%rsp), %rdi
   125ee:      	callq	0x14430 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c>
   125f3:      	cmpb	$0x7, %al
   125f5:      	jne	0x1277b <brynja_ghash_timing::timed::h720b496f80791f98+0x45b>
   125fb:      	movq	%rbx, (%rsp)
   125ff:      	movq	$0x10, 0x8(%rsp)
   12608:      	movq	%rsp, %rax
   1260b:      	movq	(%rsp), %rsi
   1260f:      	movq	0x8(%rsp), %rdx
   12614:      	leaq	0x20(%rsp), %rdi
   12619:      	callq	0x14430 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c>
   1261e:      	cmpb	$0x7, %al
   12620:      	jne	0x1277b <brynja_ghash_timing::timed::h720b496f80791f98+0x45b>
   12626:      	movq	%rbx, (%rsp)
   1262a:      	movq	$0x10, 0x8(%rsp)
   12633:      	movq	%rsp, %rax
   12636:      	movq	(%rsp), %rsi
   1263a:      	movq	0x8(%rsp), %rdx
   1263f:      	leaq	0x20(%rsp), %rdi
   12644:      	callq	0x14430 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c>
   12649:      	cmpb	$0x7, %al
   1264b:      	jne	0x1277b <brynja_ghash_timing::timed::h720b496f80791f98+0x45b>
   12651:      	movq	%rbx, (%rsp)
   12655:      	movq	$0x10, 0x8(%rsp)
   1265e:      	movq	%rsp, %rax
   12661:      	movq	(%rsp), %rsi
   12665:      	movq	0x8(%rsp), %rdx
   1266a:      	leaq	0x20(%rsp), %rdi
   1266f:      	callq	0x14430 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c>
   12674:      	cmpb	$0x7, %al
   12676:      	jne	0x1277b <brynja_ghash_timing::timed::h720b496f80791f98+0x45b>
   1267c:      	movq	%rbx, (%rsp)
   12680:      	movq	$0x10, 0x8(%rsp)
   12689:      	movq	%rsp, %rax
   1268c:      	movq	(%rsp), %rsi
   12690:      	movq	0x8(%rsp), %rdx
   12695:      	leaq	0x20(%rsp), %rdi
   1269a:      	callq	0x14430 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c>
   1269f:      	cmpb	$0x7, %al
   126a1:      	jne	0x1277b <brynja_ghash_timing::timed::h720b496f80791f98+0x45b>
   126a7:      	movq	%rbx, (%rsp)
   126ab:      	movq	$0x10, 0x8(%rsp)
   126b4:      	movq	%rsp, %rax
   126b7:      	movq	(%rsp), %rsi
   126bb:      	movq	0x8(%rsp), %rdx
   126c0:      	leaq	0x20(%rsp), %rdi
   126c5:      	callq	0x14430 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c>
   126ca:      	cmpb	$0x7, %al
   126cc:      	jne	0x1277b <brynja_ghash_timing::timed::h720b496f80791f98+0x45b>
   126d2:      	movq	%rsp, %rdi
   126d5:      	leaq	0x20(%rsp), %rsi
   126da:      	leaq	0x80(%rsp), %rdx
   126e2:      	callq	0x146e0 <brynja_crypto::ghash::Ghash::finish::h1b2e39d6d5ab42e3>
   126e7:      	cmpb	$0x1, (%rsp)
   126eb:      	je	0x127b4 <brynja_ghash_timing::timed::h720b496f80791f98+0x494>
   126f1:      	movq	0x8(%rsp), %rdi
   126f6:      	movl	$0x1, %eax
   126fb:      	testq	%rdi, %rdi
   126fe:      	cmovneq	%rdi, %rax
   12702:      	movq	0x10(%rsp), %rsi
   12707:      	movq	%rsi, %rcx
   1270a:      	cmoveq	%rdi, %rcx
   1270e:      	movq	%rax, (%rsp)
   12712:      	movq	%rcx, 0x8(%rsp)
   12717:      	movq	%rsp, %rax
   1271a:      	je	0x12721 <brynja_ghash_timing::timed::h720b496f80791f98+0x401>
   1271c:      	callq	0x14370 <brynja_core::secret_memory_volatile::zeroize_region_volatile::h74c9935cebe3283e>
   12721:      	callq	0x503d0 <std::sys::pal::unix::time::Timespec::now::h224d2ca8dcd19161>
   12726:      	movq	%rax, 0x60(%rsp)
   1272b:      	movl	%edx, 0x68(%rsp)
   1272f:      	movq	%r14, 0x50(%rsp)
   12734:      	movl	%ebp, 0x58(%rsp)
   12738:      	movq	%rsp, %rdi
   1273b:      	leaq	0x60(%rsp), %rsi
   12740:      	leaq	0x50(%rsp), %rdx
   12745:      	callq	0x50cf0 <std::sys::pal::unix::time::Timespec::sub_timespec::h4edae83e47a00da9>
   1274a:      	movl	$0x3b9aca00, %eax       # imm = 0x3B9ACA00
   1274f:      	mulq	0x8(%rsp)
   12754:      	movl	0x10(%rsp), %ecx
   12758:      	addq	%rcx, %rax
   1275b:      	adcq	$0x0, %rdx
   1275f:      	xorl	%ecx, %ecx
   12761:      	cmpb	$0x0, (%rsp)
   12765:      	cmovneq	%rcx, %rax
   12769:      	cmovneq	%rcx, %rdx
   1276d:      	addq	$0x98, %rsp
   12774:      	popq	%rbx
   12775:      	popq	%r14
   12777:      	popq	%r15
   12779:      	popq	%rbp
   1277a:      	retq
   1277b:      	movb	%al, (%rsp)
   1277e:      	leaq	-0xadae(%rip), %rdi     # 0x79d7 <core::unicode::unicode_data::grapheme_extend::SHORT_OFFSET_RUNS::h2ae729b4dfffb971+0x4a3>
   12785:      	leaq	0x403cc(%rip), %rcx     # 0x52b58 <write+0x52b58>
   1278c:      	leaq	0x4045d(%rip), %r8      # 0x52bf0 <write+0x52bf0>
   12793:      	movq	%rsp, %rdx
   12796:      	movl	$0x2b, %esi
   1279b:      	callq	0x16f70 <core::result::unwrap_failed::h95bc3f5a607b2c95>
   127a0:      	callq	0x51480 <std_detect::detect::cache::detect_and_initialize::hd21b90854bd2a812>
   127a5:      	movb	$0x4, %cl
   127a7:      	testb	$0x2, %al
   127a9:      	jne	0x12373 <brynja_ghash_timing::timed::h720b496f80791f98+0x53>
   127af:      	jmp	0x123ef <brynja_ghash_timing::timed::h720b496f80791f98+0xcf>
   127b4:      	movzbl	0x1(%rsp), %eax
   127b9:      	movb	%al, 0x50(%rsp)
   127bd:      	leaq	-0xaded(%rip), %rdi     # 0x79d7 <core::unicode::unicode_data::grapheme_extend::SHORT_OFFSET_RUNS::h2ae729b4dfffb971+0x4a3>
   127c4:      	leaq	0x4038d(%rip), %rcx     # 0x52b58 <write+0x52b58>
   127cb:      	leaq	0x40406(%rip), %r8      # 0x52bd8 <write+0x52bd8>
   127d2:      	leaq	0x50(%rsp), %rdx
   127d7:      	movl	$0x2b, %esi
   127dc:      	callq	0x16f70 <core::result::unwrap_failed::h95bc3f5a607b2c95>
   127e1:      	int3
   127e2:      	int3
   127e3:      	int3
   127e4:      	int3
   127e5:      	int3
   127e6:      	int3
   127e7:      	int3
   127e8:      	int3
   127e9:      	int3
   127ea:      	int3
   127eb:      	int3
   127ec:      	int3
   127ed:      	int3
   127ee:      	int3
   127ef:      	int3
0000000000014430 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c>:
   14430:      	cmpb	$0x2, 0x28(%rdi)
   14434:      	jne	0x144a1 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x71>
   14436:      	movq	0x8(%rdi), %rcx
   1443a:      	movb	$0x5, %al
   1443c:      	subq	%rdx, %rcx
   1443f:      	jb	0x144a3 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x73>
   14441:      	pushq	%rbp
   14442:      	pushq	%r15
   14444:      	pushq	%r14
   14446:      	pushq	%r13
   14448:      	pushq	%r12
   1444a:      	pushq	%rbx
   1444b:      	subq	$0x38, %rsp
   1444f:      	movq	%rcx, 0x20(%rsp)
   14454:      	testq	%rdx, %rdx
   14457:      	je	0x146b8 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x288>
   1445d:      	addq	%rsi, %rdx
   14460:      	movq	(%rdi), %rcx
   14463:      	movq	0x10(%rdi), %rax
   14467:      	movq	%rax, 0x10(%rsp)
   1446c:      	movq	0x18(%rdi), %r15
   14470:      	movq	0x20(%rdi), %r11
   14474:      	leaq	0x8(%rdi), %rax
   14478:      	movq	%rax, 0x30(%rsp)
   1447d:      	leaq	0x1(%r15), %rbp
   14481:      	leaq	0x2(%r15), %rax
   14485:      	movq	%rax, 0x28(%rsp)
   1448a:      	leaq	0x3(%r15), %rax
   1448e:      	movq	%rax, 0x18(%rsp)
   14493:      	pcmpeqd	%xmm2, %xmm2
   14497:      	movq	%rcx, %rax
   1449a:      	movq	%r15, 0x8(%rsp)
   1449f:      	jmp	0x14519 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0xe9>
   144a1:      	movb	$0x4, %al
   144a3:      	retq
   144a4:      	movq	0x10(%rsp), %rax
   144a9:      	movq	(%rax), %rcx
   144ac:      	movq	0x8(%rax), %rax
   144b0:      	movq	0x8(%r15), %r8
   144b4:      	bswapq	%rax
   144b7:      	bswapq	%rcx
   144ba:      	bswapq	%r8
   144bd:      	movq	(%r15), %r9
   144c0:      	bswapq	%r9
   144c3:      	incq	%r11
   144c6:      	movq	%rdi, %r13
   144c9:      	movq	%r8, %rdi
   144cc:      	movq	%rsi, %r12
   144cf:      	movq	%r9, %rsi
   144d2:      	movq	%rdx, %r14
   144d5:      	movq	%rax, %rdx
   144d8:      	movq	%r11, %rbx
   144db:      	callq	0x14750 <brynja_crypto_cpu::ghash_pclmul::multiply::h8afef9e1d4b7828f>
   144e0:      	pcmpeqd	%xmm2, %xmm2
   144e4:      	movq	%rbx, %r11
   144e7:      	movq	%r12, %rsi
   144ea:      	movq	%r13, %rdi
   144ed:      	movq	%rdx, %rcx
   144f0:      	movq	%r14, %rdx
   144f3:      	bswapq	%rax
   144f6:      	movq	%rbx, 0x20(%r13)
   144fa:      	bswapq	%rcx
   144fd:      	movq	%rcx, (%r15)
   14500:      	movq	%rax, 0x8(%r15)
   14504:      	movq	$0x0, (%r13)
   1450c:      	xorl	%ecx, %ecx
   1450e:      	xorl	%eax, %eax
   14510:      	cmpq	%rsi, %rdx
   14513:      	je	0x146b8 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x288>
   14519:      	testq	%rax, %rax
   1451c:      	jne	0x146a8 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x278>
   14522:      	cmpq	%rdx, %rsi
   14525:      	je	0x146b8 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x288>
   1452b:      	movzbl	(%rsi), %r8d
   1452f:      	xorb	%r8b, (%r15,%rax)
   14533:      	movq	%rsi, %r10
   14536:      	notq	%r10
   14539:      	addq	%rdx, %r10
   1453c:      	movl	$0xf, %r9d
   14542:      	subq	%rax, %r9
   14545:      	cmpq	%r9, %r10
   14548:      	movq	%r9, %r8
   1454b:      	cmovbq	%r10, %r8
   1454f:      	incq	%r8
   14552:      	cmpq	$0x9, %r8
   14556:      	jae	0x14560 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x130>
   14558:      	movq	%rsi, %r9
   1455b:      	jmp	0x14654 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x224>
   14560:      	movq	%r11, (%rsp)
   14564:      	leaq	(%rax,%rbp), %r14
   14568:      	cmpq	%r9, %r10
   1456b:      	cmovbq	%r10, %r9
   1456f:      	movq	0x28(%rsp), %r10
   14574:      	leaq	(%r10,%rax), %r12
   14578:      	addq	%r9, %r12
   1457b:      	leaq	0x1(%rsi), %r13
   1457f:      	leaq	(%rsi,%r9), %r10
   14583:      	addq	$0x2, %r10
   14587:      	cmpq	%r12, %rdi
   1458a:      	setb	%bl
   1458d:      	movq	0x30(%rsp), %r11
   14592:      	cmpq	%r11, %r14
   14595:      	setb	%r15b
   14599:      	cmpq	%r10, %rdi
   1459c:      	setb	%r9b
   145a0:      	cmpq	%r11, %r13
   145a3:      	setb	%r11b
   145a7:      	cmpq	%r10, %r14
   145aa:      	setb	%r10b
   145ae:      	cmpq	%r12, %r13
   145b1:      	setb	%r14b
   145b5:      	testb	%r15b, %bl
   145b8:      	jne	0x14645 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x215>
   145be:      	andb	%r11b, %r9b
   145c1:      	movq	0x8(%rsp), %r15
   145c6:      	jne	0x14640 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x210>
   145c8:      	andb	%r14b, %r10b
   145cb:      	jne	0x14640 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x210>
   145cd:      	movl	%r8d, %r9d
   145d0:      	andl	$0x3, %r9d
   145d4:      	movl	$0x4, %r10d
   145da:      	cmoveq	%r10, %r9
   145de:      	subq	%r9, %r8
   145e1:      	leaq	(%rsi,%r8), %r9
   145e5:      	movq	%rcx, %xmm0
   145ea:      	movq	0x18(%rsp), %rcx
   145ef:      	addq	%rax, %rcx
   145f2:      	addq	%r8, %rax
   145f5:      	pxor	%xmm1, %xmm1
   145f9:      	xorl	%r10d, %r10d
   145fc:      	nopl	(%rax)
   14600:      	movzwl	0x1(%rsi,%r10), %r11d
   14606:      	movzwl	0x3(%rsi,%r10), %ebx
   1460c:      	xorw	%r11w, -0x2(%rcx,%r10)
   14612:      	xorw	%bx, (%rcx,%r10)
   14617:      	psubq	%xmm2, %xmm0
   1461b:      	psubq	%xmm2, %xmm1
   1461f:      	addq	$0x4, %r10
   14623:      	cmpq	%r10, %r8
   14626:      	jne	0x14600 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x1d0>
   14628:      	paddq	%xmm0, %xmm1
   1462c:      	pshufd	$0xee, %xmm1, %xmm0     # xmm0 = xmm1[2,3,2,3]
   14631:      	paddq	%xmm1, %xmm0
   14635:      	movq	%xmm0, %rcx
   1463a:      	movq	%xmm0, (%rdi)
   1463e:      	jmp	0x14650 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x220>
   14640:      	movq	%rsi, %r9
   14643:      	jmp	0x14650 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x220>
   14645:      	movq	%rsi, %r9
   14648:      	movq	0x8(%rsp), %r15
   1464d:      	nopl	(%rax)
   14650:      	movq	(%rsp), %r11
   14654:      	incq	%rcx
   14657:      	incq	%r9
   1465a:      	movq	%r9, %rsi
   1465d:      	movq	%rcx, (%rdi)
   14660:      	cmpq	$0xf, %rax
   14664:      	je	0x14690 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x260>
   14666:      	nopw	%cs:(%rax,%rax)
   14670:      	cmpq	%rdx, %rsi
   14673:      	je	0x14690 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x260>
   14675:      	movzbl	(%rsi), %r8d
   14679:      	xorb	%r8b, (%rbp,%rax)
   1467e:      	incq	%rcx
   14681:      	incq	%rsi
   14684:      	incq	%rax
   14687:      	movq	%rcx, (%rdi)
   1468a:      	cmpq	$0xf, %rax
   1468e:      	jne	0x14670 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x240>
   14690:      	movq	%rcx, %rax
   14693:      	cmpq	$0x10, %rax
   14697:      	jne	0x14510 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0xe0>
   1469d:      	cmpq	$-0x1, %r11
   146a1:      	je	0x146b4 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x284>
   146a3:      	jmp	0x144a4 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x74>
   146a8:      	cmpq	$0xf, %rax
   146ac:      	jbe	0x14522 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0xf2>
   146b2:      	jmp	0x14693 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x263>
   146b4:      	movb	$0x4, %al
   146b6:      	jmp	0x146c3 <brynja_crypto::ghash::Ghash::update::h89449bbc90cd1f7c+0x293>
   146b8:      	movq	0x20(%rsp), %rax
   146bd:      	movq	%rax, 0x8(%rdi)
   146c1:      	movb	$0x7, %al
   146c3:      	addq	$0x38, %rsp
   146c7:      	popq	%rbx
   146c8:      	popq	%r12
   146ca:      	popq	%r13
   146cc:      	popq	%r14
   146ce:      	popq	%r15
   146d0:      	popq	%rbp
   146d1:      	retq
   146d2:      	int3
   146d3:      	int3
   146d4:      	int3
   146d5:      	int3
   146d6:      	int3
   146d7:      	int3
   146d8:      	int3
   146d9:      	int3
   146da:      	int3
   146db:      	int3
   146dc:      	int3
   146dd:      	int3
   146de:      	int3
   146df:      	int3
0000000000014750 <brynja_crypto_cpu::ghash_pclmul::multiply::h8afef9e1d4b7828f>:
   14750:      	pushq	%r14
   14752:      	pushq	%rbx
   14753:      	bswapq	%rsi
   14756:      	movq	%rsi, %rax
   14759:      	shrq	$0x4, %rax
   1475d:      	movabsq	$0xf0f0f0f0f0f0f0f, %r9 # imm = 0xF0F0F0F0F0F0F0F
   14767:      	andq	%r9, %rax
   1476a:      	andq	%r9, %rsi
   1476d:      	shlq	$0x4, %rsi
   14771:      	orq	%rax, %rsi
   14774:      	movabsq	$0x3333333333333333, %r8 # imm = 0x3333333333333333
   1477e:      	movq	%rsi, %rax
   14781:      	andq	%r8, %rax
   14784:      	shrq	$0x2, %rsi
   14788:      	andq	%r8, %rsi
   1478b:      	leaq	(%rsi,%rax,4), %rax
   1478f:      	movabsq	$0x5555555555555555, %rsi # imm = 0x5555555555555555
   14799:      	movq	%rax, %r10
   1479c:      	andq	%rsi, %r10
   1479f:      	shrq	%rax
   147a2:      	andq	%rsi, %rax
   147a5:      	leaq	(%rax,%r10,2), %rax
   147a9:      	bswapq	%rdi
   147ac:      	movq	%rdi, %r10
   147af:      	shrq	$0x4, %r10
   147b3:      	andq	%r9, %r10
   147b6:      	andq	%r9, %rdi
   147b9:      	shlq	$0x4, %rdi
   147bd:      	orq	%r10, %rdi
   147c0:      	movq	%rdi, %r10
   147c3:      	andq	%r8, %r10
   147c6:      	shrq	$0x2, %rdi
   147ca:      	andq	%r8, %rdi
   147cd:      	leaq	(%rdi,%r10,4), %rdi
   147d1:      	movq	%rdi, %r10
   147d4:      	andq	%rsi, %r10
   147d7:      	shrq	%rdi
   147da:      	andq	%rsi, %rdi
   147dd:      	leaq	(%rdi,%r10,2), %rdi
   147e1:      	bswapq	%rcx
   147e4:      	movq	%rcx, %r10
   147e7:      	shrq	$0x4, %r10
   147eb:      	andq	%r9, %r10
   147ee:      	andq	%r9, %rcx
   147f1:      	shlq	$0x4, %rcx
   147f5:      	orq	%r10, %rcx
   147f8:      	movq	%rcx, %r10
   147fb:      	andq	%r8, %r10
   147fe:      	shrq	$0x2, %rcx
   14802:      	andq	%r8, %rcx
   14805:      	leaq	(%rcx,%r10,4), %rcx
   14809:      	movq	%rcx, %r10
   1480c:      	andq	%rsi, %r10
   1480f:      	shrq	%rcx
   14812:      	andq	%rsi, %rcx
   14815:      	leaq	(%rcx,%r10,2), %rcx
   14819:      	bswapq	%rdx
   1481c:      	movq	%rdx, %r10
   1481f:      	shrq	$0x4, %r10
   14823:      	andq	%r9, %r10
   14826:      	andq	%r9, %rdx
   14829:      	shlq	$0x4, %rdx
   1482d:      	orq	%r10, %rdx
   14830:      	movq	%rdx, %r10
   14833:      	andq	%r8, %r10
   14836:      	shrq	$0x2, %rdx
   1483a:      	andq	%r8, %rdx
   1483d:      	leaq	(%rdx,%r10,4), %rdx
   14841:      	movq	%rdx, %r10
   14844:      	andq	%rsi, %r10
   14847:      	shrq	%rdx
   1484a:      	andq	%rsi, %rdx
   1484d:      	leaq	(%rdx,%r10,2), %rdx
   14851:      	movq	%rdi, %xmm0
   14856:      	movq	%rax, %xmm1
   1485b:      	punpcklqdq	%xmm0, %xmm1    # xmm1 = xmm1[0],xmm0[0]
   1485f:      	movq	%rdx, %xmm0
   14864:      	movq	%rcx, %xmm2
   14869:      	punpcklqdq	%xmm0, %xmm2    # xmm2 = xmm2[0],xmm0[0]
   1486d:      	movdqa	%xmm1, %xmm0
   14871:      	pclmulqdq	$0x0, %xmm2, %xmm0
   14877:      	movq	%xmm0, %rax
   1487c:      	pshufd	$0xee, %xmm0, %xmm0     # xmm0 = xmm0[2,3,2,3]
   14881:      	movq	%xmm0, %rcx
   14886:      	movdqa	%xmm1, %xmm0
   1488a:      	pclmulqdq	$0x11, %xmm2, %xmm0
   14890:      	pshufd	$0xee, %xmm0, %xmm3     # xmm3 = xmm0[2,3,2,3]
   14895:      	movq	%xmm3, %rdx
   1489a:      	movq	%xmm0, %rdi
   1489f:      	movdqa	%xmm1, %xmm0
   148a3:      	pclmulqdq	$0x1, %xmm2, %xmm0
   148a9:      	pclmulqdq	$0x1, %xmm1, %xmm2
   148af:      	pxor	%xmm0, %xmm2
   148b3:      	movq	%xmm2, %r11
   148b8:      	xorq	%rcx, %r11
   148bb:      	pshufd	$0xee, %xmm2, %xmm0     # xmm0 = xmm2[2,3,2,3]
   148c0:      	movq	%xmm0, %rcx
   148c5:      	xorq	%rdi, %rcx
   148c8:      	movq	%rdx, %rbx
   148cb:      	shldq	$0x1, %rcx, %rbx
   148d0:      	movq	%rdx, %r10
   148d3:      	movq	%rdx, %r14
   148d6:      	shldq	$0x2, %rcx, %r14
   148db:      	xorq	%r11, %rbx
   148de:      	movq	%rdx, %rdi
   148e1:      	shldq	$0x7, %rcx, %rdi
   148e6:      	movq	%rdx, %r11
   148e9:      	xorq	%r14, %rdi
   148ec:      	xorq	%rbx, %rdi
   148ef:      	xorq	%rdx, %rdi
   148f2:      	shrq	$0x3f, %rdx
   148f6:      	shrq	$0x3e, %r10
   148fa:      	xorq	%rdx, %r10
   148fd:      	shrq	$0x39, %r11
   14901:      	xorq	%r10, %r11
   14904:      	leaq	(%rcx,%rcx), %rdx
   14908:      	leaq	(,%rcx,4), %r10
   14910:      	xorq	%rdx, %r10
   14913:      	movq	%rcx, %rdx
   14916:      	shlq	$0x7, %rdx
   1491a:      	xorq	%r10, %rdx
   1491d:      	leal	(%r11,%r11), %r10d
   14921:      	xorq	%rax, %r10
   14924:      	leal	(,%r11,4), %eax
   1492c:      	xorq	%r11, %rdx
   1492f:      	shll	$0x7, %r11d
   14933:      	xorq	%rax, %r11
   14936:      	xorq	%r10, %r11
   14939:      	xorq	%r11, %rdx
   1493c:      	xorq	%rcx, %rdx
   1493f:      	bswapq	%rdi
   14942:      	movq	%rdi, %rax
   14945:      	shrq	$0x4, %rax
   14949:      	andq	%r9, %rax
   1494c:      	andq	%r9, %rdi
   1494f:      	shlq	$0x4, %rdi
   14953:      	orq	%rax, %rdi
   14956:      	movq	%rdi, %rax
   14959:      	andq	%r8, %rax
   1495c:      	shrq	$0x2, %rdi
   14960:      	andq	%r8, %rdi
   14963:      	leaq	(%rdi,%rax,4), %rax
   14967:      	movq	%rax, %rcx
   1496a:      	andq	%rsi, %rcx
   1496d:      	shrq	%rax
   14970:      	andq	%rsi, %rax
   14973:      	leaq	(%rax,%rcx,2), %rax
   14977:      	bswapq	%rdx
   1497a:      	movq	%rdx, %rcx
   1497d:      	shrq	$0x4, %rcx
   14981:      	andq	%r9, %rcx
   14984:      	andq	%r9, %rdx
   14987:      	shlq	$0x4, %rdx
   1498b:      	orq	%rcx, %rdx
   1498e:      	movq	%rdx, %rcx
   14991:      	andq	%r8, %rcx
   14994:      	shrq	$0x2, %rdx
   14998:      	andq	%r8, %rdx
   1499b:      	leaq	(%rdx,%rcx,4), %rcx
   1499f:      	movq	%rcx, %rdx
   149a2:      	andq	%rsi, %rdx
   149a5:      	shrq	%rcx
   149a8:      	andq	%rsi, %rcx
   149ab:      	leaq	(%rcx,%rdx,2), %rdx
   149af:      	popq	%rbx
   149b0:      	popq	%r14
   149b2:      	retq
