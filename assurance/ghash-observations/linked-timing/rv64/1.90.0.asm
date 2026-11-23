000000000001667e <brynja_ghash_timing::timed::hdf5b9f118c845fcb>:
   1667e:      	addi	sp, sp, -0xc0
   16680:      	sd	ra, 0xb8(sp)
   16682:      	sd	s0, 0xb0(sp)
   16684:      	sd	s1, 0xa8(sp)
   16686:      	sd	s2, 0xa0(sp)
   16688:      	sd	s3, 0x98(sp)
   1668a:      	sd	s4, 0x90(sp)
   1668c:      	sd	zero, 0x8(sp)
   1668e:      	sd	zero, 0x10(sp)
   16690:      	sd	zero, 0x18(sp)
   16692:      	sd	zero, 0x20(sp)
   16694:      	sd	a0, 0x78(sp)
   16696:      	addi	a0, sp, 0x78
   16698:      	ld	a4, 0x78(sp)
   1669a:      	mv	s0, a1
   1669c:      	addi	a0, sp, 0x28
   1669e:      	addi	a2, sp, 0x8
   166a0:      	li	a3, 0x100
   166a4:      	mv	a1, a4
   166a6:      	auipc	ra, 0x2
   166aa:      	jalr	-0x5c8(ra) <brynja_crypto::ghash::Ghash::new::h841d53a3994d4ffa>
   166ae:      	auipc	ra, 0x31
   166b2:      	jalr	0x70e(ra) <std::sys::pal::unix::time::Timespec::now::h8c12d60e9bacf26c>
   166b6:      	mv	s2, a0
   166b8:      	li	s4, 0x10
   166ba:      	addi	a0, sp, 0x78
   166bc:      	sd	s0, 0x78(sp)
   166be:      	sd	s4, 0x80(sp)
   166c0:      	ld	a3, 0x78(sp)
   166c2:      	ld	a2, 0x80(sp)
   166c4:      	mv	s3, a1
   166c6:      	addi	a0, sp, 0x28
   166c8:      	mv	a1, a3
   166ca:      	auipc	ra, 0x2
   166ce:      	jalr	-0x23c(ra) <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d>
   166d2:      	zext.b	a1, a0
   166d6:      	li	s1, 0x7
   166d8:      	bne	a1, s1, 0x16924 <brynja_ghash_timing::timed::hdf5b9f118c845fcb+0x2a6>
   166dc:      	sd	s0, 0x78(sp)
   166de:      	sd	s4, 0x80(sp)
   166e0:      	addi	a0, sp, 0x78
   166e2:      	ld	a1, 0x78(sp)
   166e4:      	ld	a2, 0x80(sp)
   166e6:      	addi	a0, sp, 0x28
   166e8:      	auipc	ra, 0x2
   166ec:      	jalr	-0x25a(ra) <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d>
   166f0:      	zext.b	a1, a0
   166f4:      	bne	a1, s1, 0x16924 <brynja_ghash_timing::timed::hdf5b9f118c845fcb+0x2a6>
   166f8:      	li	s4, 0x10
   166fa:      	addi	a0, sp, 0x78
   166fc:      	sd	s0, 0x78(sp)
   166fe:      	sd	s4, 0x80(sp)
   16700:      	ld	a1, 0x78(sp)
   16702:      	ld	a2, 0x80(sp)
   16704:      	addi	a0, sp, 0x28
   16706:      	auipc	ra, 0x2
   1670a:      	jalr	-0x278(ra) <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d>
   1670e:      	zext.b	a1, a0
   16712:      	li	s1, 0x7
   16714:      	bne	a1, s1, 0x16924 <brynja_ghash_timing::timed::hdf5b9f118c845fcb+0x2a6>
   16718:      	sd	s0, 0x78(sp)
   1671a:      	sd	s4, 0x80(sp)
   1671c:      	addi	a0, sp, 0x78
   1671e:      	ld	a1, 0x78(sp)
   16720:      	ld	a2, 0x80(sp)
   16722:      	addi	a0, sp, 0x28
   16724:      	auipc	ra, 0x2
   16728:      	jalr	-0x296(ra) <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d>
   1672c:      	zext.b	a1, a0
   16730:      	bne	a1, s1, 0x16924 <brynja_ghash_timing::timed::hdf5b9f118c845fcb+0x2a6>
   16734:      	li	s4, 0x10
   16736:      	addi	a0, sp, 0x78
   16738:      	sd	s0, 0x78(sp)
   1673a:      	sd	s4, 0x80(sp)
   1673c:      	ld	a1, 0x78(sp)
   1673e:      	ld	a2, 0x80(sp)
   16740:      	addi	a0, sp, 0x28
   16742:      	auipc	ra, 0x2
   16746:      	jalr	-0x2b4(ra) <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d>
   1674a:      	zext.b	a1, a0
   1674e:      	li	s1, 0x7
   16750:      	bne	a1, s1, 0x16924 <brynja_ghash_timing::timed::hdf5b9f118c845fcb+0x2a6>
   16754:      	sd	s0, 0x78(sp)
   16756:      	sd	s4, 0x80(sp)
   16758:      	addi	a0, sp, 0x78
   1675a:      	ld	a1, 0x78(sp)
   1675c:      	ld	a2, 0x80(sp)
   1675e:      	addi	a0, sp, 0x28
   16760:      	auipc	ra, 0x2
   16764:      	jalr	-0x2d2(ra) <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d>
   16768:      	zext.b	a1, a0
   1676c:      	bne	a1, s1, 0x16924 <brynja_ghash_timing::timed::hdf5b9f118c845fcb+0x2a6>
   16770:      	li	s4, 0x10
   16772:      	addi	a0, sp, 0x78
   16774:      	sd	s0, 0x78(sp)
   16776:      	sd	s4, 0x80(sp)
   16778:      	ld	a1, 0x78(sp)
   1677a:      	ld	a2, 0x80(sp)
   1677c:      	addi	a0, sp, 0x28
   1677e:      	auipc	ra, 0x2
   16782:      	jalr	-0x2f0(ra) <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d>
   16786:      	zext.b	a1, a0
   1678a:      	li	s1, 0x7
   1678c:      	bne	a1, s1, 0x16924 <brynja_ghash_timing::timed::hdf5b9f118c845fcb+0x2a6>
   16790:      	sd	s0, 0x78(sp)
   16792:      	sd	s4, 0x80(sp)
   16794:      	addi	a0, sp, 0x78
   16796:      	ld	a1, 0x78(sp)
   16798:      	ld	a2, 0x80(sp)
   1679a:      	addi	a0, sp, 0x28
   1679c:      	auipc	ra, 0x2
   167a0:      	jalr	-0x30e(ra) <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d>
   167a4:      	zext.b	a1, a0
   167a8:      	bne	a1, s1, 0x16924 <brynja_ghash_timing::timed::hdf5b9f118c845fcb+0x2a6>
   167ac:      	li	s4, 0x10
   167ae:      	addi	a0, sp, 0x78
   167b0:      	sd	s0, 0x78(sp)
   167b2:      	sd	s4, 0x80(sp)
   167b4:      	ld	a1, 0x78(sp)
   167b6:      	ld	a2, 0x80(sp)
   167b8:      	addi	a0, sp, 0x28
   167ba:      	auipc	ra, 0x2
   167be:      	jalr	-0x32c(ra) <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d>
   167c2:      	zext.b	a1, a0
   167c6:      	li	s1, 0x7
   167c8:      	bne	a1, s1, 0x16924 <brynja_ghash_timing::timed::hdf5b9f118c845fcb+0x2a6>
   167cc:      	sd	s0, 0x78(sp)
   167ce:      	sd	s4, 0x80(sp)
   167d0:      	addi	a0, sp, 0x78
   167d2:      	ld	a1, 0x78(sp)
   167d4:      	ld	a2, 0x80(sp)
   167d6:      	addi	a0, sp, 0x28
   167d8:      	auipc	ra, 0x2
   167dc:      	jalr	-0x34a(ra) <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d>
   167e0:      	zext.b	a1, a0
   167e4:      	bne	a1, s1, 0x16924 <brynja_ghash_timing::timed::hdf5b9f118c845fcb+0x2a6>
   167e8:      	li	s4, 0x10
   167ea:      	addi	a0, sp, 0x78
   167ec:      	sd	s0, 0x78(sp)
   167ee:      	sd	s4, 0x80(sp)
   167f0:      	ld	a1, 0x78(sp)
   167f2:      	ld	a2, 0x80(sp)
   167f4:      	addi	a0, sp, 0x28
   167f6:      	auipc	ra, 0x2
   167fa:      	jalr	-0x368(ra) <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d>
   167fe:      	zext.b	a1, a0
   16802:      	li	s1, 0x7
   16804:      	bne	a1, s1, 0x16924 <brynja_ghash_timing::timed::hdf5b9f118c845fcb+0x2a6>
   16808:      	sd	s0, 0x78(sp)
   1680a:      	sd	s4, 0x80(sp)
   1680c:      	addi	a0, sp, 0x78
   1680e:      	ld	a1, 0x78(sp)
   16810:      	ld	a2, 0x80(sp)
   16812:      	addi	a0, sp, 0x28
   16814:      	auipc	ra, 0x2
   16818:      	jalr	-0x386(ra) <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d>
   1681c:      	zext.b	a1, a0
   16820:      	bne	a1, s1, 0x16924 <brynja_ghash_timing::timed::hdf5b9f118c845fcb+0x2a6>
   16824:      	li	s4, 0x10
   16826:      	addi	a0, sp, 0x78
   16828:      	sd	s0, 0x78(sp)
   1682a:      	sd	s4, 0x80(sp)
   1682c:      	ld	a1, 0x78(sp)
   1682e:      	ld	a2, 0x80(sp)
   16830:      	addi	a0, sp, 0x28
   16832:      	auipc	ra, 0x2
   16836:      	jalr	-0x3a4(ra) <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d>
   1683a:      	zext.b	a1, a0
   1683e:      	li	s1, 0x7
   16840:      	bne	a1, s1, 0x16924 <brynja_ghash_timing::timed::hdf5b9f118c845fcb+0x2a6>
   16844:      	sd	s0, 0x78(sp)
   16846:      	sd	s4, 0x80(sp)
   16848:      	addi	a0, sp, 0x78
   1684a:      	ld	a1, 0x78(sp)
   1684c:      	ld	a2, 0x80(sp)
   1684e:      	addi	a0, sp, 0x28
   16850:      	auipc	ra, 0x2
   16854:      	jalr	-0x3c2(ra) <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d>
   16858:      	zext.b	a1, a0
   1685c:      	bne	a1, s1, 0x16924 <brynja_ghash_timing::timed::hdf5b9f118c845fcb+0x2a6>
   16860:      	li	s4, 0x10
   16862:      	addi	a0, sp, 0x78
   16864:      	sd	s0, 0x78(sp)
   16866:      	sd	s4, 0x80(sp)
   16868:      	ld	a1, 0x78(sp)
   1686a:      	ld	a2, 0x80(sp)
   1686c:      	addi	a0, sp, 0x28
   1686e:      	auipc	ra, 0x2
   16872:      	jalr	-0x3e0(ra) <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d>
   16876:      	zext.b	a1, a0
   1687a:      	li	s1, 0x7
   1687c:      	bne	a1, s1, 0x16924 <brynja_ghash_timing::timed::hdf5b9f118c845fcb+0x2a6>
   16880:      	sd	s0, 0x78(sp)
   16882:      	sd	s4, 0x80(sp)
   16884:      	addi	a0, sp, 0x78
   16886:      	ld	a1, 0x78(sp)
   16888:      	ld	a2, 0x80(sp)
   1688a:      	addi	a0, sp, 0x28
   1688c:      	auipc	ra, 0x2
   16890:      	jalr	-0x3fe(ra) <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d>
   16894:      	zext.b	a1, a0
   16898:      	bne	a1, s1, 0x16924 <brynja_ghash_timing::timed::hdf5b9f118c845fcb+0x2a6>
   1689c:      	addi	a0, sp, 0x78
   1689e:      	addi	a1, sp, 0x28
   168a0:      	addi	a2, sp, 0x18
   168a2:      	auipc	ra, 0x2
   168a6:      	jalr	0xc8(ra) <brynja_crypto::ghash::Ghash::finish::h8d53af7c6b84f8a6>
   168aa:      	lbu	a0, 0x78(sp)
   168ae:      	bnez	a0, 0x1694e <brynja_ghash_timing::timed::hdf5b9f118c845fcb+0x2d0>
   168b0:      	ld	a0, 0x80(sp)
   168b2:      	ld	a1, 0x88(sp)
   168b4:      	seqz	a2, a0
   168b8:      	add	a3, a0, a2
   168bc:      	addi	a2, a2, -0x1
   168be:      	and	a2, a2, a1
   168c0:      	sd	a3, 0x78(sp)
   168c2:      	sd	a2, 0x80(sp)
   168c4:      	addi	a2, sp, 0x78
   168c6:      	beqz	a0, 0x168d0 <brynja_ghash_timing::timed::hdf5b9f118c845fcb+0x252>
   168c8:      	auipc	ra, 0x2
   168cc:      	jalr	-0x7fc(ra) <brynja_core::secret_memory_volatile::zeroize_region_volatile::h6ce5149abf096f8e>
   168d0:      	auipc	ra, 0x31
   168d4:      	jalr	0x4ec(ra) <std::sys::pal::unix::time::Timespec::now::h8c12d60e9bacf26c>
   168d8:      	sd	a0, 0x58(sp)
   168da:      	sw	a1, 0x60(sp)
   168dc:      	sd	s2, 0x68(sp)
   168de:      	sw	s3, 0x70(sp)
   168e0:      	addi	a0, sp, 0x78
   168e2:      	addi	a1, sp, 0x58
   168e4:      	addi	a2, sp, 0x68
   168e6:      	auipc	ra, 0x32
   168ea:      	jalr	-0x41c(ra) <std::sys::pal::unix::time::Timespec::sub_timespec::h0e5d3e7ced81245e>
   168ee:      	ld	a0, 0x78(sp)
   168f0:      	ld	a1, 0x80(sp)
   168f2:      	lwu	a2, 0x88(sp)
   168f6:      	lui	a3, 0x3b9ad
   168fa:      	addiw	a3, a3, -0x600
   168fe:      	mulhu	a4, a1, a3
   16902:      	mul	a1, a1, a3
   16906:      	addi	a0, a0, -0x1
   16908:      	add	a2, a2, a1
   1690a:      	sltu	a1, a2, a1
   1690e:      	add	a1, a1, a4
   16910:      	and	a1, a1, a0
   16912:      	and	a0, a0, a2
   16914:      	ld	ra, 0xb8(sp)
   16916:      	ld	s0, 0xb0(sp)
   16918:      	ld	s1, 0xa8(sp)
   1691a:      	ld	s2, 0xa0(sp)
   1691c:      	ld	s3, 0x98(sp)
   1691e:      	ld	s4, 0x90(sp)
   16920:      	addi	sp, sp, 0xc0
   16922:      	ret
   16924:      	sb	a0, 0x78(sp)
   16928:      	auipc	a0, 0x88
   1692c:      	auipc	a2, 0xc1
   16930:      	auipc	a4, 0xc1
   16934:      	li	a1, 0x2b
   16938:      	addi	a0, a0, -0x4ed
   1693c:      	addi	a3, a2, -0x254
   16940:      	addi	a4, a4, -0x1c0
   16944:      	addi	a2, sp, 0x78
   16946:      	auipc	ra, 0xffffa
   1694a:      	jalr	0x176(ra) <core::result::unwrap_failed::h68e834ce9e0a6701>
   1694e:      	lbu	a0, 0x79(sp)
   16952:      	sb	a0, 0x68(sp)
   16956:      	auipc	a0, 0x88
   1695a:      	auipc	a2, 0xc1
   1695e:      	auipc	a4, 0xc1
   16962:      	li	a1, 0x2b
   16966:      	addi	a0, a0, -0x51b
   1696a:      	addi	a3, a2, -0x282
   1696e:      	addi	a4, a4, -0x206
   16972:      	addi	a2, sp, 0x68
   16974:      	auipc	ra, 0xffffa
   16978:      	jalr	0x148(ra) <core::result::unwrap_failed::h68e834ce9e0a6701>
000000000001848e <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d>:
   1848e:      	mv	a3, a0
   18490:      	lbu	a4, 0x28(a0)
   18494:      	li	a5, 0x2
   18496:      	li	a0, 0x4
   18498:      	bne	a4, a5, 0x184a6 <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d+0x18>
   1849c:      	ld	a6, 0x8(a3)
   184a0:      	bgeu	a6, a2, 0x184a8 <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d+0x1a>
   184a4:      	li	a0, 0x5
   184a6:      	ret
   184a8:      	addi	sp, sp, -0xb0
   184aa:      	sd	ra, 0xa8(sp)
   184ac:      	sd	s0, 0xa0(sp)
   184ae:      	sd	s1, 0x98(sp)
   184b0:      	sd	s2, 0x90(sp)
   184b2:      	sd	s3, 0x88(sp)
   184b4:      	sd	s4, 0x80(sp)
   184b6:      	sd	s5, 0x78(sp)
   184b8:      	sd	s6, 0x70(sp)
   184ba:      	sd	s7, 0x68(sp)
   184bc:      	sd	s8, 0x60(sp)
   184be:      	sd	s9, 0x58(sp)
   184c0:      	sd	s10, 0x50(sp)
   184c2:      	sd	s11, 0x48(sp)
   184c4:      	beqz	a2, 0x18944 <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d+0x4b6>
   184c8:      	add	t0, a1, a2
   184cc:      	ld	a4, 0x0(a3)
   184ce:      	ld	s4, 0x10(a3)
   184d2:      	ld	t1, 0x18(a3)
   184d6:      	ld	a7, 0x20(a3)
   184da:      	li	t3, 0x10
   184dc:      	lui	t2, 0xf0f1
   184e0:      	lui	s0, 0x33333
   184e4:      	lui	s1, 0x55555
   184e8:      	addiw	t5, t2, -0xf1
   184ec:      	addiw	a5, s0, 0x333
   184f0:      	sd	a5, 0x38(sp)
   184f2:      	addiw	a5, s1, 0x555
   184f6:      	sd	a5, 0x30(sp)
   184f8:      	slli	s1, t5, 0x20
   184fc:      	add	ra, t5, s1
   18500:      	addi	t2, t1, 0x1
   18504:      	mv	s5, a4
   18506:      	j	0x188e4 <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d+0x456>
   18508:      	li	a4, 0x0
   1850a:      	li	s5, 0x0
   1850c:      	sd	t2, 0x18(sp)
   1850e:      	lbu	t2, 0x8(s4)
   18512:      	lbu	t3, 0x9(s4)
   18516:      	lbu	s9, 0xa(s4)
   1851a:      	lbu	s0, 0xb(s4)
   1851e:      	lbu	t4, 0xc(s4)
   18522:      	lbu	t6, 0xd(s4)
   18526:      	lbu	s2, 0xe(s4)
   1852a:      	lbu	s3, 0xf(s4)
   1852e:      	lbu	s7, 0x0(s4)
   18532:      	lbu	s8, 0x1(s4)
   18536:      	lbu	s6, 0x2(s4)
   1853a:      	lbu	a5, 0x3(s4)
   1853e:      	lbu	s10, 0x4(s4)
   18542:      	lbu	s11, 0x5(s4)
   18546:      	sd	ra, 0x20(sp)
   18548:      	lbu	ra, 0x6(s4)
   1854c:      	sd	s4, 0x40(sp)
   1854e:      	ld	s1, 0x40(sp)
   18550:      	lbu	s4, 0x7(s1)
   18554:      	slli	t3, t3, 0x8
   18556:      	slli	s9, s9, 0x10
   18558:      	slli	s0, s0, 0x18
   1855a:      	or	s1, t3, t2
   1855e:      	sd	s1, 0x0(sp)
   18560:      	or	t3, s0, s9
   18564:      	lbu	t2, 0x8(t1)
   18568:      	lbu	s9, 0x9(t1)
   1856c:      	sd	a6, 0x28(sp)
   1856e:      	lbu	a6, 0xa(t1)
   18572:      	lbu	t5, 0xb(t1)
   18576:      	slli	t6, t6, 0x8
   18578:      	slli	s2, s2, 0x10
   1857a:      	slli	s3, s3, 0x18
   1857c:      	slli	s8, s8, 0x8
   1857e:      	slli	s1, s6, 0x10
   18582:      	slli	a5, a5, 0x18
   18584:      	or	t6, t6, t4
   18588:      	or	s3, s3, s2
   1858c:      	or	s0, s8, s7
   18590:      	sd	s0, 0x10(sp)
   18592:      	or	a5, a5, s1
   18594:      	sd	a5, 0x8(sp)
   18596:      	lbu	t4, 0xc(t1)
   1859a:      	lbu	s2, 0xd(t1)
   1859e:      	lbu	s1, 0xe(t1)
   185a2:      	lbu	a5, 0xf(t1)
   185a6:      	slli	s11, s11, 0x8
   185a8:      	slli	ra, ra, 0x10
   185aa:      	slli	s4, s4, 0x18
   185ac:      	slli	s9, s9, 0x8
   185ae:      	slli	s8, a6, 0x10
   185b2:      	slli	t5, t5, 0x18
   185b4:      	or	a6, s11, s10
   185b8:      	or	s7, s4, ra
   185bc:      	or	s4, s9, t2
   185c0:      	or	s8, t5, s8
   185c4:      	lbu	t2, 0x0(t1)
   185c8:      	lbu	t5, 0x1(t1)
   185cc:      	lbu	s9, 0x2(t1)
   185d0:      	lbu	s10, 0x3(t1)
   185d4:      	slli	s2, s2, 0x8
   185d6:      	slli	s1, s1, 0x10
   185d8:      	slli	a5, a5, 0x18
   185da:      	slli	t5, t5, 0x8
   185dc:      	slli	ra, s9, 0x10
   185e0:      	slli	s10, s10, 0x18
   185e2:      	or	s9, s2, t4
   185e6:      	or	s11, a5, s1
   185ea:      	or	t5, t5, t2
   185ee:      	lbu	t2, 0x4(t1)
   185f2:      	lbu	t4, 0x5(t1)
   185f6:      	or	ra, s10, ra
   185fa:      	lbu	s1, 0x6(t1)
   185fe:      	lbu	a5, 0x7(t1)
   18602:      	slli	t4, t4, 0x8
   18604:      	or	s2, t4, t2
   18608:      	slli	s1, s1, 0x10
   1860a:      	slli	a5, a5, 0x18
   1860c:      	or	t2, a5, s1
   18610:      	ld	a5, 0x0(sp)
   18612:      	or	s10, t3, a5
   18616:      	ld	a5, 0x38(sp)
   18618:      	slli	t4, a5, 0x20
   1861c:      	or	t3, s3, t6
   18620:      	ld	s0, 0x30(sp)
   18622:      	slli	t6, s0, 0x20
   18626:      	sd	zero, 0x0(a3)
   1862a:      	sd	a7, 0x20(a3)
   1862e:      	add	t4, t4, a5
   18630:      	add	t6, t6, s0
   18632:      	ld	a5, 0x10(sp)
   18634:      	ld	s0, 0x8(sp)
   18636:      	or	s3, s0, a5
   1863a:      	or	s1, s7, a6
   1863e:      	or	a6, s8, s4
   18642:      	or	a5, s11, s9
   18646:      	or	t5, ra, t5
   1864a:      	ld	ra, 0x20(sp)
   1864c:      	or	s0, t2, s2
   18650:      	slli	t3, t3, 0x20
   18652:      	slli	s1, s1, 0x20
   18654:      	slli	t2, a5, 0x20
   18658:      	slli	s2, s0, 0x20
   1865c:      	or	t3, t3, s10
   18660:      	or	s1, s1, s3
   18664:      	or	s0, t2, a6
   18668:      	or	a5, s2, t5
   1866c:      	srli	a6, a5, 0x4
   18670:      	and	a5, a5, ra
   18674:      	srli	t2, s0, 0x4
   18678:      	and	s3, s0, ra
   1867c:      	srli	t5, s1, 0x4
   18680:      	and	s4, s1, ra
   18684:      	srli	s2, t3, 0x4
   18688:      	and	t3, t3, ra
   1868c:      	and	a6, a6, ra
   18690:      	slli	s7, a5, 0x4
   18694:      	and	t2, t2, ra
   18698:      	slli	s3, s3, 0x4
   1869a:      	and	t5, t5, ra
   1869e:      	slli	s4, s4, 0x4
   186a0:      	and	s2, s2, ra
   186a4:      	slli	t3, t3, 0x4
   186a6:      	or	s0, a6, s7
   186aa:      	or	s1, t2, s3
   186ae:      	or	a5, t5, s4
   186b2:      	or	a6, s2, t3
   186b6:      	srli	t2, s0, 0x2
   186ba:      	and	s0, s0, t4
   186be:      	srli	t3, s1, 0x2
   186c2:      	and	s1, s1, t4
   186c6:      	srli	t5, a5, 0x2
   186ca:      	and	s3, a5, t4
   186ce:      	srli	s2, a6, 0x2
   186d2:      	and	a6, a6, t4
   186d6:      	and	t2, t2, t4
   186da:      	slli	s4, s0, 0x2
   186de:      	and	t3, t3, t4
   186e2:      	slli	s1, s1, 0x2
   186e4:      	and	t5, t5, t4
   186e8:      	slli	s3, s3, 0x2
   186ea:      	and	s2, s2, t4
   186ee:      	slli	a6, a6, 0x2
   186f0:      	or	a5, t2, s4
   186f4:      	or	s1, t3, s1
   186f8:      	or	s0, t5, s3
   186fc:      	or	a6, s2, a6
   18700:      	srli	t2, a5, 0x1
   18704:      	and	a5, a5, t6
   18708:      	srli	t3, s1, 0x1
   1870c:      	and	s1, s1, t6
   18710:      	srli	t5, s0, 0x1
   18714:      	and	s3, s0, t6
   18718:      	srli	s2, a6, 0x1
   1871c:      	and	a6, a6, t6
   18720:      	and	t2, t2, t6
   18724:      	slli	s4, a5, 0x1
   18728:      	and	t3, t3, t6
   1872c:      	slli	s1, s1, 0x1
   1872e:      	and	t5, t5, t6
   18732:      	slli	s3, s3, 0x1
   18734:      	and	s2, s2, t6
   18738:      	slli	a6, a6, 0x1
   1873a:      	or	a5, t2, s4
   1873e:      	or	t2, t3, s1
   18742:      	or	s0, t5, s3
   18746:      	or	s1, s2, a6
   1874a:      	clmul	a6, a5, s0
   1874e:      	clmulh	t3, a5, s0
   18752:      	xor	t5, a5, t2
   18756:      	xor	s0, s0, s1
   18758:      	clmul	a5, t2, s1
   1875c:      	clmulh	s1, t2, s1
   18760:      	clmul	t2, t5, s0
   18764:      	clmulh	t5, t5, s0
   18768:      	xor	s8, a6, a5
   1876c:      	xor	s2, t3, s1
   18770:      	slli	s3, s1, 0x1
   18774:      	slli	s4, s1, 0x2
   18778:      	slli	s7, s1, 0x7
   1877c:      	srli	s9, s1, 0x3f
   18780:      	srli	s0, s1, 0x3e
   18784:      	srli	s10, s1, 0x39
   18788:      	xor	t3, t3, s1
   1878c:      	xor	t2, s8, t2
   18790:      	xor	s1, s2, t5
   18794:      	xor	s0, s9, s0
   18798:      	xor	a5, a5, s1
   1879a:      	xor	s1, s0, s10
   1879e:      	slli	t5, a5, 0x1
   187a2:      	srli	s0, a5, 0x3f
   187a6:      	srli	s2, a5, 0x3e
   187aa:      	slli	s8, a5, 0x2
   187ae:      	srli	s9, a5, 0x39
   187b2:      	slli	s10, a5, 0x7
   187b6:      	or	s3, s3, s0
   187ba:      	slli	s11, s1, 0x1
   187be:      	or	s2, s4, s2
   187c2:      	slli	s0, s1, 0x2
   187c6:      	xor	s4, s1, a5
   187ca:      	slli	s1, s1, 0x7
   187cc:      	or	s7, s7, s9
   187d0:      	xor	s0, s11, s0
   187d4:      	xor	s1, s1, s8
   187d8:      	xor	a5, t5, s10
   187dc:      	xor	t5, s0, s1
   187e0:      	xor	s1, t2, s2
   187e4:      	xor	s0, s3, s7
   187e8:      	xor	a5, a5, a6
   187ec:      	xor	s0, s0, s1
   187ee:      	xor	a5, t5, a5
   187f2:      	xor	s1, s0, t3
   187f6:      	xor	a5, a5, s4
   187fa:      	srli	s0, a5, 0x4
   187fe:      	and	a5, a5, ra
   18802:      	srli	a6, s1, 0x4
   18806:      	and	s1, s1, ra
   1880a:      	and	t2, s0, ra
   1880e:      	slli	a5, a5, 0x4
   18810:      	and	s0, a6, ra
   18814:      	slli	s1, s1, 0x4
   18816:      	or	a5, t2, a5
   1881a:      	or	s0, s0, s1
   1881c:      	srli	s1, a5, 0x2
   18820:      	and	a5, a5, t4
   18824:      	srli	a6, s0, 0x2
   18828:      	and	t2, s0, t4
   1882c:      	and	s1, s1, t4
   18830:      	slli	a5, a5, 0x2
   18832:      	and	s0, a6, t4
   18836:      	slli	t2, t2, 0x2
   18838:      	or	a5, a5, s1
   1883a:      	or	s1, s0, t2
   1883e:      	srli	s0, a5, 0x1
   18842:      	and	a5, a5, t6
   18846:      	srli	a6, s1, 0x1
   1884a:      	and	s1, s1, t6
   1884e:      	and	t2, s0, t6
   18852:      	slli	a5, a5, 0x1
   18854:      	and	s0, a6, t6
   18858:      	slli	s1, s1, 0x1
   1885a:      	or	a5, t2, a5
   1885e:      	or	s0, s0, s1
   18860:      	srli	a6, s0, 0x38
   18864:      	srli	t2, s0, 0x30
   18868:      	srli	t3, s0, 0x28
   1886c:      	srli	s1, s0, 0x20
   18870:      	srli	t4, s0, 0x18
   18874:      	srli	t5, s0, 0x10
   18878:      	srli	t6, s0, 0x8
   1887c:      	srli	s2, a5, 0x38
   18880:      	srli	s3, a5, 0x30
   18884:      	srli	s4, a5, 0x28
   18888:      	srli	s7, a5, 0x20
   1888c:      	srli	s8, a5, 0x18
   18890:      	srli	s9, a5, 0x10
   18894:      	srli	s10, a5, 0x8
   18898:      	sb	s1, 0xc(t1)
   1889c:      	sb	t3, 0xd(t1)
   188a0:      	li	t3, 0x10
   188a2:      	sb	t2, 0xe(t1)
   188a6:      	ld	t2, 0x18(sp)
   188a8:      	sb	a6, 0xf(t1)
   188ac:      	ld	a6, 0x28(sp)
   188ae:      	sb	s0, 0x8(t1)
   188b2:      	sb	t6, 0x9(t1)
   188b6:      	sb	t5, 0xa(t1)
   188ba:      	sb	t4, 0xb(t1)
   188be:      	sb	s7, 0x4(t1)
   188c2:      	sb	s4, 0x5(t1)
   188c6:      	ld	s4, 0x40(sp)
   188c8:      	sb	s3, 0x6(t1)
   188cc:      	sb	s2, 0x7(t1)
   188d0:      	sb	a5, 0x0(t1)
   188d4:      	sb	s10, 0x1(t1)
   188d8:      	sb	s9, 0x2(t1)
   188dc:      	sb	s8, 0x3(t1)
   188e0:      	beq	t0, a1, 0x18944 <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d+0x4b6>
   188e4:      	bnez	s5, 0x1893c <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d+0x4ae>
   188e8:      	beq	a1, t0, 0x18944 <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d+0x4b6>
   188ec:      	add	s0, t1, s5
   188f0:      	lbu	s1, 0x0(a1)
   188f4:      	lbu	a5, 0x0(s0)
   188f8:      	addi	a4, a4, 0x1
   188fa:      	addi	a1, a1, 0x1
   188fc:      	xor	a5, a5, s1
   188fe:      	add	s1, t2, s5
   18902:      	sb	a5, 0x0(s0)
   18906:      	addi	s5, s5, -0xf
   18908:      	sd	a4, 0x0(a3)
   1890a:      	beqz	s5, 0x1892e <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d+0x4a0>
   1890e:      	beq	a1, t0, 0x1892e <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d+0x4a0>
   18912:      	lbu	a5, 0x0(a1)
   18916:      	lbu	s0, 0x0(s1)
   1891a:      	addi	a4, a4, 0x1
   1891c:      	addi	a1, a1, 0x1
   1891e:      	xor	a5, a5, s0
   18920:      	sb	a5, 0x0(s1)
   18924:      	addi	s1, s1, 0x1
   18926:      	addi	s5, s5, 0x1
   18928:      	sd	a4, 0x0(a3)
   1892a:      	bnez	s5, 0x1890e <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d+0x480>
   1892e:      	mv	s5, a4
   18930:      	bne	s5, t3, 0x188e0 <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d+0x452>
   18934:      	addi	a7, a7, 0x1
   18936:      	beqz	a7, 0x1894c <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d+0x4be>
   1893a:      	j	0x18508 <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d+0x7a>
   1893c:      	li	a5, 0xf
   1893e:      	bgeu	a5, s5, 0x188e8 <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d+0x45a>
   18942:      	j	0x18930 <brynja_crypto::ghash::Ghash::update::h6228bf3e1c6e9c7d+0x4a2>
   18944:      	sub	a0, a6, a2
   18948:      	sd	a0, 0x8(a3)
   1894a:      	li	a0, 0x7
   1894c:      	ld	ra, 0xa8(sp)
   1894e:      	ld	s0, 0xa0(sp)
   18950:      	ld	s1, 0x98(sp)
   18952:      	ld	s2, 0x90(sp)
   18954:      	ld	s3, 0x88(sp)
   18956:      	ld	s4, 0x80(sp)
   18958:      	ld	s5, 0x78(sp)
   1895a:      	ld	s6, 0x70(sp)
   1895c:      	ld	s7, 0x68(sp)
   1895e:      	ld	s8, 0x60(sp)
   18960:      	ld	s9, 0x58(sp)
   18962:      	ld	s10, 0x50(sp)
   18964:      	ld	s11, 0x48(sp)
   18966:      	addi	sp, sp, 0xb0
   18968:      	ret
