0000000000010088 <brynja_ghash_timing::timed>:
   10088:      	addi	sp, sp, -0xc0
   1008a:      	sd	ra, 0xb8(sp)
   1008c:      	sd	s0, 0xb0(sp)
   1008e:      	sd	s1, 0xa8(sp)
   10090:      	sd	s2, 0xa0(sp)
   10092:      	sd	s3, 0x98(sp)
   10094:      	sd	s4, 0x90(sp)
   10096:      	sd	zero, 0x8(sp)
   10098:      	sd	zero, 0x10(sp)
   1009a:      	sd	zero, 0x18(sp)
   1009c:      	sd	zero, 0x20(sp)
   1009e:      	sd	a0, 0x78(sp)
   100a0:      	addi	a0, sp, 0x78
   100a2:      	ld	a4, 0x78(sp)
   100a4:      	mv	s2, a1
   100a6:      	addi	a0, sp, 0x28
   100a8:      	addi	a2, sp, 0x8
   100aa:      	li	a3, 0x100
   100ae:      	mv	a1, a4
   100b0:      	auipc	ra, 0x2
   100b4:      	jalr	0xfa(ra) <<brynja_crypto::ghash::Ghash>::new>
   100b8:      	auipc	ra, 0x2a
   100bc:      	jalr	-0x42a(ra) <<std::sys::pal::unix::time::Timespec>::now>
   100c0:      	mv	s0, a0
   100c2:      	li	s3, 0x10
   100c4:      	sd	s2, 0x78(sp)
   100c6:      	sd	s3, 0x80(sp)
   100c8:      	addi	a0, sp, 0x78
   100ca:      	ld	a3, 0x78(sp)
   100cc:      	ld	a2, 0x80(sp)
   100ce:      	mv	s1, a1
   100d0:      	addi	a0, sp, 0x28
   100d2:      	mv	a1, a3
   100d4:      	auipc	ra, 0x2
   100d8:      	jalr	0x4ee(ra) <<brynja_crypto::ghash::Ghash>::update>
   100dc:      	li	s4, 0xff
   100e0:      	zext.b	a1, a0
   100e4:      	bne	a1, s4, 0x10344 <brynja_ghash_timing::timed+0x2bc>
   100e8:      	sd	s2, 0x78(sp)
   100ea:      	sd	s3, 0x80(sp)
   100ec:      	addi	a0, sp, 0x78
   100ee:      	ld	a1, 0x78(sp)
   100f0:      	ld	a2, 0x80(sp)
   100f2:      	addi	a0, sp, 0x28
   100f4:      	auipc	ra, 0x2
   100f8:      	jalr	0x4ce(ra) <<brynja_crypto::ghash::Ghash>::update>
   100fc:      	zext.b	a1, a0
   10100:      	bne	a1, s4, 0x10344 <brynja_ghash_timing::timed+0x2bc>
   10104:      	li	s3, 0x10
   10106:      	sd	s2, 0x78(sp)
   10108:      	sd	s3, 0x80(sp)
   1010a:      	addi	a0, sp, 0x78
   1010c:      	ld	a1, 0x78(sp)
   1010e:      	ld	a2, 0x80(sp)
   10110:      	addi	a0, sp, 0x28
   10112:      	auipc	ra, 0x2
   10116:      	jalr	0x4b0(ra) <<brynja_crypto::ghash::Ghash>::update>
   1011a:      	li	s4, 0xff
   1011e:      	zext.b	a1, a0
   10122:      	bne	a1, s4, 0x10344 <brynja_ghash_timing::timed+0x2bc>
   10126:      	sd	s2, 0x78(sp)
   10128:      	sd	s3, 0x80(sp)
   1012a:      	addi	a0, sp, 0x78
   1012c:      	ld	a1, 0x78(sp)
   1012e:      	ld	a2, 0x80(sp)
   10130:      	addi	a0, sp, 0x28
   10132:      	auipc	ra, 0x2
   10136:      	jalr	0x490(ra) <<brynja_crypto::ghash::Ghash>::update>
   1013a:      	zext.b	a1, a0
   1013e:      	bne	a1, s4, 0x10344 <brynja_ghash_timing::timed+0x2bc>
   10142:      	li	s3, 0x10
   10144:      	sd	s2, 0x78(sp)
   10146:      	sd	s3, 0x80(sp)
   10148:      	addi	a0, sp, 0x78
   1014a:      	ld	a1, 0x78(sp)
   1014c:      	ld	a2, 0x80(sp)
   1014e:      	addi	a0, sp, 0x28
   10150:      	auipc	ra, 0x2
   10154:      	jalr	0x472(ra) <<brynja_crypto::ghash::Ghash>::update>
   10158:      	li	s4, 0xff
   1015c:      	zext.b	a1, a0
   10160:      	bne	a1, s4, 0x10344 <brynja_ghash_timing::timed+0x2bc>
   10164:      	sd	s2, 0x78(sp)
   10166:      	sd	s3, 0x80(sp)
   10168:      	addi	a0, sp, 0x78
   1016a:      	ld	a1, 0x78(sp)
   1016c:      	ld	a2, 0x80(sp)
   1016e:      	addi	a0, sp, 0x28
   10170:      	auipc	ra, 0x2
   10174:      	jalr	0x452(ra) <<brynja_crypto::ghash::Ghash>::update>
   10178:      	zext.b	a1, a0
   1017c:      	bne	a1, s4, 0x10344 <brynja_ghash_timing::timed+0x2bc>
   10180:      	li	s3, 0x10
   10182:      	sd	s2, 0x78(sp)
   10184:      	sd	s3, 0x80(sp)
   10186:      	addi	a0, sp, 0x78
   10188:      	ld	a1, 0x78(sp)
   1018a:      	ld	a2, 0x80(sp)
   1018c:      	addi	a0, sp, 0x28
   1018e:      	auipc	ra, 0x2
   10192:      	jalr	0x434(ra) <<brynja_crypto::ghash::Ghash>::update>
   10196:      	li	s4, 0xff
   1019a:      	zext.b	a1, a0
   1019e:      	bne	a1, s4, 0x10344 <brynja_ghash_timing::timed+0x2bc>
   101a2:      	sd	s2, 0x78(sp)
   101a4:      	sd	s3, 0x80(sp)
   101a6:      	addi	a0, sp, 0x78
   101a8:      	ld	a1, 0x78(sp)
   101aa:      	ld	a2, 0x80(sp)
   101ac:      	addi	a0, sp, 0x28
   101ae:      	auipc	ra, 0x2
   101b2:      	jalr	0x414(ra) <<brynja_crypto::ghash::Ghash>::update>
   101b6:      	zext.b	a1, a0
   101ba:      	bne	a1, s4, 0x10344 <brynja_ghash_timing::timed+0x2bc>
   101be:      	li	s3, 0x10
   101c0:      	sd	s2, 0x78(sp)
   101c2:      	sd	s3, 0x80(sp)
   101c4:      	addi	a0, sp, 0x78
   101c6:      	ld	a1, 0x78(sp)
   101c8:      	ld	a2, 0x80(sp)
   101ca:      	addi	a0, sp, 0x28
   101cc:      	auipc	ra, 0x2
   101d0:      	jalr	0x3f6(ra) <<brynja_crypto::ghash::Ghash>::update>
   101d4:      	li	s4, 0xff
   101d8:      	zext.b	a1, a0
   101dc:      	bne	a1, s4, 0x10344 <brynja_ghash_timing::timed+0x2bc>
   101e0:      	sd	s2, 0x78(sp)
   101e2:      	sd	s3, 0x80(sp)
   101e4:      	addi	a0, sp, 0x78
   101e6:      	ld	a1, 0x78(sp)
   101e8:      	ld	a2, 0x80(sp)
   101ea:      	addi	a0, sp, 0x28
   101ec:      	auipc	ra, 0x2
   101f0:      	jalr	0x3d6(ra) <<brynja_crypto::ghash::Ghash>::update>
   101f4:      	zext.b	a1, a0
   101f8:      	bne	a1, s4, 0x10344 <brynja_ghash_timing::timed+0x2bc>
   101fc:      	li	s3, 0x10
   101fe:      	sd	s2, 0x78(sp)
   10200:      	sd	s3, 0x80(sp)
   10202:      	addi	a0, sp, 0x78
   10204:      	ld	a1, 0x78(sp)
   10206:      	ld	a2, 0x80(sp)
   10208:      	addi	a0, sp, 0x28
   1020a:      	auipc	ra, 0x2
   1020e:      	jalr	0x3b8(ra) <<brynja_crypto::ghash::Ghash>::update>
   10212:      	li	s4, 0xff
   10216:      	zext.b	a1, a0
   1021a:      	bne	a1, s4, 0x10344 <brynja_ghash_timing::timed+0x2bc>
   1021e:      	sd	s2, 0x78(sp)
   10220:      	sd	s3, 0x80(sp)
   10222:      	addi	a0, sp, 0x78
   10224:      	ld	a1, 0x78(sp)
   10226:      	ld	a2, 0x80(sp)
   10228:      	addi	a0, sp, 0x28
   1022a:      	auipc	ra, 0x2
   1022e:      	jalr	0x398(ra) <<brynja_crypto::ghash::Ghash>::update>
   10232:      	zext.b	a1, a0
   10236:      	bne	a1, s4, 0x10344 <brynja_ghash_timing::timed+0x2bc>
   1023a:      	li	s3, 0x10
   1023c:      	sd	s2, 0x78(sp)
   1023e:      	sd	s3, 0x80(sp)
   10240:      	addi	a0, sp, 0x78
   10242:      	ld	a1, 0x78(sp)
   10244:      	ld	a2, 0x80(sp)
   10246:      	addi	a0, sp, 0x28
   10248:      	auipc	ra, 0x2
   1024c:      	jalr	0x37a(ra) <<brynja_crypto::ghash::Ghash>::update>
   10250:      	li	s4, 0xff
   10254:      	zext.b	a1, a0
   10258:      	bne	a1, s4, 0x10344 <brynja_ghash_timing::timed+0x2bc>
   1025c:      	sd	s2, 0x78(sp)
   1025e:      	sd	s3, 0x80(sp)
   10260:      	addi	a0, sp, 0x78
   10262:      	ld	a1, 0x78(sp)
   10264:      	ld	a2, 0x80(sp)
   10266:      	addi	a0, sp, 0x28
   10268:      	auipc	ra, 0x2
   1026c:      	jalr	0x35a(ra) <<brynja_crypto::ghash::Ghash>::update>
   10270:      	zext.b	a1, a0
   10274:      	bne	a1, s4, 0x10344 <brynja_ghash_timing::timed+0x2bc>
   10278:      	li	s3, 0x10
   1027a:      	sd	s2, 0x78(sp)
   1027c:      	sd	s3, 0x80(sp)
   1027e:      	addi	a0, sp, 0x78
   10280:      	ld	a1, 0x78(sp)
   10282:      	ld	a2, 0x80(sp)
   10284:      	addi	a0, sp, 0x28
   10286:      	auipc	ra, 0x2
   1028a:      	jalr	0x33c(ra) <<brynja_crypto::ghash::Ghash>::update>
   1028e:      	li	s4, 0xff
   10292:      	zext.b	a1, a0
   10296:      	bne	a1, s4, 0x10344 <brynja_ghash_timing::timed+0x2bc>
   1029a:      	sd	s2, 0x78(sp)
   1029c:      	sd	s3, 0x80(sp)
   1029e:      	addi	a0, sp, 0x78
   102a0:      	ld	a1, 0x78(sp)
   102a2:      	ld	a2, 0x80(sp)
   102a4:      	addi	a0, sp, 0x28
   102a6:      	auipc	ra, 0x2
   102aa:      	jalr	0x31c(ra) <<brynja_crypto::ghash::Ghash>::update>
   102ae:      	zext.b	a1, a0
   102b2:      	bne	a1, s4, 0x10344 <brynja_ghash_timing::timed+0x2bc>
   102b6:      	addi	a0, sp, 0x78
   102b8:      	addi	a1, sp, 0x28
   102ba:      	addi	a2, sp, 0x18
   102bc:      	auipc	ra, 0x2
   102c0:      	jalr	0x290(ra) <<brynja_crypto::ghash::Ghash>::finish>
   102c4:      	lbu	a0, 0x78(sp)
   102c8:      	bnez	a0, 0x1036e <brynja_ghash_timing::timed+0x2e6>
   102ca:      	ld	a0, 0x80(sp)
   102cc:      	ld	a1, 0x88(sp)
   102ce:      	seqz	a2, a0
   102d2:      	add	a3, a0, a2
   102d6:      	addi	a2, a2, -0x1
   102d8:      	and	a2, a2, a1
   102da:      	sd	a3, 0x78(sp)
   102dc:      	sd	a2, 0x80(sp)
   102de:      	addi	a2, sp, 0x78
   102e0:      	beqz	a0, 0x102ea <brynja_ghash_timing::timed+0x262>
   102e2:      	auipc	ra, 0x2
   102e6:      	jalr	-0x14c(ra) <brynja_core::secret_memory_volatile::zeroize_region_volatile>
   102ea:      	auipc	ra, 0x2a
   102ee:      	jalr	-0x65c(ra) <<std::sys::pal::unix::time::Timespec>::now>
   102f2:      	sd	a0, 0x58(sp)
   102f4:      	sw	a1, 0x60(sp)
   102f6:      	sd	s0, 0x68(sp)
   102f8:      	sw	s1, 0x70(sp)
   102fa:      	addi	a0, sp, 0x78
   102fc:      	addi	a1, sp, 0x58
   102fe:      	addi	a2, sp, 0x68
   10300:      	auipc	ra, 0x2a
   10304:      	jalr	-0x722(ra) <<std::sys::pal::unix::time::Timespec>::sub_timespec>
   10308:      	ld	a0, 0x80(sp)
   1030a:      	lui	a1, 0x3b9ad
   1030e:      	addi	a1, a1, -0x600
   10312:      	lwu	a2, 0x88(sp)
   10316:      	mul	a3, a0, a1
   1031a:      	mulhu	a0, a0, a1
   1031e:      	ld	a1, 0x78(sp)
   10320:      	add	a2, a2, a3
   10322:      	sltu	a3, a2, a3
   10326:      	add	a0, a0, a3
   10328:      	addi	a3, a1, -0x1
   1032c:      	and	a1, a3, a0
   10330:      	and	a0, a3, a2
   10334:      	ld	ra, 0xb8(sp)
   10336:      	ld	s0, 0xb0(sp)
   10338:      	ld	s1, 0xa8(sp)
   1033a:      	ld	s2, 0xa0(sp)
   1033c:      	ld	s3, 0x98(sp)
   1033e:      	ld	s4, 0x90(sp)
   10340:      	addi	sp, sp, 0xc0
   10342:      	ret
   10344:      	sb	a0, 0x68(sp)
   10348:      	auipc	a0, 0x83
   1034c:      	auipc	a1, 0xba
   10350:      	addi	a0, a0, -0x489
   10354:      	addi	a3, a1, -0x394
   10358:      	auipc	a4, 0xba
   1035c:      	addi	a4, a4, -0x3b8
   10360:      	li	a1, 0x2b
   10364:      	addi	a2, sp, 0x68
   10366:      	auipc	ra, 0xffffb
   1036a:      	jalr	-0x288(ra) <core::result::unwrap_failed>
   1036e:      	lbu	a0, 0x79(sp)
   10372:      	sb	a0, 0x68(sp)
   10376:      	auipc	a0, 0x83
   1037a:      	auipc	a1, 0xba
   1037e:      	addi	a0, a0, -0x4b7
   10382:      	addi	a3, a1, -0x3c2
   10386:      	auipc	a4, 0xba
   1038a:      	addi	a4, a4, -0x3fe
   1038e:      	li	a1, 0x2b
   10392:      	addi	a2, sp, 0x68
   10394:      	auipc	ra, 0xffffb
   10398:      	jalr	-0x2b6(ra) <core::result::unwrap_failed>
00000000000125c2 <<brynja_crypto::ghash::Ghash>::update>:
   125c2:      	mv	a3, a0
   125c4:      	lbu	a4, 0x28(a0)
   125c8:      	li	a5, 0x2
   125ca:      	li	a0, 0x4
   125cc:      	bne	a4, a5, 0x125d8 <<brynja_crypto::ghash::Ghash>::update+0x16>
   125d0:      	ld	a4, 0x8(a3)
   125d2:      	bgeu	a4, a2, 0x125da <<brynja_crypto::ghash::Ghash>::update+0x18>
   125d6:      	li	a0, 0x5
   125d8:      	ret
   125da:      	addi	sp, sp, -0x80
   125dc:      	sd	ra, 0x78(sp)
   125de:      	sd	s0, 0x70(sp)
   125e0:      	sd	s1, 0x68(sp)
   125e2:      	sd	s2, 0x60(sp)
   125e4:      	sd	s3, 0x58(sp)
   125e6:      	sd	s4, 0x50(sp)
   125e8:      	sd	s5, 0x48(sp)
   125ea:      	sd	s6, 0x40(sp)
   125ec:      	sd	s7, 0x38(sp)
   125ee:      	sd	s8, 0x30(sp)
   125f0:      	sd	s9, 0x28(sp)
   125f2:      	sd	s10, 0x20(sp)
   125f4:      	sd	s11, 0x18(sp)
   125f6:      	beqz	a2, 0x12a60 <<brynja_crypto::ghash::Ghash>::update+0x49e>
   125fa:      	add	a5, a1, a2
   125fe:      	ld	t1, 0x0(a3)
   12602:      	ld	a6, 0x18(a3)
   12606:      	ld	a7, 0x10(a3)
   1260a:      	ld	t0, 0x20(a3)
   1260e:      	li	t2, 0x10
   12610:      	lui	t3, 0xf0f1
   12614:      	addi	t3, t3, -0xf1
   12618:      	lui	t5, 0x33333
   1261c:      	addi	t4, a6, 0x1
   12620:      	lui	t6, 0x55555
   12624:      	addi	t5, t5, 0x333
   12628:      	addi	t6, t6, 0x555
   1262c:      	mv	s1, t1
   1262e:      	j	0x129fe <<brynja_crypto::ghash::Ghash>::update+0x43c>
   12630:      	li	t1, 0x0
   12632:      	li	s1, 0x0
   12634:      	lbu	s2, 0x9(a7)
   12638:      	lbu	s3, 0x8(a7)
   1263c:      	lbu	s4, 0xa(a7)
   12640:      	lbu	s5, 0xb(a7)
   12644:      	lbu	s6, 0xd(a7)
   12648:      	lbu	s7, 0xe(a7)
   1264c:      	lbu	s8, 0xf(a7)
   12650:      	lbu	s9, 0xc(a7)
   12654:      	slli	s2, s2, 0x8
   12656:      	or	s2, s2, s3
   1265a:      	slli	s4, s4, 0x10
   1265c:      	slli	s5, s5, 0x18
   1265e:      	slli	s6, s6, 0x8
   12660:      	slli	s7, s7, 0x10
   12662:      	slli	s8, s8, 0x18
   12664:      	or	s3, s6, s9
   12668:      	or	s6, s8, s7
   1266c:      	or	s4, s5, s4
   12670:      	or	s3, s6, s3
   12674:      	or	s2, s4, s2
   12678:      	slli	s3, s3, 0x20
   1267a:      	lbu	s4, 0x0(a7)
   1267e:      	lbu	s6, 0x1(a7)
   12682:      	lbu	s7, 0x2(a7)
   12686:      	lbu	s8, 0x3(a7)
   1268a:      	lbu	s9, 0x4(a7)
   1268e:      	lbu	s10, 0x5(a7)
   12692:      	lbu	s11, 0x6(a7)
   12696:      	lbu	ra, 0x7(a7)
   1269a:      	or	s5, s3, s2
   1269e:      	slli	s6, s6, 0x8
   126a0:      	or	s2, s6, s4
   126a4:      	slli	s7, s7, 0x10
   126a6:      	slli	s8, s8, 0x18
   126a8:      	slli	s10, s10, 0x8
   126aa:      	slli	s11, s11, 0x10
   126ac:      	slli	ra, ra, 0x18
   126ae:      	or	s3, s10, s9
   126b2:      	or	s4, ra, s11
   126b6:      	or	s6, s8, s7
   126ba:      	or	s3, s4, s3
   126be:      	or	s2, s6, s2
   126c2:      	slli	s3, s3, 0x20
   126c4:      	lbu	s4, 0x8(a6)
   126c8:      	lbu	s7, 0x9(a6)
   126cc:      	lbu	s8, 0xa(a6)
   126d0:      	lbu	s9, 0xb(a6)
   126d4:      	lbu	s10, 0xc(a6)
   126d8:      	lbu	s11, 0xd(a6)
   126dc:      	lbu	ra, 0xe(a6)
   126e0:      	lbu	s0, 0xf(a6)
   126e4:      	or	s6, s3, s2
   126e8:      	slli	s7, s7, 0x8
   126ea:      	or	s2, s7, s4
   126ee:      	slli	s8, s8, 0x10
   126f0:      	slli	s9, s9, 0x18
   126f2:      	slli	s11, s11, 0x8
   126f4:      	slli	ra, ra, 0x10
   126f6:      	slli	s0, s0, 0x18
   126f8:      	or	s3, s11, s10
   126fc:      	or	s0, s0, ra
   12700:      	or	s4, s9, s8
   12704:      	or	s0, s0, s3
   12708:      	or	s2, s4, s2
   1270c:      	slli	s0, s0, 0x20
   1270e:      	lbu	s3, 0x0(a6)
   12712:      	lbu	s4, 0x1(a6)
   12716:      	lbu	s7, 0x2(a6)
   1271a:      	lbu	s8, 0x3(a6)
   1271e:      	lbu	s9, 0x4(a6)
   12722:      	lbu	s10, 0x5(a6)
   12726:      	lbu	s11, 0x6(a6)
   1272a:      	lbu	ra, 0x7(a6)
   1272e:      	or	s0, s0, s2
   12732:      	slli	s4, s4, 0x8
   12734:      	or	s2, s4, s3
   12738:      	slli	s7, s7, 0x10
   1273a:      	slli	s8, s8, 0x18
   1273c:      	slli	s10, s10, 0x8
   1273e:      	slli	s11, s11, 0x10
   12740:      	slli	ra, ra, 0x18
   12742:      	or	s3, s10, s9
   12746:      	or	s4, ra, s11
   1274a:      	or	s7, s8, s7
   1274e:      	or	s3, s4, s3
   12752:      	or	s2, s7, s2
   12756:      	slli	s3, s3, 0x20
   12758:      	or	s3, s3, s2
   1275c:      	slli	s2, t3, 0x20
   12760:      	srli	s4, s3, 0x4
   12764:      	add	s2, s2, t3
   12766:      	and	s4, s4, s2
   1276a:      	and	s3, s3, s2
   1276e:      	slli	s3, s3, 0x4
   12770:      	slli	s7, t5, 0x20
   12774:      	or	s4, s4, s3
   12778:      	add	s3, t5, s7
   1277c:      	srli	s7, s4, 0x2
   12780:      	and	s4, s4, s3
   12784:      	and	s7, s7, s3
   12788:      	slli	s4, s4, 0x2
   1278a:      	or	s7, s7, s4
   1278e:      	slli	s4, t6, 0x20
   12792:      	srli	s8, s7, 0x1
   12796:      	add	s4, s4, t6
   12798:      	srli	s9, s0, 0x4
   1279c:      	and	s0, s0, s2
   127a0:      	and	s9, s9, s2
   127a4:      	slli	s0, s0, 0x4
   127a6:      	and	s8, s8, s4
   127aa:      	or	s0, s9, s0
   127ae:      	srli	s9, s0, 0x2
   127b2:      	and	s0, s0, s3
   127b6:      	and	s9, s9, s3
   127ba:      	slli	s0, s0, 0x2
   127bc:      	and	s7, s7, s4
   127c0:      	or	s0, s9, s0
   127c4:      	slli	s7, s7, 0x1
   127c6:      	srli	s9, s0, 0x1
   127ca:      	or	s7, s8, s7
   127ce:      	and	s8, s9, s4
   127d2:      	srli	s9, s6, 0x4
   127d6:      	and	s6, s6, s2
   127da:      	and	s9, s9, s2
   127de:      	slli	s6, s6, 0x4
   127e0:      	and	s0, s0, s4
   127e4:      	or	s6, s9, s6
   127e8:      	srli	s9, s6, 0x2
   127ec:      	and	s6, s6, s3
   127f0:      	and	s9, s9, s3
   127f4:      	slli	s6, s6, 0x2
   127f6:      	slli	s0, s0, 0x1
   127f8:      	or	s6, s9, s6
   127fc:      	or	s0, s8, s0
   12800:      	srli	s8, s6, 0x1
   12804:      	and	s8, s8, s4
   12808:      	and	s6, s6, s4
   1280c:      	srli	s9, s5, 0x4
   12810:      	and	s5, s5, s2
   12814:      	and	s9, s9, s2
   12818:      	slli	s5, s5, 0x4
   1281a:      	slli	s6, s6, 0x1
   1281c:      	or	s5, s9, s5
   12820:      	srli	s9, s5, 0x2
   12824:      	and	s5, s5, s3
   12828:      	and	s9, s9, s3
   1282c:      	slli	s5, s5, 0x2
   1282e:      	or	s6, s8, s6
   12832:      	or	s5, s9, s5
   12836:      	srli	s8, s5, 0x1
   1283a:      	and	s5, s5, s4
   1283e:      	and	s8, s8, s4
   12842:      	slli	s5, s5, 0x1
   12844:      	or	s5, s8, s5
   12848:      	clmul	s8, s7, s6
   1284c:      	clmulh	s9, s7, s6
   12850:      	clmul	s10, s0, s5
   12854:      	clmulh	s11, s0, s5
   12858:      	xor	s0, s7, s0
   1285c:      	xor	s5, s6, s5
   12860:      	clmul	s6, s0, s5
   12864:      	clmulh	s0, s0, s5
   12868:      	xor	s5, s9, s11
   1286c:      	xor	s7, s8, s10
   12870:      	xor	s0, s5, s0
   12874:      	xor	s6, s7, s6
   12878:      	xor	s0, s0, s10
   1287c:      	srli	s7, s0, 0x3f
   12880:      	slli	s9, s11, 0x1
   12884:      	slli	s10, s0, 0x1
   12888:      	or	s7, s9, s7
   1288c:      	srli	s9, s0, 0x3e
   12890:      	slli	ra, s11, 0x2
   12894:      	or	s9, ra, s9
   12898:      	slli	ra, s0, 0x2
   1289c:      	srli	t2, s11, 0x3f
   128a0:      	sd	t6, 0x8(sp)
   128a2:      	mv	t6, t4
   128a4:      	srli	t4, s11, 0x3e
   128a8:      	sd	t5, 0x10(sp)
   128aa:      	mv	t5, t3
   128ac:      	srli	t3, s0, 0x39
   128b0:      	xor	t2, t2, t4
   128b4:      	slli	t4, s11, 0x7
   128b8:      	srli	s11, s11, 0x39
   128bc:      	or	t3, t4, t3
   128c0:      	xor	t2, t2, s11
   128c4:      	slli	t4, t2, 0x1
   128c8:      	slli	s11, t2, 0x2
   128cc:      	xor	t4, t4, s11
   128d0:      	slli	s11, t2, 0x7
   128d4:      	xor	s11, s11, ra
   128d8:      	slli	ra, s0, 0x7
   128dc:      	xor	t4, t4, s11
   128e0:      	xor	s10, s10, ra
   128e4:      	xor	s6, s6, s9
   128e8:      	xor	s8, s10, s8
   128ec:      	xor	t4, t4, s8
   128f0:      	xor	t2, t2, s0
   128f4:      	xor	t3, s7, t3
   128f8:      	xor	t2, t4, t2
   128fc:      	srli	t4, t2, 0x4
   12900:      	and	t2, t2, s2
   12904:      	and	t4, t4, s2
   12908:      	slli	t2, t2, 0x4
   1290a:      	xor	t3, s6, t3
   1290e:      	or	t2, t4, t2
   12912:      	srli	t4, t2, 0x2
   12916:      	and	t2, t2, s3
   1291a:      	and	t4, t4, s3
   1291e:      	slli	t2, t2, 0x2
   12920:      	xor	s6, t3, s5
   12924:      	or	s5, t4, t2
   12928:      	srli	t2, s5, 0x1
   1292c:      	sd	zero, 0x0(a3)
   12930:      	sd	t0, 0x20(a3)
   12934:      	and	t2, t2, s4
   12938:      	srli	t3, s6, 0x4
   1293c:      	and	t4, s6, s2
   12940:      	and	t3, t3, s2
   12944:      	slli	t4, t4, 0x4
   12946:      	and	s0, s5, s4
   1294a:      	or	t3, t3, t4
   1294e:      	srli	t4, t3, 0x2
   12952:      	and	t3, t3, s3
   12956:      	and	t4, t4, s3
   1295a:      	slli	t3, t3, 0x2
   1295c:      	slli	s0, s0, 0x1
   1295e:      	or	t3, t4, t3
   12962:      	srli	t4, t3, 0x1
   12966:      	and	t3, t3, s4
   1296a:      	and	t4, t4, s4
   1296e:      	slli	t3, t3, 0x1
   12970:      	or	t2, t2, s0
   12974:      	or	t3, t4, t3
   12978:      	srli	t4, t3, 0x38
   1297c:      	srli	s0, t3, 0x30
   12980:      	srli	s2, t3, 0x28
   12984:      	srli	s3, t3, 0x20
   12988:      	sb	s3, 0xc(a6)
   1298c:      	sb	s2, 0xd(a6)
   12990:      	sb	s0, 0xe(a6)
   12994:      	sb	t4, 0xf(a6)
   12998:      	srli	t4, t3, 0x18
   1299c:      	srli	s0, t3, 0x10
   129a0:      	srli	s2, t3, 0x8
   129a4:      	sb	t3, 0x8(a6)
   129a8:      	sb	s2, 0x9(a6)
   129ac:      	sb	s0, 0xa(a6)
   129b0:      	sb	t4, 0xb(a6)
   129b4:      	srli	t3, t2, 0x38
   129b8:      	srli	t4, t2, 0x30
   129bc:      	srli	s0, t2, 0x20
   129c0:      	srli	s2, t2, 0x28
   129c4:      	sb	s0, 0x4(a6)
   129c8:      	sb	s2, 0x5(a6)
   129cc:      	sb	t4, 0x6(a6)
   129d0:      	sb	t3, 0x7(a6)
   129d4:      	srli	t3, t2, 0x18
   129d8:      	srli	t4, t2, 0x10
   129dc:      	srli	s0, t2, 0x8
   129e0:      	sb	t2, 0x0(a6)
   129e4:      	li	t2, 0x10
   129e6:      	sb	s0, 0x1(a6)
   129ea:      	sb	t4, 0x2(a6)
   129ee:      	mv	t4, t6
   129f0:      	ld	t6, 0x8(sp)
   129f2:      	sb	t3, 0x3(a6)
   129f6:      	mv	t3, t5
   129f8:      	ld	t5, 0x10(sp)
   129fa:      	beq	a5, a1, 0x12a60 <<brynja_crypto::ghash::Ghash>::update+0x49e>
   129fe:      	bnez	s1, 0x12a58 <<brynja_crypto::ghash::Ghash>::update+0x496>
   12a00:      	beq	a1, a5, 0x12a60 <<brynja_crypto::ghash::Ghash>::update+0x49e>
   12a04:      	add	s2, a6, s1
   12a08:      	lbu	s3, 0x0(a1)
   12a0c:      	lbu	s4, 0x0(s2)
   12a10:      	addi	t1, t1, 0x1
   12a12:      	xor	s3, s4, s3
   12a16:      	addi	a1, a1, 0x1
   12a18:      	sb	s3, 0x0(s2)
   12a1c:      	add	s2, t4, s1
   12a20:      	addi	s1, s1, -0xf
   12a22:      	sd	t1, 0x0(a3)
   12a26:      	beqz	s1, 0x12a4a <<brynja_crypto::ghash::Ghash>::update+0x488>
   12a28:      	beq	a1, a5, 0x12a4a <<brynja_crypto::ghash::Ghash>::update+0x488>
   12a2c:      	lbu	s3, 0x0(a1)
   12a30:      	lbu	s4, 0x0(s2)
   12a34:      	addi	t1, t1, 0x1
   12a36:      	xor	s3, s4, s3
   12a3a:      	addi	a1, a1, 0x1
   12a3c:      	sb	s3, 0x0(s2)
   12a40:      	addi	s2, s2, 0x1
   12a42:      	addi	s1, s1, 0x1
   12a44:      	sd	t1, 0x0(a3)
   12a48:      	bnez	s1, 0x12a28 <<brynja_crypto::ghash::Ghash>::update+0x466>
   12a4a:      	mv	s1, t1
   12a4c:      	bne	s1, t2, 0x129fa <<brynja_crypto::ghash::Ghash>::update+0x438>
   12a50:      	addi	t0, t0, 0x1
   12a52:      	beqz	t0, 0x12a68 <<brynja_crypto::ghash::Ghash>::update+0x4a6>
   12a56:      	j	0x12630 <<brynja_crypto::ghash::Ghash>::update+0x6e>
   12a58:      	li	s0, 0xf
   12a5a:      	bgeu	s0, s1, 0x12a00 <<brynja_crypto::ghash::Ghash>::update+0x43e>
   12a5e:      	j	0x12a4c <<brynja_crypto::ghash::Ghash>::update+0x48a>
   12a60:      	sub	a4, a4, a2
   12a62:      	sd	a4, 0x8(a3)
   12a64:      	li	a0, 0xff
   12a68:      	ld	ra, 0x78(sp)
   12a6a:      	ld	s0, 0x70(sp)
   12a6c:      	ld	s1, 0x68(sp)
   12a6e:      	ld	s2, 0x60(sp)
   12a70:      	ld	s3, 0x58(sp)
   12a72:      	ld	s4, 0x50(sp)
   12a74:      	ld	s5, 0x48(sp)
   12a76:      	ld	s6, 0x40(sp)
   12a78:      	ld	s7, 0x38(sp)
   12a7a:      	ld	s8, 0x30(sp)
   12a7c:      	ld	s9, 0x28(sp)
   12a7e:      	ld	s10, 0x20(sp)
   12a80:      	ld	s11, 0x18(sp)
   12a82:      	addi	sp, sp, 0x80
   12a84:      	ret
