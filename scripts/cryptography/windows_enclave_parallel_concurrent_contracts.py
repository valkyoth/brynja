"""Remaining concurrent COFF instruction contracts; author review only.

Full bodies are independent of the population hashes. These are fixed-build
contracts, not a generic disassembler or whole-image qualification.
"""

CONTRACTS = {
    'finish_handler': {
        'name': "?dtor$55@?0?_RNvMs_NtCs2u1vj83u0E8_14parallel_waves25parallel_concurrent_wavesNtB4_5Waves6finish@4HA",
        'contract': "Actual dtor55 rebases the parent frame, drops the 18-byte suffix at parent+0x40 then invokes root Operation with complete=false from parent+0x60; no claim for OS exception dispatch.",
        'code': (
            '4889542410554157415641545657534883ec20488d6a70488d4dd0e800000000488b4df031d2e800000000904883c420'
            '5b5f5e415c415e415f5dc3'
        ),
        'branches': [
        ],
    },
    'leaf_entry': {
        'name': "PrivateWaveLeaf",
        'contract': "Reject generation0 and lane>=4; locked CAS atomically validates generation, OPEN, active and unclaimed bits before any pointer load. KAT creates local authority at rsp+0x20. Bound block1..1024, bits1..block*8 and nonnull input; lane*block+ceil(bits/8)<=published width before BitString/run. Success receipt follows successful Slot::run; all admitted ordinary returns release LIVE. No host pointer is accepted here.",
        'code': (
            '56574883ec784889d689ca85c90f94c04883fe040f93c108c1740731d2e90b01000041b80100000089f149d3e041b900'
            '10000049d3e1488b05000000004189d241bb1100000049d3e331d20f1f4400004889c148c1e9204439d10f85cd000000'
            '89c181e1000002000f84bf0000004889c14c21c10f85b30000004889c14c21c90f84a70000004889c14c09d9f0480fb1'
            '0d0000000075b9488d0500000000488b3cf04885ff746fe800000000b10228c148c744242002000000884c2428c64424'
            '2904488d05000000004c8b0cf0488b0500000000488b0d00000000488b15000000004c8d80fffbffff4981f800fcffff'
            '410f92c04c8d14c5000000004d8d59ff4d39d3410f93c24885d2410f94c34508c34508d3742131d2b81000000089f148'
            'd3e048f7d0f0482105000000004889d04883c4785f5ec3480fafc64d89c849c1e8034589ca4183e2074983fa014983d8'
            'ff4d8d14004939ca77bc4801c241fec94180e10741fec1488d4c2430e80000000048837c243000749dc5fc10442430c5'
            'fc11442450488d5424204c8d4424504889f9c5f877e8000000003cff0f8574ffffffb80001000089f148d3e0f0480905'
            '00000000ba01000000e95affffff'
        ),
        'branches': [
            (25, '74', 34),
            (29, 'e9', 301),
            (90, '0f85', 301),
            (104, '0f84', 301),
            (116, '0f85', 301),
            (128, '0f84', 301),
            (149, '75', 80),
            (165, '74', 278),
            (276, '74', 311),
            (344, '77', 278),
            (375, '74', 278),
            (412, '0f85', 278),
            (441, 'e9', 280),
        ],
    },
    'operation_glue': {
        'name': "_RINvNtCs8xEFJqa6dYS_4core3ptr9drop_glueNtNtCs2u1vj83u0E8_14parallel_waves25parallel_concurrent_waves9OperationEBF_",
        'contract': "Disarmed only by low complete bit. Otherwise drop installed state at owner+0x400 unless tag=-1, set empty, clear all1024 output bytes, set phaseDead3.",
        'code': (
            '564883ec20f6c20175374889ce83b9b0070000ff740c488d8e00040000e80000000048c786b0070000ffffffffba0004'
            '00004889f1e800000000c68620080000034883c4205ec3'
        ),
        'branches': [
            (8, '75', 65),
            (20, '74', 34),
        ],
    },
    'panic_bridge': {
        'name': "_RNvCs1njKG4L9aB3_7___rustc17rust_begin_unwind",
        'contract': "PrivateWaveAbort then UD2: terminating path, never counted as returning cleanup or exception recovery.",
        'code': (
            '4883ec28e8000000000f0b'
        ),
        'branches': [
        ],
    },
    'authority': {
        'name': "_RNvCs2u1vj83u0E8_14parallel_waves15check_authority",
        'contract': "Only kernel4 and health1 accepted; generation identity is additionally checked by the borrowed engine/session rather than by this shallow predicate.",
        'code': (
            'b00580790904750b807908010f94c0f6d80c05c3'
        ),
        'branches': [
            (6, '75', 19),
        ],
    },
    'plan': {
        'name': "_RNvMCs2u1vj83u0E8_14parallel_wavesNtB2_4Plan3new",
        'contract': "Specialized call accepts identity1..4, block1..1024 and computes ceil(input_bits/(block*8)), rejecting leaves>4. Writes custom/output lengths0, cancellation0 and claimed0; caller then stores claimed1. Not a general public Plan ABI.",
        'code': (
            '565753488d42ff41b30141ba010000004883f8037733498d80fffbffff40b602483dfffbffff76234889d74a8d1cc500'
            '0000004c89c84809d848c1e82074174c89c831d248f7f3eb1431f6428834114488195b5f5ec34489c831d2f7f34883fa'
            '014883d8ff4883f80477e0488979084c8941104c894918c5f857c0c5f811412048894130c641380041ba3900000031f6'
            '4531dbebb6'
        ),
        'branches': [
            (20, '77', 73),
            (38, '76', 75),
            (61, '74', 86),
            (71, 'eb', 93),
            (105, '77', 75),
            (147, 'eb', 75),
        ],
    },
    'right_encode': {
        'name': "_RNvMNtCs2u1vj83u0E8_14parallel_waves24parallel_stream_encodingNtB2_20SecretEncodedInteger5right",
        'contract': "Clear17-byte suffix and length before construction. Width1..16, big-endian payload followed by width and stored total width+1<=17; bounded two-byte loop; shift>=128 terminates via panic bridge, not a clearing return.",
        'code': (
            '415741565657534883ec204c89c74889d34989ce488d7111ba11000000e80000000041bf01000000ba010000004889f1'
            'e8000000004881fb000100004889f84883d800726031c9b8ffff00004989d84989f94889fa66662e0f1f840000000000'
            '4d89c24d89c84d0fa4d0384989cf48c1ea0848ffc14c39d041ba000000004d19ca4989d172dab0024881f9fe0000000f'
            '87ac000000b0014883f90f0f87a00000004983c70247883c3e498d57ff4a8d04fdf8ffffff4531c949b8feffffffffff'
            'ff1f66666666662e0f1f840000000000483d8000000073754989da89c1490fadfa4989fb49d3eba8404d0f44da47881c'
            '0e4c39ca743f4c89c94c31c14c01f948c1e1034883f97f77444983f91074304989da490fadfa4989fb49d3ebf6c1404d'
            '0f44da47885c0e014983c1024883c0f04d39cf759b418d47018806b0ffeb02b0014883c4205b5f5e415e415fc3e80000'
            '00000f0b'
        ),
        'branches': [
            (67, '72', 165),
            (132, '72', 96),
            (143, '0f87', 321),
            (155, '0f87', 321),
            (214, '73', 333),
            (244, '74', 309),
            (263, '77', 333),
            (269, '74', 319),
            (307, '75', 208),
            (317, 'eb', 321),
        ],
    },
    'bits': {
        'name': "_RNvMNtCs58M5yX2Qwr5_16brynja_hash_sha310bit_stringNtB2_16Fips202BitString3new",
        'contract': "Specialized ABI supplies last0..8 and bounded slice lengths. Reject empty/nonempty-last mismatch, checked bit-length carry and noncanonical tail via secret predicate before returning borrowed descriptor. Not an unrestricted last-byte validator.",
        'code': (
            '4156565755534883ec204d85c00f94c04584c9410f95c24130c274534d85c0745b4a8d04c5f8ffffff410fb6f14801c6'
            '72664180f9087346b0ff4889cf4489c9d2e04a8d0c0248ffc94889d389c24489cd4d89c6e8000000004889da4d89f041'
            '89e94889f984c07515c6410801eb04c641080048c70100000000eb1131f64889114c89410848897110448849184883c4'
            '205b5d5f5e415ec3c6410802ebd5'
        ),
        'branches': [
            (26, '74', 111),
            (31, '74', 124),
            (48, '72', 152),
            (54, '73', 126),
            (103, '75', 126),
            (109, 'eb', 115),
            (122, 'eb', 141),
            (156, 'eb', 115),
        ],
    },
    'custom': {
        'name': "_RNvMs1_Cs8LdeoEVKasr_14parallel_inputNtB5_10InputFrame6custom",
        'contract': "Require Ready and Some(request); ceil(custom_bits/8)<=1024; borrow only frame+0xc0, preserve exact last-bit count and reject nonzero unused bits. No pointer to host data is returned.",
        'code': (
            '415741565657534883ec2080bac8140000010f859c000000f602010f8493000000488b42204889c748c1ef034189c041'
            '83e0074983f8014883dfff4881ff010400000f83830000004881c2c0000000448d40ff4180e00741fec031db4885c041'
            '0fb6f00f44f3743b488d04fdf8ffffff400fb6de4801c372584080fe077724b0ff4989ce89f1d2e0488d0c3a48ffc949'
            '89d789c2e8000000004c89fa4c89f184c0742e488911488979084889591040887118eb0bc641080148c7010000000048'
            '83c4205b5f5e415e415fc3c6410800ebe7c6410803ebe1'
        ),
        'branches': [
            (18, '0f85', 180),
            (27, '0f84', 180),
            (66, '0f83', 203),
            (102, '74', 163),
            (119, '72', 209),
            (125, '77', 163),
            (161, '74', 209),
            (178, 'eb', 191),
            (207, 'eb', 184),
            (213, 'eb', 184),
        ],
    },
    'state_update': {
        'name': "_RNvMs2_CscBEH4D3OuJh_22sha3_accelerated_stateNtB5_5State6update",
        'contract': "Same machine code and references as sequential AVX2; current LLVM length range is narrowed to0..255. Permit, generation and state-phase checks precede absorption. Error clears owned engine/prefix and poisons state.",
        'code': (
            '56574883ec2840b70783b9b0030000020f84c20000004889ce40b70780b9c203000001755280be5b03000000754980be'
            '5a030000007540488b86400200000fb6480885c9742983f9017529488b0840b705483b8e48020000751d0fb6400940b7'
            '01b92c0000000fa3c1737931ffeb0840b703eb0340b704c6865b0300000148c7866802000000000000488d8e70020000'
            'e80000000080beaa030000ff742c488d8ea8030000ba01000000e800000000c686a903000000c5f857c0c5fc29866003'
            '0000c5fc298680030000c686aa030000ffc686c20300000389f84883c4285f5ec5f877c3b9030000000fa3c172894889'
            'f1e8000000003cff742589c7c6865b0300000148c7866802000000000000488d8e70020000e800000000e958ffffff40'
            'b7ffebb4'
        ),
        'branches': [
            (16, '0f84', 216),
            (35, '75', 119),
            (44, '75', 119),
            (53, '75', 119),
            (68, '74', 111),
            (73, '75', 116),
            (88, '75', 119),
            (105, '73', 228),
            (109, 'eb', 119),
            (114, 'eb', 119),
            (156, '74', 202),
            (236, '72', 119),
            (248, '74', 287),
            (282, 'e9', 119),
            (290, 'eb', 216),
        ],
    },
    'state_squeeze': {
        'name': "_RNvMs2_CscBEH4D3OuJh_22sha3_accelerated_stateNtB5_5State7squeeze",
        'contract': "Require squeezing phase, healthy matching authority and finalized engine. Read to separate zero-initialized1024-byte stack stage; shape/bounds or read/copy failure clears stage and poisons state. Mask partial final byte, copy exact length, clear stage and consume Core on success. Earlier caller copies/window retirement remain package08.",
        'code': (
            '415741565657534881ec2004000040b70783b9b0030000020f84c60000004889ce40b70780b9c203000002755680be5b'
            '03000000754d80be5a030000007444488b86400200000fb6480885c9742d83f901752d488b0840b705483b8e48020000'
            '75210fb6400940b701b92c0000000fa3c10f838100000031ffeb0840b703eb0340b704c6865b0300000148c786680200'
            '0000000000488d8e70020000e80000000080beaa030000ff742c488d8ea8030000ba01000000e800000000c686a90300'
            '0000c5f857c0c5fc298660030000c5fc298680030000c686aa030000ffc686c20300000389f84881c4200400005b5f5e'
            '415e415fc5f877c3b9030000000fa3c172814d85c074374889d3488d4c24204d89c641b80004000031d24c89cfe80000'
            '00004981fe010400000f93c04989ff4084ff0f94c140b70908c17429eb3d40b7094584c90f8539ffffff4d89cf4889d3'
            '488d4c24204d89c641b80004000031d2e800000000488d5424204889f14d89f0e80000000089c73cff7414488d4c2420'
            'ba00040000e800000000e9f4feffff4c89f2418d47ff3c0677254885d20f8482000000488d04144883c01fb1084428f9'
            'b2ffd2ea4889c1e8000000004c89f24c8d4424204889d94989d1e8000000003cff7417488d4c2420ba00040000e80000'
            '000040b70ae999feffff4889f1e800000000488d4c2420ba00040000e80000000083beb00300000274084889f1e80000'
            '000048c786b00300000200000040b7ffe9bffeffff40b709e94effffff'
        ),
        'branches': [
            (24, '0f84', 228),
            (43, '75', 131),
            (52, '75', 131),
            (61, '74', 131),
            (76, '74', 123),
            (81, '75', 128),
            (96, '75', 131),
            (113, '0f83', 248),
            (121, 'eb', 131),
            (126, 'eb', 131),
            (168, '74', 214),
            (256, '72', 131),
            (261, '74', 318),
            (314, '74', 357),
            (316, 'eb', 379),
            (324, '0f85', 131),
            (377, '74', 399),
            (394, 'e9', 131),
            (408, '77', 447),
            (413, '0f84', 549),
            (465, '74', 490),
            (485, 'e9', 131),
            (520, '74', 530),
            (544, 'e9', 228),
            (552, 'e9', 379),
        ],
    },
    'panic_fmt': {
        'name': "_RNvNtCs8xEFJqa6dYS_4core9panicking9panic_fmt",
        'contract': "Cold nounwind nonreturning bridge to rust_begin_unwind and UD2; debug metadata renumbering is not an ABI permission change.",
        'code': (
            '554883ec20488d6c2420e8000000000f0b'
        ),
        'branches': [
        ],
    },
    'panic_shift': {
        'name': "_RNvNtNtCs8xEFJqa6dYS_4core9panicking11panic_const24panic_const_shr_overflow",
        'contract': "Cold nounwind nonreturning bridge to panic_fmt and UD2; no successful cleanup claim.",
        'code': (
            '554883ec20488d6c2420e8000000000f0b'
        ),
        'branches': [
        ],
    },
    'core_drop': {
        'name': "_RNvXs0_CscBEH4D3OuJh_22sha3_accelerated_stateNtB5_4CoreNtNtNtCs8xEFJqa6dYS_4core3ops4drop4Drop4drop",
        'contract': "Poison engine, zero its counters, wipe memory and any pending prefix byte, zero prefix metadata, mark prefix absent and phaseDead. Full scratch lifetime also requires owning State/Core drop glue.",
        'code': (
            '564883ec204889cec6815b0300000148c78168020000000000004881c170020000e80000000080beaa030000ff742c48'
            '8d8ea8030000ba01000000e800000000c686a903000000c5f857c0c5fc298660030000c5fc298680030000c686aa0300'
            '00ffc686c2030000034883c4205ec5f877c3'
        ),
        'branches': [
            (45, '74', 91),
        ],
    },
    'input_guard': {
        'name': "_RNvXs_Cs8LdeoEVKasr_14parallel_inputNtB4_9OperationNtNtNtCs8xEFJqa6dYS_4core3ops4drop4Drop4drop",
        'contract': "Unless complete low bit is set, clear frame header128/custom1024/wave4096 at offsets0x40/0xc0/0x4c0, forget request, reset loaded bits and mark Dead2. No payload clearing implied for compiler copies outside this allocation.",
        'code': (
            '564883ec20f6c201754f488d4140ba800000004889ce4889c1e800000000488d8ec0000000ba00040000e80000000048'
            '8d8ec0040000ba00100000e80000000048c7060000000048c786c014000000000000c686c8140000024883c4205ec3'
        ),
        'branches': [
            (8, '75', 89),
        ],
    },
}

