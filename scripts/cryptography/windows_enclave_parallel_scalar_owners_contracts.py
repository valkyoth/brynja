"""Actual COFF instruction contracts for sequential ParallelHash scalar.

Not derived from the separately emitted listing. Population pins also bind
all references and ABI. These are conditional author-review contracts.
"""

CONTRACTS = {
    "begin": {
        'name': "_RNvMs0_Csh5jde4i55II_15parallel_streamNtB5_5Owner5begin",
        'contract': "Empty phase and exact next sequence; positive B/identity1..4; setup success before metadata/Custom publication; guard retains original Owner.",
        'code': (
            '4157415641554154565755534881ec180900004c89ce4c89c74989d04889ca48c7442420010000004c8d0d00000000488d4c2430e8000000'
            '000fb66c24384080fd02750b440fb6742430e91d010000488b5c2430488d8b70040000e800000000c6837004000000488d8be0080000ba10'
            '000000e800000000488d8bf0080000ba10000000e800000000488d8b00090000ba10000000e8000000000f57c00f2983100900004885f60f'
            '94c0488d4fff4883f9040f93c108c10f85a20000004c8b8c24880900004c8b8424800900004889b3100900004889bb18090000488d4c2430'
            '4889fae800000000440fb6642430440fb67424314180fcff74684c8bac2490090000488d5424324c8dbc24aa04000041b86e0400004c89f9'
            'e8000000004889d9e80000000044882344887301488d4b0241b86e0400004c89fae8000000004889bb280d00004889b3300d00004c89ab38'
            '0d0000c683500d00000141b6ffeb0d4531f64889d989eae8000000004489f04881c4180900005b5d5f5e415c415d415e415fc3'
        ),
        'branches': [
            (0x42, '75', 0x4f), (0x4a, 'e9', 0x16c), (0xb7, '0f85', 0x15f),
            (0xf8, '74', 0x162), (0x15d, 'eb', 0x16c),
        ],
    },
    "custom": {
        'name': "_RNvMs0_Csh5jde4i55II_15parallel_streamNtB5_5Owner6custom",
        'contract': "Custom phase; <=1024-byte budget charge; exact remaining prefix bits; failure quarantines; AVX2 empty chunk intentionally succeeds.",
        'code': (
            '41565657534883ec384c89c64989d04889ca48c7442420020000004c8d0d00000000488d4c2428e8000000000fb654243080fa0275070fb6'
            '5c2428eb6d488b4c2428488b4608b303483d0004000077554c8b81380d00004929c072494c8981380d00000fb60183f802741cb30283f801'
            '753389d74989ce4883c110b2014989f0e800000000eb1389d74989ce4883c110b2014989f0e800000000b3063cff89fa4c89f17411e80000'
            '000089d84883c4385b5f5e415ec3b3ffebf0'
        ),
        'branches': [
            (0x34, '75', 0x3d), (0x3b, 'eb', 0xaa), (0x4e, '77', 0xa5),
            (0x5a, '72', 0xa5), (0x69, '74', 0x87), (0x70, '75', 0xa5),
            (0x85, 'eb', 0x9a), (0xa3, '74', 0xb6), (0xb8, 'eb', 0xaa),
        ],
    },
    "update": {
        'name': "_RNvMs0_Csh5jde4i55II_15parallel_streamNtB5_5Owner6update",
        'contract': "Absorb phase; caller bounds<=1024; checked budget/u128 total; distinct leaf/root storage; failure quarantines.",
        'code': (
            '41565657534883ec384c89ce4c89c74989d04889ca48c7442420010000004c8d0d00000000488d4c2428e8000000000fb65c243080fb0275'
            '070fb6442428eb6b4c8b742428498b8e380d0000b0034829f1724a49898e380d0000488d14f5000000004d8b860809000049039600090000'
            '4983d0007227498d8e70040000498996000900004d8986080900004c89f24989f84989f1e8000000003cff74184c89f189da89c3e8000000'
            '0089d84883c4385b5f5e415ec3b0ffebf2'
        ),
        'branches': [
            (0x37, '75', 0x40), (0x3e, 'eb', 0xab), (0x51, '72', 0x9d),
            (0x74, '72', 0x9d), (0x9b, '74', 0xb5), (0xb7, 'eb', 0xab),
        ],
    },
    "squeeze": {
        'name': "_RNvMs0_Csh5jde4i55II_15parallel_streamNtB5_5Owner7squeeze",
        'contract': "Reader phase, <=1024 and nonterminal full bytes; disjoint root/output; terminal drop before Retained; shape publication only on success.",
        'code': (
            '4156565755534883ec404489ce4c89c74989d04889ca48c7442420010000004c8d0d00000000488d4c2430e8000000000fb654243880fa02'
            '750a0fb65c2430e9ba000000488b4c2430b3034881ff000400000f87a10000004885ff0f94c04084f6410f95c0b3044484c00f8589000000'
            '4885ff0f95c0448d46ff4180f808410f93c04484c0757280bc249000000000743389d5488d9120090000c6442420014989ce4989f84189f1'
            'e8000000003cff75414c89f34c89f1e80000000041c60600b005eb4c4885ff0f95c0c0e0034038c6752789d5488d9120090000c644242000'
            '4989ce4989f84189f1e8000000003cff741989c34c89f189eae80000000089d84883c4405b5d5f5e415ec3b0064c89f34889bb400d000040'
            '88b3510d00008883500d0000b3ffebd6'
        ),
        'branches': [
            (0x38, '75', 0x44), (0x3f, 'e9', 0xfe), (0x52, '0f87', 0xf9),
            (0x6a, '0f85', 0xf9), (0x85, '75', 0xf9), (0x8f, '74', 0xc4),
            (0xaf, '75', 0xf2), (0xc2, 'eb', 0x110), (0xd0, '75', 0xf9),
            (0xf0, '74', 0x10b), (0x126, 'eb', 0xfe),
        ],
    },
    "advance136": {
        'name': "_RNvMs_NtNtNtCs58M5yX2Qwr5_16brynja_hash_sha38hardened6cshake5setupINtB4_5SetupKj88_E7advanceBa_",
        'contract': "Zero remaining before transition; checked emitted count, pending-byte flush/wipe, modulo136 padding; exact expected total before Complete.",
        'code': (
            '415741565657534881ec300100004889ce488b4910b0ff480b4e18740f4881c4300100005b5f5e415e415fc30fb65642b10184d20f85c600'
            '0000488b56204c8b46284c8d7424204c89f1e8000000000fb784242001000031ff3d01010000bb01000000490f42de0f42f8807e41007430'
            '4885ff746d66662e0f1f8400000000004889f14889da41b008e8000000003cff0f85ca01000048ffc348ffcf75e2eb424c8b76084c8b3e49'
            '01ff4983d600b0010f82aa010000807e43010f859e010000488d4e444889da4989f8e80000000089c1b00184c90f85850100004c893e4c89'
            '7608488b4620488b4e2848894e1848894610c64642014809c80f94c1b201b0ff80fa010f94c284ca0f840fffffff807e4100488b1e4c8b76'
            '0874544883c3014983d600b0010f82f2feffff807e43010f8522010000488d4e44488d7e4041b8010000004889fae80000000089c1b00184'
            'c90f85c6feffffba010000004889f9e8000000004c89760848891ec64641004c89f0480fa4d83d4c89f148c1e9034801c14883d10048baf1'
            'f0f0f0f0f0f0f04889c848f7e248c1ea0489d0c1e00401d029c1c1e10389d883e0074809c80f848c0000000f57c00f298424b00000000f29'
            '8424a00000000f298424900000000f298424800000000f294424700f294424600f294424500f294424400f294424300f2944242048c78424'
            'c00000000000000041b8880000004929c04c01c34983d600b0010f8205feffff807e43017539488d4e44488d542420e80000000089c1b001'
            '84c90f85e5fdffff48891e4c89760848335e304c3376384909de750bc6464202b0ffe9c6fdffff31c0e9bffdffff31c0e9b8fdffff'
        ),
        'branches': [
            (0x1b, '74', 0x2c), (0x34, '0f85', 0x100), (0x6e, '74', 0xa0),
            (0x73, '74', 0xe2), (0x90, '0f85', 0x260), (0x9c, '75', 0x80),
            (0x9e, 'eb', 0xe2), (0xb0, '0f82', 0x260), (0xba, '0f85', 0x25e),
            (0xd5, '0f85', 0x260), (0x108, '0f84', 0x1d), (0x119, '74', 0x16f),
            (0x125, '0f82', 0x1d), (0x12f, '0f85', 0x257), (0x151, '0f85', 0x1d),
            (0x1ad, '0f84', 0x23f), (0x212, '0f82', 0x1d), (0x21c, '75', 0x257),
            (0x232, '0f85', 0x1d), (0x24a, '75', 0x257), (0x252, 'e9', 0x1d),
            (0x259, 'e9', 0x1d), (0x260, 'e9', 0x1d),
        ],
    },
    "advance168": {
        'name': "_RNvMs_NtNtNtCs58M5yX2Qwr5_16brynja_hash_sha38hardened6cshake5setupINtB4_5SetupKja8_E7advanceBa_",
        'contract': "Same prefix completion at168; external __umodti3 ABI assigned package08.",
        'code': (
            '415741565657534881ec500100004889ce488b4910b0ff480b4e18740f4881c4500100005b5f5e415e415fc30fb65642b10184d20f85c600'
            '0000488b56204c8b46284c8d7424404c89f1e8000000000fb784244001000031ff3d01010000bb01000000490f42de0f42f8807e41007430'
            '4885ff746d66662e0f1f8400000000004889f14889da41b008e8000000003cff0f85db01000048ffc348ffcf75e2eb424c8b76084c8b3e49'
            '01ff4983d600b0010f82bb010000807e43010f85af010000488d4e444889da4989f8e80000000089c1b00184c90f85960100004c893e4c89'
            '7608488b4620488b4e2848894e1848894610c64642014809c80f94c1b201b0ff80fa010f94c284ca0f840fffffff807e4100488b1e4c8b76'
            '0874544883c3014983d600b0010f82f2feffff807e43010f8533010000488d4e44488d7e4041b8010000004889fae80000000089c1b00184'
            'c90f85c6feffffba010000004889f9e8000000004c89760848891ec646410048895c24304c8974243848c7442420a800000048c744242800'
            '000000488d4c2430488d542420e800000000660fefc9660f6fd0660f76d10f50c283f00f0f849e00000066480f7ec0660f7f8c24d0000000'
            '660f7f8c24c0000000660f7f8c24b0000000660f7f8c24a0000000660f7f8c2490000000660f7f8c2480000000660f7f4c2470660f7f4c24'
            '60660f7f4c2450660f7f4c244048c78424e00000000000000041b8a80000004929c04c01c34983d600b0010f82f4fdffff807e4301753948'
            '8d4e44488d542440e80000000089c1b00184c90f85d4fdffff48891e4c89760848335e304c3376384909de750bc6464202b0ffe9b5fdffff'
            '31c0e9aefdffff31c0e9a7fdffff'
        ),
        'branches': [
            (0x1b, '74', 0x2c), (0x34, '0f85', 0x100), (0x6e, '74', 0xa0),
            (0x73, '74', 0xe2), (0x90, '0f85', 0x271), (0x9c, '75', 0x80),
            (0x9e, 'eb', 0xe2), (0xb0, '0f82', 0x271), (0xba, '0f85', 0x26f),
            (0xd5, '0f85', 0x271), (0x108, '0f84', 0x1d), (0x119, '74', 0x16f),
            (0x125, '0f82', 0x1d), (0x12f, '0f85', 0x268), (0x151, '0f85', 0x1d),
            (0x1ac, '0f84', 0x250), (0x223, '0f82', 0x1d), (0x22d, '75', 0x268),
            (0x243, '0f85', 0x1d), (0x25b, '75', 0x268), (0x263, 'e9', 0x1d),
            (0x26a, 'e9', 0x1d), (0x271, 'e9', 0x1d),
        ],
    },
    "left_encoder": {
        'name': "_RNvNtCs58M5yX2Qwr5_16brynja_hash_sha38sp80018511encode_u128",
        'contract': "Public u128 minimal big-endian encoding, one byte for zero, 1..16-byte payload and length prefix; zero-filled backing bytes.",
        'code': (
            '41565657534881ec380100004c89c0480fc8480fca4889ce4889542428488944242084c074084531c0e9f800000041b801000000a900ff00'
            '000f85e700000041b802000000a90000ff000f85d60000004889c148c1e91841b80300000084c90f85c10000004889c148c1e92041b80400'
            '000084c90f85ac0000004889c148c1e92841b80500000084c90f85970000004889c148c1e93041b80600000084c90f858200000048c1e838'
            '41b80700000075764889d048c1e03841b808000000756741b809000000f7c200ff0000755941b80a000000f7c20000ff00754b4889d048c1'
            'e81841b80b00000084c0753a4889d048c1e82041b80c00000084c075294889d048c1e82841b80d00000084c0751848b8000000000000ff00'
            '4821c24531c04883fa014983d00ebf100000004c29c74a8d1c044883c3204981c0ef000000488d0c3c4883c13931d2e8000000004c8d7424'
            '394c89f14889da4989f8e80000000040883e488d4e0141b8ff0000004c89f2e800000000ffc76689be000100004881c4380100005b5f5e41'
            '5ec3'
        ),
        'branches': [
            (0x24, '74', 0x2e), (0x29, 'e9', 0x126), (0x39, '0f85', 0x126),
            (0x4a, '0f85', 0x126), (0x5f, '0f85', 0x126), (0x74, '0f85', 0x126),
            (0x89, '0f85', 0x126), (0x9e, '0f85', 0x126), (0xae, '75', 0x126),
            (0xbd, '75', 0x126), (0xcb, '75', 0x126), (0xd9, '75', 0x126),
            (0xea, '75', 0x126), (0xfb, '75', 0x126), (0x10c, '75', 0x126),
        ],
    },
    "panic_fmt": {
        'name': "_RNvNtCs8xEFJqa6dYS_4core9panicking9panic_fmt",
        'contract': "Fixed terminating bridge to rust_begin_unwind; not returning cleanup.",
        'code': (
            '554883ec20488d6c2420e8000000000f0b'
        ),
        'branches': [
        ],
    },
    "panic_shift": {
        'name': "_RNvNtNtCs8xEFJqa6dYS_4core9panicking11panic_const24panic_const_shr_overflow",
        'contract': "Checked-shift failure terminates through panic_fmt; no successful output.",
        'code': (
            '554883ec20488d6c2420e8000000000f0b'
        ),
        'branches': [
        ],
    },
    "input_drop": {
        'name': "_RNvXs_NtCsh5jde4i55II_15parallel_stream21parallel_stream_inputNtB4_5InputNtNtNtCs8xEFJqa6dYS_4core3ops4drop4Drop4drop",
        'contract': "Active leaf drop before disarm; three16-byte counters erased; AVX2 authority borrow persists until resident retirement.",
        'code': (
            '564883ec204889cee800000000c60600488d8e70040000ba10000000e800000000488d8e80040000ba10000000e800000000488d8e900400'
            '00ba10000000e8000000000f57c00f2986a00400004883c4205ec3'
        ),
        'branches': [
        ],
    },
}
