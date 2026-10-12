"""Actual COFF instruction contracts for sequential ParallelHash avx2.

Not derived from the separately emitted listing. Population pins also bind
all references and ABI. These are conditional author-review contracts.
"""

CONTRACTS = {
    "begin": {
        'name': "_RNvMs_Cs22XHcxRQXBi_20parallel_acceleratedNtB4_5Owner5begin",
        'contract': "Empty phase and exact next sequence; positive B/identity1..4; setup success before metadata/Custom publication; guard retains original Owner.",
        'code': (
            '5541574156415541545657534881ec38080000488dac24800000004883e4e04889e34889ab2808000048c785b0070000feffffff4c89ce4c'
            '89c74989d04889ca48c7442420010000004c8d0d00000000488d8b80000000e800000000440fb6bb880000004180ff02750c0fb683800000'
            '00e9dc0100004c8bb3800000004183beb0070000ff740c498d8e00040000e80000000049c786b0070000ffffffff498d8ee0070000ba1000'
            '0000e800000000498d8ef0070000ba10000000e800000000498d8e00080000ba10000000e800000000c5f857c0c4c1781186180800004885'
            'f60f95c0488d4fff4883f9040f92c184c8746844887b37488b85280800004c8b8d200800004989b6180800004989be200800004c89733849'
            '8b96500c00004889442420488d8b800000004989f8e800000000904c8bb3300400000fb683800000004983fefe75514c8b7338440fb67b37'
            '41f6c7017411e9f700000031c041f6c7010f85eb00000089c6498b86500c000080780802740bc640080248c700030000004c89f1e8000000'
            '0041c6865a0c00000789f0e9ba0000004189c44c8bbd30080000488d9381000000488d8b7904000041b8af030000e800000000c5fc108338'
            '040000c5fc294340488b8358040000488943604c8b6b384183bdf00b0000ff740f498d8d40080000c5f877e8000000004588a54008000049'
            '8d8d41080000488d937904000041b8af030000c5f877e8000000004d89b5f00b0000c5fc284340c4c17c1185f80b0000488b436049898518'
            '0c00004989bd280c00004989b5300c00004d89bd380c000041c6855a0c000001b0ff488da5b80700005b5f5e415c415d415e415f5dc5f877'
            'c3'
        ),
        'branches': [
            (0x68, '75', 0x76), (0x71, 'e9', 0x252), (0x85, '74', 0x93),
            (0xf1, '74', 0x15b), (0x145, '75', 0x198), (0x154, '74', 0x167),
            (0x156, 'e9', 0x252), (0x161, '0f85', 0x252), (0x174, '74', 0x181),
            (0x193, 'e9', 0x252), (0x1df, '74', 0x1f0),
        ],
    },
    "custom": {
        'name': "_RNvMs_Cs22XHcxRQXBi_20parallel_acceleratedNtB4_5Owner6custom",
        'contract': "Custom phase; <=1024-byte budget charge; exact remaining prefix bits; failure quarantines; AVX2 empty chunk intentionally succeeds.",
        'code': (
            '5541565657534883ec50488d6c245048c745f8feffffff4c89c64989d04889ca48c7442420020000004c8d0d00000000488d4dd8e8000000'
            '000fb655e080fa0275060fb65dd8eb4e4c8b75d8488b460840b703483d00040000770c498b8e380c00004829c1733cf6c2017528498b8650'
            '0c000080780802740bc640080248c700030000004c89f1e80000000041c6865a0c00000789fb89d84883c4505b5f5e415e5dc349898e380c'
            '0000b3ff48837e100074e34183bef00b0000ff742a8855f74c8975e8498d8e4008000031d24989f0e8000000009040b7063cff4c8b75e80f'
            'b655f77582ebaf40b702e978ffffff'
        ),
        'branches': [
            (0x40, '75', 0x48), (0x46, 'eb', 0x96), (0x59, '77', 0x67),
            (0x65, '73', 0xa3), (0x6a, '75', 0x94), (0x77, '74', 0x84),
            (0xb1, '74', 0x96), (0xbb, '74', 0xe7), (0xe3, '75', 0x67),
            (0xe5, 'eb', 0x96), (0xea, 'e9', 0x67),
        ],
    },
    "update": {
        'name': "_RNvMs_Cs22XHcxRQXBi_20parallel_acceleratedNtB4_5Owner6update",
        'contract': "Absorb phase; caller bounds<=1024; checked budget/u128 total; distinct leaf/root storage; failure quarantines.",
        'code': (
            '5541565657534883ec50488d6c245048c745f8feffffff4c89ce4c89c74989d04889ca48c7442420010000004c8d0d00000000488d4dd8e8'
            '000000000fb655e080fa0275090fb645d8e9a50000004c8b75d8498b8e380c0000b0034829f1725e49898e380c00004c8d04f5000000004d'
            '8b8e080800004d0386000800004983d100723b8855f7498d8e00040000498d96400800004d8986000800004c8975e84d898e080800004989'
            'f84989f1e800000000903cff4c8b75e80fb655f77433f6c201753089c3498b86500c000080780802740bc640080248c700030000004c89f1'
            'e80000000041c6865a0c00000789d8eb02b0ff4883c4505b5f5e415e5dc3'
        ),
        'branches': [
            (0x43, '75', 0x4e), (0x49, 'e9', 0xf3), (0x5e, '72', 0xbe),
            (0x81, '72', 0xbe), (0xbc, '74', 0xf1), (0xc1, '75', 0xf3),
            (0xd0, '74', 0xdd), (0xef, 'eb', 0xf3),
        ],
    },
    "squeeze": {
        'name': "_RNvMs_Cs22XHcxRQXBi_20parallel_acceleratedNtB4_5Owner7squeeze",
        'contract': "Reader phase, <=1024 and nonterminal full bytes; disjoint root/output; terminal drop before Retained; shape publication only on success.",
        'code': (
            '55415741565657534883ec58488d6c245048c74500feffffff4489ce4c89c74989d04889ca48c7442420010000004c8d0d00000000488d4d'
            'e0e800000000440fb645e84180f80275090fb645e0e90f0100004c8b7de0b0034881ff000400000f87ca0000004885ff0f94c14084f60f95'
            'c2b00484d10f85b40000004885ff0f94c18d56ff80fa080f92c208ca0f849d000000440fb675604885ff0f95c14584f6750cc0e1034038ce'
            '0f85810000004183bff00b0000ff7475448845ff498d9f4008000044887424204889d94c897df04c89fa4989f84189f1e8000000009089c1'
            'b00680f9ff4c8b7df0440fb645ff753f4584f6741f4183bff00b0000ff74084889d9e80000000049c787f00b0000ffffffffb0054989bf40'
            '0c00004188b7580c00004188875a0c0000b0ffeb34b00241f6c001752c89c3498b87500c000080780802740bc640080248c700030000004c'
            '89f9e80000000041c6875a0c00000789d84883c4585b5f5e415e415f5dc3'
        ),
        'branches': [
            (0x47, '75', 0x52), (0x4d, 'e9', 0x161), (0x5f, '0f87', 0x12f),
            (0x75, '0f85', 0x12f), (0x8c, '0f84', 0x12f), (0xa0, '75', 0xae),
            (0xa8, '0f85', 0x12f), (0xb6, '74', 0x12d), (0xee, '75', 0x12f),
            (0xf3, '74', 0x114), (0xfd, '74', 0x107), (0x12b, 'eb', 0x161),
            (0x133, '75', 0x161), (0x142, '74', 0x14f),
        ],
    },
    "left_encoder": {
        'name': "_RNvNtCs58M5yX2Qwr5_16brynja_hash_sha38sp80018516left_encode_u128",
        'contract': "Public u128 minimal big-endian encoding, one byte for zero, 1..16-byte payload and length prefix; zero-filled backing bytes.",
        'code': (
            '5657534881ec300100004c89c0480fc8480fca4889ce4889542428488944242084c074084531c0e9f800000041b801000000a900ff00000f'
            '85e700000041b802000000a90000ff000f85d60000004889c148c1e91841b80300000084c90f85c10000004889c148c1e92041b804000000'
            '84c90f85ac0000004889c148c1e92841b80500000084c90f85970000004889c148c1e93041b80600000084c90f858200000048c1e83841b8'
            '0700000075764889d048c1e03841b808000000756741b809000000f7c200ff0000755941b80a000000f7c20000ff00754b4889d048c1e818'
            '41b80b00000084c0753a4889d048c1e82041b80c00000084c075294889d048c1e82841b80d00000084c0751848b8000000000000ff004821'
            'c24531c04883fa014983d00ebf100000004c29c74a8d1c044883c3204981c0ef000000488d0c3c4883c13131d2e800000000488d4c243148'
            '89da4989f8e80000000040883ec5fc10442431c5fc104c2451c5fc10542471c5fc109c2491000000c5fc114601c5fc114e21c5fc115641c5'
            'fc115e61c5fc108424b1000000c5fc118681000000c5fc108424d1000000c5fc1186a1000000c5fc108424f1000000c5fc1186c1000000c5'
            'fc10842410010000c5fc1186e0000000ffc76689be000100004881c4300100005b5f5ec5f877c3'
        ),
        'branches': [
            (0x22, '74', 0x2c), (0x27, 'e9', 0x124), (0x37, '0f85', 0x124),
            (0x48, '0f85', 0x124), (0x5d, '0f85', 0x124), (0x72, '0f85', 0x124),
            (0x87, '0f85', 0x124), (0x9c, '0f85', 0x124), (0xac, '75', 0x124),
            (0xbb, '75', 0x124), (0xc9, '75', 0x124), (0xd7, '75', 0x124),
            (0xe8, '75', 0x124), (0xf9, '75', 0x124), (0x10a, '75', 0x124),
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
    "xor_wrapper": {
        'name': "_RNvNtCsjNKEhcqdpKw_11brynja_core13secret_memory20xor_secret_byte_bits",
        'contract': "Same KMAC body/references, narrowed caller destination-bit ABI; count1..8 and source/destination offsets<=8-count.",
        'code': (
            '534883ec30b0014180f908773e440fb65c246041b2084528ca4538d3772d4584c974284538d07723b3ff4889c84489d1d2eb450fb6c0450f'
            'b6cb0fb6cb894c24204889c1e80000000031c04883c4305bc3'
        ),
        'branches': [
            (0xb, '77', 0x4b), (0x1c, '77', 0x4b), (0x21, '74', 0x4b),
            (0x26, '77', 0x4b),
        ],
    },
    "xor_bits": {
        'name': "_RNvNtCsjNKEhcqdpKw_11brynja_core17secret_memory_xor8xor_bits",
        'contract': "Same opaque byte-XOR body/references, narrowed destination ABI; guarded shifts and one-byte live source/destination.",
        'code': (
            '4989ca448b5c24280fb6024489c1d3e84421d84489c9d3e041300231c031c9c3'
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
}
