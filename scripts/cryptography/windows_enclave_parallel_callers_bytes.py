"""Reviewed actual COFF instruction spans for sequential ParallelHash callers.

These are fixed saved-image contracts, not a compiler/disassembler proof.
Named spans state the reviewed operation; enclosing allocation and transitive
callee obligations are not discharged by a byte match. Customization starts
after setup conversion: its earlier moved-copy lifetimes remain separate.
"""

CONTRACTS = {
    'scalar': {
        'finish': {
            'size': 270,
            'regions': [
                ('phase_guard', 0x0,
                    '41574156565755534883ec384c89ce4c89c74989d04889ca48c7442420010000004c8d0d00000000488d4c24'
                    '28e8000000000fb654243080fa02750a0fb65c2428e9b5000000'),
                ('output_shape_and_xof_restriction', 0x46,
                    '488b4c24284881fe000400007607b303e99b000000440fb6b424900000004885f60f94c04584f6410f95c0b3'
                    '044484c0757e4885f60f95c0458d46ff4180f808410f93c04484c075674885f6740a4883b9280d00000277b6'),
                ('input_charge', 0x9e,
                    '488b4708483d0004000077aa4c8b81380d0000b3034929c0723e'),
                ('leaf_then_root_arguments_and_errors', 0xb8,
                    '89d54c8981380d0000488d81700400004889ca4889c14989d74989f8e8000000003cff75124c89f94889f245'
                    '89f0e8000000003cff741b89c389ea4c89f9e800000000'),
                ('return', 0xfb,
                    '89d84883c4385b5d5f5e415e415fc3b3ffebed'),
            ],
            'branches': [
                (0x3a, '75', 0x46), (0x41, 'e9', 0xfb), (0x52, '76', 0x5b),
                (0x56, 'e9', 0xf6), (0x76, '75', 0xf6), (0x8d, '75', 0xf6),
                (0x92, '74', 0x9e), (0x9c, '77', 0x54), (0xa8, '77', 0x54),
                (0xb6, '72', 0xf6), (0xdb, '75', 0xef), (0xed, '74', 0x10a),
                (0x10c, 'eb', 0xfb),
            ],
        },
        'rehash': {
            'size': 547,
            'regions': [
                ('phase_guard', 0x0,
                    '4157415641554154565755534881ec180900004c89ce4c89c74989d04889ca48c7442420020000004c8d0d00'
                    '000000488d4c2430e8000000000fb654243880fa02750a0fb65c2430e9c0010000'),
                ('output_shape_and_xof_restriction', 0x4d,
                    '4c8ba42498090000488b4c24304981fc000400007607b303e99e010000440fb6ac24a00900004d85e40f94c0'
                    '4584ed410f95c0b3044484c00f857d0100004d85e40f95c0458d45ff4180f808410f93c04484c00f85620100'
                    '004d85e40f95c04883ff03410f93c04184c075aa'),
                ('leaf_drop_and_counter_clear', 0xb9,
                    '8854242f488d81700400004989cf4889c1e80000000041c6877004000000498d8fe0080000ba10000000e800'
                    '000000498d8ff0080000ba10000000e800000000498d8f00090000ba10000000e8000000004c89f90f57c041'
                    '0f298710090000'),
                ('new_identity_block_and_setup', 0x118,
                    '4885f60f94c0488d57ff4883fa040f93c208c20f85c60000004c8b8c24880900004c8b8424800900004889b1'
                    '100900004889b918090000488d4c24304889fae800000000'),
                ('setup_result_move_and_root_replacement', 0x15c,
                    '0fb66c24300fb65c24314080fdff0f84900000004c8bb42490090000488d542432488d8c24aa04000041b86e'
                    '040000e8000000004c89f9e80000000041882f41885f01498d4f0241b86e040000488d9424aa040000e80000'
                    '0000'),
                ('checked_budget_and_next_shape_only', 0x1b6,
                    '4c89f9b3034d2bb7400d00000fb654242f723f4c89b1380d00004889b9280d00004889b1300d00004c89a148'
                    '0d00004488a9520d0000c681500d000002b3ffeb16'),
                ('armed_error_return', 0x1f7,
                    '31db0fb654242feb080fb654242f4c89f9e80000000089d84881c4180900005b5d5f5e415c415d415e415fc3'),
            ],
            'branches': [
                (0x41, '75', 0x4d), (0x48, 'e9', 0x20d), (0x61, '76', 0x6a),
                (0x65, 'e9', 0x208), (0x85, '0f85', 0x208), (0xa0, '0f85', 0x208),
                (0xb7, '75', 0x63), (0x12b, '0f85', 0x1f7), (0x16a, '0f84', 0x200),
                (0x1c7, '72', 0x208), (0x1f5, 'eb', 0x20d), (0x1fe, 'eb', 0x208),
            ],
        },
    },
    'avx2': {
        'finish': {
            'size': 322,
            'regions': [
                ('phase_guard', 0x0,
                    '5541565657534883ec50488d6c245048c745f8feffffff4c89ce4c89c74989d04889ca48c744242001000000'
                    '4c8d0d00000000488d4dd8e800000000440fb645e04180f80275090fb645d8e9e3000000'),
                ('output_shape_and_xof_restriction', 0x50,
                    '4c8b75d84881fe000400007607b003e99d0000000fb65d504885f60f94c184db0f95c2b00484d10f85840000'
                    '004885f60f94c18d53ff80fa080f92c208ca74714885f6740a4983be280c00000277be'),
                ('input_charge', 0x9f,
                    '488b4f084881f90004000077b1498b96380c0000b0034829ca7247'),
                ('leaf_then_root_arguments_and_errors', 0xba,
                    '448845f7498996380c0000498d8e000400004c8975e8498d96400800004989f8e800000000903cff7514488b'
                    '4de84889f24189d8e800000000903cff74464c8b75e8440fb645f7'),
                ('authority_revocation_owner_clear_and_return', 0x101,
                    '41f6c001752c89c3498b86500c000080780802740bc640080248c700030000004c89f1e80000000041c6865a'
                    '0c00000789d84883c4505b5f5e415e5dc3b0ffebf1'),
            ],
            'branches': [
                (0x45, '75', 0x50), (0x4b, 'e9', 0x133), (0x5b, '76', 0x64),
                (0x5f, 'e9', 0x101), (0x77, '0f85', 0x101), (0x8e, '74', 0x101),
                (0x93, '74', 0x9f), (0x9d, '77', 0x5d), (0xaa, '77', 0x5d),
                (0xb8, '72', 0x101), (0xe2, '75', 0xf8), (0xf6, '74', 0x13e),
                (0x105, '75', 0x133), (0x114, '74', 0x121), (0x140, 'eb', 0x133),
            ],
        },
        'rehash': {
            'size': 738,
            'regions': [
                ('phase_guard_and_aligned_frame', 0x0,
                    '5541574156415541545657534881ec38080000488dac24800000004883e4e04889e34889ab2808000048c785'
                    'b0070000feffffff4c89ce4c89c74989d04889ca48c7442420020000004c8d0d00000000488d8b80000000e8'
                    '00000000440fb6a3880000004180fc02750c0fb68380000000e971010000'),
                ('output_shape_and_xof_restriction', 0x76,
                    '4c8bb5380800004c8bab800000004981fe000400007607b003e91e010000440fb6bd400800004d85f60f94c1'
                    '4584ff0f95c2b00484d10f85000100004d85f60f94c1418d57ff80fa080f92c208ca0f84e80000004d85f60f'
                    '95c04883ff030f93c184c175b2'),
                ('leaf_drop_and_counter_clear', 0xdb,
                    '4183bdb0070000ff740c498d8d00040000e80000000049c785b0070000ffffffff498d8de0070000ba100000'
                    '00e800000000498d8df0070000ba10000000e800000000498d8d00080000ba10000000e800000000c5f857c0'
                    'c4c178118518080000'),
                ('new_identity_block_authority_and_setup', 0x13c,
                    '4885f60f94c0488d4fff4883f9040f93c108c1755f4488632f488b85280800004c8b8d200800004989b51808'
                    '00004989bd200800004c896b30498b95500c00004889442420488d8b800000004989f8e80000000090'),
                ('setup_result_and_armed_failure', 0x191,
                    '4c8ba3300400000fb683800000004983fcfe75594c8b6b30440fb6632feb0231c041f6c401752f89c6498b85'
                    '500c000080780802740bc640080248c700030000004c89e9c5f877e80000000041c6855a0c00000789f0488d'
                    'a5b80700005b5f5e415c415d415e415f5dc5f877c3'),
                ('setup_result_move_and_root_replacement', 0x1fe,
                    '89433c488d9381000000488d8b7904000041b8af030000e800000000c5fc108338040000c5fc294340488b83'
                    '58040000488943604c8b6b304183bdf00b0000ff740f498d8d40080000c5f877e8000000008b433c41888540'
                    '080000498d8d41080000488d937904000041b8af030000c5f877e8000000004d89a5f00b0000c5fc284340c4'
                    'c17c1185f80b0000488b4360498985180c0000'),
                ('checked_budget_and_next_shape_only', 0x295,
                    'b003488b8d30080000492b8d400c0000440fb6632f0f8202ffffff49898d380c00004989bd280c00004989b5'
                    '300c00004d89b5480c00004588bd590c000041c6855a0c000002b0ffe905ffffff'),
            ],
            'branches': [
                (0x68, '75', 0x76), (0x71, 'e9', 0x1e7), (0x8b, '76', 0x94),
                (0x8f, 'e9', 0x1b2), (0xac, '0f85', 0x1b2), (0xc4, '0f84', 0x1b2),
                (0xd9, '75', 0x8d), (0xe3, '74', 0xf1), (0x14f, '75', 0x1b0),
                (0x1a3, '75', 0x1fe), (0x1ae, 'eb', 0x1b2), (0x1b6, '75', 0x1e7),
                (0x1c5, '74', 0x1d2), (0x23e, '74', 0x24f), (0x2aa, '0f82', 0x1b2),
                (0x2dd, 'e9', 0x1e7),
            ],
        },
        'finish_handler': {
            'size': 83,
            'regions': [
                ('invoked_parent_cleanup', 0x0,
                    '48895424105541565657534883ec30488d6a50f645f701752f488b45e8488b80500c000080780802740bc640'
                    '080248c70003000000488b75e84889f1e800000000c6865a0c0000074883c4305b5f5e415e5dc3'),
            ],
            'branches': [
            ],
        },
        'rehash_handler': {
            'size': 105,
            'regions': [
                ('invoked_parent_cleanup', 0x0,
                    '48895424105541574156415541545657534883ec28488daa800000004883e2e04889d3f6432f01752f488b43'
                    '30488b80500c000080780802740bc640080248c70003000000488b73304889f1e800000000c6865a0c000007'
                    '4883c4285b5f5e415c415d415e415f5dc3'),
            ],
            'branches': [
            ],
        },
    },
}
