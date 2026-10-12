"""Reviewed actual COFF instruction spans for sequential ParallelHash custom.

These are fixed saved-image contracts, not a compiler/disassembler proof.
Named spans state the reviewed operation; enclosing allocation and transitive
callee obligations are not discharged by a byte match. Customization starts
after setup conversion: its earlier moved-copy lifetimes remain separate.
"""

CONTRACTS = {
    'scalar': {
        'finish_custom': {
            'size': 1952,
            'regions': [
                ('left_encoding_allocation', 0x44f,
                    '660fefc0660f7f44244066c744245000004c8bb6300d0000488d7c2451488d4c2440ba11000000e800000000'
                    '41bf01000000ba010000004889f9e800000000'),
                ('left_encoding_width', 0x48e,
                    '4981fe00010000725231c0b9ffff00004d89f04531c931d2662e0f1f8400000000004d89c24d89c84d0fa4d0'
                    '384989c748c1ea0848ffc04c39d141ba000000004d19ca4989d172da40b503483dfe0000000f878d01000049'
                    '83c702'),
                ('bounded_left_encoding_stores', 0x4e9,
                    '488d460244887c24404a8d14fdf8ffffff41b8020000004531c949bafeffffffffffff1f4531db40b5026666'
                    '66662e0f1f8400000000004881fa800000000f836c0200004983f8120f843b0100004d89f489d14d0fadcc4c'
                    '89d94883c901f6c2404d0f45e1468864043f4c39f9743b4c89d94c31d14c01f948c1e1034883f97f0f872a02'
                    '00004d89f44d0fadcc4983c302f6c1404d0f45e146886404404983c0024883c2f04d39fb758d'),
                ('prefix_absorption', 0x593,
                    '418d4f01884c24514983ff100f87cd000000440fb6c10fb60e83f9040f84a300000083f9030f85b400000040'
                    'b506807e01000f85a7000000488d5424404889c1e800000000e991000000'),
                ('setup_rejection_cleanup', 0x5dd,
                    '807e5301751a488d7e544889f9e800000000807e530074084889f9e800000000c6465300488d4e50ba010000'
                    '00e80000000066c746510003c6866404000000660fefc066410f7f473066410f7f472066410f7f471066410f'
                    '7f0740b506'),
                ('armed_operation_drop_return', 0x63a,
                    '4889f189dae80000000089e84881c4800c00005b5d5f5e415c415e415fc3'),
                ('wide_prefix_absorption', 0x658,
                    '40b506807e01007511488d5424404889c1e80000000084c0741e'),
                ('prefix_error_cleanup', 0x672,
                    '488d4c2440ba11000000e800000000ba010000004889f9e800000000ebaa'),
                ('retained_shape_and_bit_string', 0x690,
                    '80be500d0000020f85db0000004c8b86400d000040b5034981f80104000073c24c8db620090000440fb68e51'
                    '0d0000488d8c24e80000004c89f2e800000000'),
                ('retained_input_descriptor', 0x6cf,
                    '488b8424e80000004885c00f84b10000000fb68c24f0000000f30f6f8424f1000000f30f7f8424d100000048'
                    '8b94240001000048899424e000000048898424c8000000888c24d0000000'),
                ('exact_leaf_completion', 0x719,
                    '488d8e700400004c8d8424c80000004889f2e8000000003cff753d'),
                ('erase_old_output_then_load_next_shape', 0x734,
                    'ba000400004c89f1e800000000660fefc0488b96480d0000660f7f86400d0000440fb686520d000066c78651'
                    '0d00000000'),
                ('root_finish_and_commit', 0x765,
                    '4889f1e8000000003cff740e89c5e9fafeffffc686500d000003488d4c2440e80000000040b5ffe9b3feffff'),
                ('bit_string_failure_and_shift_panic', 0x791,
                    '40b504e9d9feffffe8000000000f0b'),
            ],
            'branches': [
                (0x495, '72', 0x4e9), (0x4d4, '72', 0x4b0), (0x4df, '0f87', 0x672),
                (0x527, '0f83', 0x799), (0x531, '0f84', 0x672), (0x556, '74', 0x593),
                (0x569, '0f87', 0x799), (0x591, '75', 0x520), (0x59f, '0f87', 0x672),
                (0x5af, '0f84', 0x658), (0x5b8, '0f85', 0x672), (0x5c5, '0f85', 0x672),
                (0x5d8, 'e9', 0x66e), (0x5e1, '75', 0x5fd), (0x5f3, '74', 0x5fd),
                (0x65f, '75', 0x672), (0x670, '74', 0x690), (0x68e, 'eb', 0x63a),
                (0x697, '0f85', 0x778), (0x6ae, '73', 0x672), (0x6da, '0f84', 0x791),
                (0x732, '75', 0x771), (0x76f, '74', 0x77f), (0x773, 'e9', 0x672),
                (0x78c, 'e9', 0x644), (0x794, 'e9', 0x672),
            ],
        },
    },
    'avx2': {
        'finish_custom': {
            'size': 1214,
            'regions': [
                ('left_encoding_allocation', 0x234,
                    'c5f9efc0c5f97f45f066c7450000004d8bbc24300c0000488d7501488d4df0ba11000000c5f877e800000000'
                    'ba010000004889f1e800000000'),
                ('left_encoding_width', 0x26d,
                    '4981ff00010000724731c0b9ffff00004d89f84531c931d24d89c24d89c84d0fa4d0384989c648c1ea0848ff'
                    'c04c39d141ba000000004d19ca4989d172dab303483dfe0000000f87d40100004983c602'),
                ('bounded_left_encoding_stores', 0x2bd,
                    '498dbc2440080000448875f04a8d04f5f8ffffffba020000004531c049b9feffffffffffff1f4531d2b30248'
                    '3d800000000f83c30100004883fa120f848f0100004d89fb89c14d0fadc34c89d14883c901a8404d0f45d844'
                    '885c15ef4c39f1743b4c89d14c31c94c01f148c1e1034883f97f0f87820100004d89fb4d0fadc34983c202f6'
                    'c1404d0f45d844885c15f04883c2024883c0f04d39f2758f'),
                ('prefix_absorption', 0x359,
                    '418d46018845014983fe100f87230100004183bc24f00b0000ff0f8414010000440fb6c0488d55f04889f9e8'
                    '00000000b3063cff0f85fa000000'),
                ('retained_shape_and_bit_string', 0x393,
                    '44886d1f4c8965104180bc245a0c0000020f85bd000000488b45104c8b80400c0000b3034981f8000400000f'
                    '87c0000000488b5510440fb68a580c0000488d4dd0e800000000'),
                ('retained_input_descriptor', 0x3d9,
                    '488b45d04885c00f849c0000000fb64dd8c5fa6f45d9c5fa7f45b9488b55e8488955c8488945b0884db8'),
                ('exact_leaf_completion', 0x403,
                    '488b4510488d88000400004c8d45b04889fae8000000009089c33cff7563'),
                ('erase_old_output_then_load_next_shape', 0x421,
                    'ba00040000488b7d104889f9e800000000c5f9efc0488b97480c0000c5f97f87400c0000440fb687590c0000'
                    '66c787580c00000000'),
                ('root_finish_and_commit', 0x456,
                    '4889f9e8000000009089c33cff751feb0b488b4510c6805a0c000003488d4df0e800000000b3ffe9b3fcffff'),
                ('prefix_error_cleanup', 0x482,
                    'b3044c8b6510440fb66d1f488d4df0ba11000000e800000000ba010000004889f1e80000000041f6c5010f84'
                    '56fcffffe97efcffff'),
                ('impossible_shift_panic', 0x4b7,
                    'e8000000000f0b'),
            ],
            'branches': [
                (0x274, '72', 0x2bd), (0x2a9, '72', 0x285), (0x2b3, '0f87', 0x48d),
                (0x2ee, '0f83', 0x4b7), (0x2f8, '0f84', 0x48d), (0x31c, '74', 0x359),
                (0x32f, '0f87', 0x4b7), (0x357, '75', 0x2e8), (0x364, '0f87', 0x48d),
                (0x373, '0f84', 0x48d), (0x38d, '0f85', 0x48d), (0x3a4, '0f85', 0x467),
                (0x3be, '0f87', 0x484), (0x3e0, '0f84', 0x482), (0x41f, '75', 0x484),
                (0x463, '75', 0x484), (0x465, 'eb', 0x472), (0x47d, 'e9', 0x135),
                (0x4ac, '0f84', 0x108), (0x4b2, 'e9', 0x135),
            ],
        },
        'finish_custom_handler': {
            'size': 107,
            'regions': [
                ('invoked_parent_cleanup', 0x0,
                    '48895424105541574156415541545657534883ec28488daa80000000488d4df0e800000000f6451f01752f48'
                    '8b4510488b80500c000080780802740bc640080248c70003000000488b75104889f1e800000000c6865a0c00'
                    '00074883c4285b5f5e415c415d415e415f5dc3'),
            ],
            'branches': [
            ],
        },
    },
}
