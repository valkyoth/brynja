"""Reviewed actual COFF instruction spans for sequential ParallelHash root.

These are fixed saved-image contracts, not a compiler/disassembler proof.
Named spans state the reviewed operation; enclosing allocation and transitive
callee obligations are not discharged by a byte match. Customization starts
after setup conversion: its earlier moved-copy lifetimes remain separate.
"""

CONTRACTS = {
    'scalar': {
        'finish_root': {
            'size': 748,
            'regions': [
                ('frame_and_split_output_bits', 0x0,
                    '4157415641554154565755534883ec784489c34889d74889ce4885d2741d4c8d6fff49c1ed3d488d04fdf8ff'
                    'ffff440fb6e34901c44983d500eb064531e44531ed'),
                ('identity_and_suffix_allocation', 0x41,
                    '488b86280d000048894424504c8d7424410f57c00f2944243066c74424400000488d4c2430ba11000000e800'
                    '00000041bf01000000ba010000004c89f1e800000000'),
                ('right_encoding_width', 0x83,
                    '4981fc000100004c89e84883d800726331c0b9ffff00004d89e04d89e94c89ea666666662e0f1f8400000000'
                    '004d89c24d89c84d0fa4d0384989c748c1ea0848ffc04c39d141ba000000004d19ca4989d172da40b503483d'
                    'fe0000000f87eb00000040b5024883f80f0f87de0000004983c702'),
                ('bounded_right_encoding_stores', 0xf6,
                    '488d54243046887c3c304d8d47ff4a8d04fdf8ffffff4531d249b9feffffffffffff1f0f1f8000000000483d'
                    '800000000f83b90100004d89e389c14d0fadeb4c89ed48d3eda840490f44eb42886c14304d39d074434c89d1'
                    '4c31c94c01f948c1e1034883f97f0f87830100004983fa1074654d89e34d0fadeb4c89ed48d3edf6c140490f'
                    '44eb42886c14314983c2024883c0f04d39d77592'),
                ('suffix_absorption', 0x18e,
                    '418d47018844244140b5024983ff107731440fb6c00fb60683f804745483f803752040b506807e0100751748'
                    '8d4e02488d542430e80000000084c07505eb4840b502'),
                ('error_suffix_clear_and_return', 0x1d0,
                    '488d4c2430ba11000000e800000000ba010000004c89f1e80000000089e84883c4785b5d5f5e415c415d415e'
                    '415fc3'),
                ('wide_suffix_absorption', 0x1ff,
                    '40b506807e010075c8488d4e02e80000000084c075bb'),
                ('empty_tail_and_finalize', 0x215,
                    '0f57c00f1144246148c744245801000000c6442460000fb60683f804741840b50283f8037595488d4e01488d'
                    '542458e800000000eb0e488d4e01488d542458e80000000040b5063cff0f856cffffff'),
                ('budget_clear_fixed_or_xof', 0x264,
                    '488d8e380d0000ba08000000e800000000b00448837c245002774e40b5034881ff010400000f8341ffffff'),
                ('terminal_output_then_root_drop', 0x28f,
                    '488d9620090000c6442420014889f14989f84189d9e80000000089c53cff0f851dffffff4889f1e800000000'
                    'c60600'),
                ('publish_then_suffix_drop', 0x2be,
                    '4889be400d0000889e510d0000b0058886500d0000488d4c2430e80000000040b5ffe907ffffff'),
                ('impossible_shift_panic', 0x2e5,
                    'e8000000000f0b'),
            ],
            'branches': [
                (0x1c, '74', 0x3b), (0x39, 'eb', 0x41), (0x91, '72', 0xf6),
                (0xd4, '72', 0xb0), (0xdf, '0f87', 0x1d0), (0xec, '0f87', 0x1d0),
                (0x126, '0f83', 0x2e5), (0x149, '74', 0x18e), (0x15c, '0f87', 0x2e5),
                (0x166, '74', 0x1cd), (0x18c, '75', 0x120), (0x19d, '77', 0x1d0),
                (0x1a9, '74', 0x1ff), (0x1ae, '75', 0x1d0), (0x1b7, '75', 0x1d0),
                (0x1c9, '75', 0x1d0), (0x1cb, 'eb', 0x215), (0x206, '75', 0x1d0),
                (0x213, '75', 0x1d0), (0x231, '74', 0x24b), (0x239, '75', 0x1d0),
                (0x249, 'eb', 0x259), (0x25e, '0f85', 0x1d0), (0x27d, '77', 0x2cd),
                (0x289, '0f83', 0x1d0), (0x2ad, '0f85', 0x1d0), (0x2e0, 'e9', 0x1ec),
            ],
        },
    },
    'avx2': {
        'finish_root': {
            'size': 714,
            'regions': [
                ('frame_and_split_output_bits', 0x0,
                    '5541574156415541545657534883ec78488d6c247048c74500feffffff4489c34889d74889ce4885d2741d4c'
                    '8d6fff49c1ed3d488d04fdf8ffffff440fb6fb4901c74983d500eb064531ff4531ed'),
                ('identity_and_suffix_allocation', 0x4e,
                    '488b86280c0000488945d84c8d65f1c5f857c0c5f82945e066c745f00000488d4de0ba11000000e800000000'
                    '41be01000000ba010000004c89e1e800000000'),
                ('right_encoding_width', 0x8d,
                    '4981ff000100004c89e84883d800725931c0b9ffff00004d89f84d89e94c89ea0f1f004d89c24d89c84d0fa4'
                    'd0384989c648c1ea0848ffc04c39d141ba000000004d19ca4989d172da41b403483dfe0000000f87e1000000'
                    '41b4024883f80f0f87d40000004983c602'),
                ('bounded_right_encoding_stores', 0xf6,
                    '488d55e046887435e04d8d46ff4a8d04f5f8ffffff4531d249b9feffffffffffff1f0f1f840000000000483d'
                    '800000000f83970100004d89fb89c14d0fadeb4d89ec49d3eca8404d0f44e346886415e04d39d074434c89d1'
                    '4c31c94c01f148c1e1034883f97f0f87610100004983fa10745b4d89fb4d0fadeb4d89ec49d3ecf6c1404d0f'
                    '44e346886415e14983c2024883c0f04d39d67592'),
                ('suffix_absorption', 0x18e,
                    '418d46018845f141b4024983fe10772883bef00b0000ff741f4c8dbe40080000440fb6c04c89f9e800000000'
                    '3cff743841b406eb0341b402'),
                ('error_suffix_clear_and_return', 0x1c6,
                    '488d4de0ba11000000e800000000ba01000000488d4df1e8000000004489e04883c4785b5f5e415c415d415e'
                    '415f5dc3'),
                ('empty_tail_and_finalize', 0x1f6,
                    'c5f857c0c5f81145c148c745b801000000c645c00083bef00b0000ff74b2488d55b84c89f9e800000000903c'
                    'ff7599'),
                ('budget_clear_fixed_or_xof', 0x225,
                    '488d8e380c0000ba08000000e800000000b00448837dd802776d41b4034881ff010400000f8377ffffff83be'
                    'f00b0000ff41b4020f8467ffffff'),
                ('terminal_output_then_root_drop', 0x25f,
                    'c6442420014c89f94889f24989f84189d9e8000000009041b4063cff0f8545ffffff83bef00b0000ff74084c'
                    '89f9e80000000048c786f00b0000ffffffff'),
                ('publish_then_suffix_drop', 0x29d,
                    '4889be400c0000889e580c0000b00588865a0c0000488d4de0e80000000041b4ffe91fffffff'),
                ('impossible_shift_panic', 0x2c3,
                    'e8000000000f0b'),
            ],
            'branches': [
                (0x29, '74', 0x48), (0x46, 'eb', 0x4e), (0x9b, '72', 0xf6),
                (0xd4, '72', 0xb0), (0xdf, '0f87', 0x1c6), (0xec, '0f87', 0x1c6),
                (0x126, '0f83', 0x2c3), (0x149, '74', 0x18e), (0x15c, '0f87', 0x2c3),
                (0x166, '74', 0x1c3), (0x18c, '75', 0x120), (0x19c, '77', 0x1c6),
                (0x1a5, '74', 0x1c6), (0x1bc, '74', 0x1f6), (0x1c1, 'eb', 0x1c6),
                (0x212, '74', 0x1c6), (0x223, '75', 0x1be), (0x23d, '77', 0x2ac),
                (0x249, '0f83', 0x1c6), (0x259, '0f84', 0x1c6), (0x27b, '0f85', 0x1c6),
                (0x288, '74', 0x292), (0x2be, 'e9', 0x1e2),
            ],
        },
        'finish_root_handler': {
            'size': 52,
            'regions': [
                ('invoked_parent_cleanup', 0x0,
                    '48895424105541574156415541545657534883ec28488d6a70488d4de0e800000000904883c4285b5f5e415c'
                    '415d415e415f5dc3'),
            ],
            'branches': [
            ],
        },
    },
}
