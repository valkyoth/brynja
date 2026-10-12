"""Reviewed actual COFF lifecycle spans; not a whole-image or unwind proof.

The labels describe the inspected instruction semantics. Callee, exclusive
placement and platform/window guarantees remain separate prerequisites.
"""

CONTRACTS = {
    'clear': {
        'size': 227,
        'regions': [
            ('save_owner_drop_active_root', 0x0,
                '564883ec30c5f8297424204889ce83b9f00b0000ff740c488d8e40080000e800000000'),
            ('empty_root_drop_active_leaf', 0x23,
                '48c786f00b0000ffffffff83beb0070000ff740c488d8e00040000e800000000'),
            ('empty_leaf_and_clear_three_counters', 0x43,
                '48c786b0070000ffffffff488d8ee0070000ba10000000e800000000488d8ef0070000ba10000000e800'
                '000000488d8e00080000ba10000000e800000000'),
            ('clear_input_metadata_and_full_output', 0x81,
                'c5c857f6c5f811b618080000ba000400004889f1e800000000'),
            ('clear_current_shape_budget_next_shape_identity', 0x9a,
                '48c786400c000000000000c686580c000000488d8e380c0000ba08000000e80000000048c786480c0000'
                '00000000c686590c000000c5f811b6280c0000'),
            ('restore_frame_preserving_authority_and_sequence', 0xd7,
                'c5f8287424204883c4305ec3'),
        ],
        'branches': [
            (0x15, '74', 0x23),
            (0x35, '74', 0x43),
        ],
    },
    'operation': {
        'size': 335,
        'regions': [
            ('owner_phase_and_first_allowed_value', 0x0,
                '56574883ec284889d64889cf0fb6825a0c00004138017543'),
            ('nonwrapping_exact_next_sequence', 0x18,
                '488b86200c000048ffc00f95c14c39c00f94c084c1756c'),
            ('sequence_error_revoke_authority_then_clear', 0x2f,
                '488b86500c000080780802740bc640080248c700030000004889f1e800000000'),
            ('quarantine_and_sequence_error', 0x4f,
                'c6865a0c000007c60701eb35'),
            ('single_allowed_value_guard', 0x5b,
                '488b4c24604883f9017563'),
            ('phase_error_revoke_authority_then_clear', 0x66,
                '488b86500c000080780802740bc640080248c700030000004889f1e800000000'),
            ('quarantine_and_phase_error', 0x86,
                'c6865a0c000007c60702'),
            ('error_tag_and_return', 0x90,
                'c64708024883c4285f5ec3'),
            ('exact_healthy_keccak_authority', 0x9b,
                '488b86500c00000fb648080fb6500980f2044189c94180f1014108d1756b'),
            ('commit_sequence_return_armed_original_owner', 0xb9,
                '4c8986200c0000488937c6470800ebcb'),
            ('length_guarded_remaining_five_allowed_values', 0xc9,
                '413841010f8445ffffff4883f902748d413841020f8435ffffff4883f9030f8479ffffff413841030f84'
                '21ffffff4883f9040f8465ffffff413841040f840dffffff4883f9050f8451ffffff413841050f84f9fe'
                'ffffe942ffffff'),
            ('backend_error_revoke_clear_quarantine', 0x124,
                'c60707c647080280f902740bc640080248c700030000004889f1e800000000c6865a0c000007e945ffff'
                'ff'),
        ],
        'branches': [
            (0x16, '75', 0x5b),
            (0x2d, '75', 0x9b),
            (0x3a, '74', 0x47),
            (0x59, 'eb', 0x90),
            (0x64, '75', 0xc9),
            (0x71, '74', 0x7e),
            (0xb7, '75', 0x124),
            (0xc7, 'eb', 0x94),
            (0xcd, '0f84', 0x18),
            (0xd7, '74', 0x66),
            (0xdd, '0f84', 0x18),
            (0xe7, '0f84', 0x66),
            (0xf1, '0f84', 0x18),
            (0xfb, '0f84', 0x66),
            (0x105, '0f84', 0x18),
            (0x10f, '0f84', 0x66),
            (0x119, '0f84', 0x18),
            (0x11f, 'e9', 0x66),
            (0x12e, '74', 0x13b),
            (0x14a, 'e9', 0x94),
        ],
    },
    'cancel': {
        'size': 101,
        'regions': [
            ('six_phase_call_with_sequence_and_original_owner', 0x0,
                '55564883ec58488d6c245048c74500feffffff4989d04889ca48c7442420060000004c8d0d0000000048'
                '8d4de0e800000000'),
            ('return_admission_error_without_reset', 0x32,
                '0fb645e83c0275060fb645e0eb1e'),
            ('capture_armed_original_owner_and_clear', 0x40,
                '8845ff488b4de048894df0e80000000090'),
            ('publish_empty_after_cleanup', 0x51,
                '488b45f0c6805a0c000000b0ff'),
            ('restore_frame', 0x5e,
                '4883c4585e5dc3'),
        ],
        'branches': [
            (0x38, '75', 0x40),
            (0x3e, 'eb', 0x5e),
        ],
    },
    'cancel_handler': {
        'size': 71,
        'regions': [
            ('parent_frame_and_original_owner_capture', 0x0,
                '488954241055564883ec28488d6a50488b75f0'),
            ('skip_if_completed_else_revoke_authority', 0x13,
                'f645ff017527488b86500c000080780802740bc640080248c70003000000'),
            ('clear_original_owner_then_quarantine', 0x31,
                '4889f1e800000000c6865a0c000007'),
            ('restore_handler_frame', 0x40,
                '4883c4285e5dc3'),
        ],
        'branches': [
            (0x17, '75', 0x40),
            (0x24, '74', 0x31),
        ],
    },
    'new': {
        'size': 560,
        'regions': [
            ('public_constructor_frame_and_original_page', 0x0,
                '41574156565753b810110000e8000000004829c44889d74889ce'),
            ('KAT_then_place_authority_before_borrow', 0x1a,
                'e800000000b10228c148c70702000000884f08c647090484c00f84a5010000'),
            ('owner_offset_and_public_initial_output', 0x39,
                '4c8d7f20c5f857c0c5fc11842490010000c5fc11842480010000488d9c24b201000041b8ff0300004889'
                'd931d2c5f877e800000000'),
            ('public_empty_owner_temporary_copy', 0x6e,
                'c5f857c0c5f829442420c5f857c0c5fc11842428010000c5fc118424380100004c8db4246109000041b8'
                'af0700004c89f14889dac5f877e800000000'),
            ('move_empty_metadata_temporaries', 0xaa,
                'c5fc10842458010000c5fc108c2478010000c5fc10942490010000c5fc118424a0000000c5fc118c24c0'
                '000000c5fc119424d8000000c5f828442420c5f829442430c5fc10842400010000c5fc108c2420010000'
                'c5fc10942438010000c5fc11442440c5fc114c2460c5fc11542478'),
            ('place_owner_output_and_inactive_leaf', 0x119,
                'c6472000488d4f2141b8af0700004c89f2c5f877e80000000048c787d0070000ffffffffc5fc108424a0'
                '000000c5fc108c24c0000000c5fc109424d8000000c5fc1187d8070000c5fc118ff8070000c5fc119710'
                '080000'),
            ('place_input_authority_pointer_and_empty_root', 0x170,
                '4889bf30080000c5f828442430c5f811873808000048c787100c0000ffffffff'),
            ('place_root_metadata_and_owner_authority_pointer', 0x190,
                'c5fc10442440c5fc104c2460c5fc10542478c5fc1187180c0000c5fc118f380c0000c5fc1197500c0000'
                '4889bf700c0000'),
            ('empty_phase_and_publish_three_pointer_handle', 0x1c1,
                '66c787780c00000000c6877a0c00000048893e48897e084c897e10eb40'),
            ('failure_loop_initialize', 0x1de,
                '31c0'),
            ('failure_erase_all_4096_bytes', 0x1e0,
                'c6040700c644070100c644070200c644070300c644070400c644070500c644070600c6440707004883c0'
                '08483d0010000075cd'),
            ('publish_backend_error_no_owner', 0x213,
                'c646080748c70600000000'),
            ('restore_frame_and_upper_vectors', 0x21e,
                '4881c4101100005b5f5e415e415fc5f877c3'),
        ],
        'branches': [
            (0x33, '0f84', 0x1de),
            (0x1dc, 'eb', 0x21e),
            (0x211, '75', 0x1e0),
        ],
    },
    'drop': {
        'size': 252,
        'regions': [
            ('capture_original_page_and_owner_then_revoke_authority', 0x0,
                '555657534883ec38488d6c243048c74500feffffff4889ce488b82500c000080780802740bc640080248'
                'c70003000000'),
            ('save_owner_and_clear', 0x30,
                '4889d1488955f8e80000000090'),
            ('quarantine_then_drop_root', 0x3d,
                '488b5df8c6835a0c000007488d8b40080000e800000000'),
            ('drop_active_leaf_and_mark_empty', 0x54,
                '488dbb0004000083bbb0070000ff74084889f9e80000000048c783b0070000ffffffff'),
            ('clear_three_leaf_counters', 0x77,
                '488d8be0070000ba10000000e800000000488d8bf0070000ba10000000e800000000488d8b00080000ba'
                '10000000e800000000'),
            ('clear_leaf_metadata_and_final_typed_drop', 0xaa,
                'c5f857c0c5f81183180800004889f9e800000000'),
            ('page_loop_initialize', 0xbe,
                '31c0'),
            ('erase_all_4096_bytes_after_typed_destructors', 0xc0,
                'c6040600c644060100c644060200c644060300c644060400c644060500c644060600c6440607004883c0'
                '08483d0010000075cd'),
            ('restore_frame', 0xf3,
                '4883c4385b5f5e5dc3'),
        ],
        'branches': [
            (0x23, '74', 0x30),
            (0x62, '74', 0x6c),
            (0xf1, '75', 0xc0),
        ],
    },
    'drop_handler': {
        'size': 58,
        'regions': [
            ('parent_frame_original_owner', 0x0,
                '4889542410555657534883ec28488d6a30488b75f8'),
            ('root_typed_drop', 0x15,
                '488d8e40080000e800000000'),
            ('input_typed_drop', 0x21,
                '4881c6000400004889f1e800000000'),
            ('return_without_claiming_full_page_erasure', 0x30,
                '904883c4285b5f5e5dc3'),
        ],
        'branches': [
        ],
    },
}
