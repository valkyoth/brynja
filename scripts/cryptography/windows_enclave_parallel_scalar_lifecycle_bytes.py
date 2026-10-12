"""Reviewed actual COFF lifecycle spans; not a whole-image or unwind proof.

The labels describe the inspected instruction semantics. Callee, exclusive
placement and platform/window guarantees remain separate prerequisites.
"""

CONTRACTS = {
    'clear': {
        'size': 189,
        'regions': [
            ('save_original_owner_and_drop_root', 0x0,
                '564883ec300f297424204889cee800000000'),
            ('empty_root_then_drop_leaf', 0x12,
                'c60600488d8e70040000e800000000'),
            ('empty_leaf_and_clear_three_counters', 0x21,
                'c6867004000000488d8ee0080000ba10000000e800000000488d8ef0080000ba10000000e80000000048'
                '8d8e00090000ba10000000e800000000'),
            ('clear_input_metadata_and_full_retained_output', 0x5b,
                '0f57f60f29b610090000488d8e20090000ba00040000e800000000'),
            ('clear_current_shape_budget_next_shape_identity', 0x76,
                '48c786400d000000000000c686510d000000488d8e380d0000ba08000000e80000000048c786480d0000'
                '00000000c686520d0000000f11b6280d0000'),
            ('restore_frame_without_resetting_sequence_or_phase', 0xb2,
                '0f287424204883c4305ec3'),
        ],
        'branches': [
        ],
    },
    'quarantine': {
        'size': 196,
        'regions': [
            ('save_original_owner_and_drop_root', 0x0,
                '564883ec300f297424204889cee800000000'),
            ('empty_root_then_drop_leaf', 0x12,
                'c60600488d8e70040000e800000000'),
            ('empty_leaf_and_clear_three_counters', 0x21,
                'c6867004000000488d8ee0080000ba10000000e800000000488d8ef0080000ba10000000e80000000048'
                '8d8e00090000ba10000000e800000000'),
            ('clear_input_metadata_and_full_retained_output', 0x5b,
                '0f57f60f29b610090000488d8e20090000ba00040000e800000000'),
            ('clear_shapes_budget_identity', 0x76,
                '48c786400d000000000000c686510d000000488d8e380d0000ba08000000e80000000048c786480d0000'
                '00000000c686520d0000000f11b6280d0000'),
            ('publish_quarantined_then_return', 0xb2,
                'c686500d0000070f287424204883c4305ec3'),
        ],
        'branches': [
        ],
    },
    'guard': {
        'size': 205,
        'regions': [
            ('skip_cleanup_only_when_guard_complete', 0x0,
                '564883ec300f29742420f6c2010f85af000000'),
            ('original_owner_root_and_leaf_drop', 0x13,
                '4889cee800000000c60600488d8e70040000e800000000'),
            ('leaf_tag_and_three_counter_clears', 0x2a,
                'c6867004000000488d8ee0080000ba10000000e800000000488d8ef0080000ba10000000e80000000048'
                '8d8e00090000ba10000000e800000000'),
            ('input_metadata_and_full_output_clear', 0x64,
                '0f57f60f29b610090000488d8e20090000ba00040000e800000000'),
            ('current_next_shape_budget_identity_clear', 0x7f,
                '48c786400d000000000000c686510d000000488d8e380d0000ba08000000e80000000048c786480d0000'
                '00000000c686520d0000000f11b6280d0000'),
            ('publish_quarantined', 0xbb,
                'c686500d000007'),
            ('restore_frame', 0xc2,
                '0f287424204883c4305ec3'),
        ],
        'branches': [
            (0xd, '0f85', 0xc2),
        ],
    },
    'cancel': {
        'size': 252,
        'regions': [
            ('six_phase_call_with_sequence_and_original_owner', 0x0,
                '564883ec500f297424404989d04889ca48c7442420060000004c8d0d00000000488d4c2430e800000000'),
            ('return_admission_error_without_reset', 0x2a,
                '807c243802750a0fb6442430e9b6000000'),
            ('admitted_original_owner_root_and_leaf_drop', 0x3b,
                '488b7424304889f1e800000000c60600488d8e70040000e800000000'),
            ('leaf_tag_and_counter_clears', 0x57,
                'c6867004000000488d8ee0080000ba10000000e800000000488d8ef0080000ba10000000e80000000048'
                '8d8e00090000ba10000000e800000000'),
            ('input_metadata_and_full_output_clear', 0x91,
                '0f57f60f29b610090000488d8e20090000ba00040000e800000000'),
            ('current_next_shape_budget_identity_clear', 0xac,
                '48c786400d000000000000c686510d000000488d8e380d0000ba08000000e80000000048c786480d0000'
                '00000000c686520d0000000f11b6280d0000'),
            ('publish_empty_only_after_cleanup', 0xe8,
                'c686500d000000b0ff'),
            ('restore_frame', 0xf1,
                '0f287424404883c4505ec3'),
        ],
        'branches': [
            (0x2f, '75', 0x3b),
            (0x36, 'e9', 0xf1),
        ],
    },
    'operation': {
        'size': 565,
        'regions': [
            ('owner_phase_and_first_allowed_value', 0x0,
                '56574883ec380f297424204889ce0fb682500d00004138010f85d5000000'),
            ('checked_nonwrapping_exact_next_sequence', 0x1e,
                '488b82200d000048ffc00f95c14c39c00f94c084c10f8582010000'),
            ('sequence_error_root_and_leaf_drop', 0x39,
                '4889d14889d7e800000000c60700488d8f70040000e800000000'),
            ('sequence_error_counters_clear', 0x53,
                'c6877004000000488d8fe0080000ba10000000e800000000488d8ff0080000ba10000000e80000000048'
                '8d8f00090000ba10000000e800000000'),
            ('sequence_error_full_output_clear', 0x8d,
                '0f57f60f29b710090000488d8f20090000ba00040000e800000000'),
            ('sequence_error_shape_budget_identity_clear', 0xa8,
                '48c787400d000000000000c687510d000000488d8f380d0000ba08000000e80000000048c787480d0000'
                '00000000c687520d0000000f11b7280d0000'),
            ('quarantine_and_sequence_error', 0xe4,
                'c687500d000007c60601e9c4000000'),
            ('single_allowed_value_guard', 0xf3,
                '488b4c24704883f9010f85d4000000'),
            ('phase_error_root_and_leaf_drop', 0x102,
                '4889d14889d7e800000000c60700488d8f70040000e800000000'),
            ('phase_error_counters_clear', 0x11c,
                'c6877004000000488d8fe0080000ba10000000e800000000488d8ff0080000ba10000000e80000000048'
                '8d8f00090000ba10000000e800000000'),
            ('phase_error_full_output_clear', 0x156,
                '0f57f60f29b710090000488d8f20090000ba00040000e800000000'),
            ('phase_error_shape_budget_identity_clear', 0x171,
                '48c787400d000000000000c687510d000000488d8f380d0000ba08000000e80000000048c787480d0000'
                '00000000c687520d0000000f11b7280d0000'),
            ('quarantine_and_phase_error', 0x1ad,
                'c687500d000007c60602b002eb0c'),
            ('commit_sequence_and_return_armed_original_owner', 0x1bb,
                '4c8982200d000048891631c0'),
            ('result_tag_and_return', 0x1c7,
                '8846080f287424204883c4385f5ec3'),
            ('length_guarded_remaining_five_allowed_values', 0x1d6,
                '413841010f843efeffff4883f9020f8418ffffff413841020f842afeffff4883f9030f8404ffffff4138'
                '41030f8416feffff4883f9040f84f0feffff413841040f8402feffff4883f9050f84dcfeffff41384105'
                '0f84eefdffffe9cdfeffff'),
        ],
        'branches': [
            (0x18, '0f85', 0xf3),
            (0x33, '0f85', 0x1bb),
            (0xee, 'e9', 0x1b7),
            (0xfc, '0f85', 0x1d6),
            (0x1b9, 'eb', 0x1c7),
            (0x1da, '0f84', 0x1e),
            (0x1e4, '0f84', 0x102),
            (0x1ee, '0f84', 0x1e),
            (0x1f8, '0f84', 0x102),
            (0x202, '0f84', 0x1e),
            (0x20c, '0f84', 0x102),
            (0x216, '0f84', 0x1e),
            (0x220, '0f84', 0x102),
            (0x22a, '0f84', 0x1e),
            (0x230, 'e9', 0x102),
        ],
    },
}
