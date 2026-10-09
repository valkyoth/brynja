"""Saved vector caller composition; scalar fallback and report serialization open."""
import windows_enclave_sha3_simd_vector_shape as shape
import windows_enclave_sha3_simd_vector_model as model
life,s=shape.life,shape.s


def inspect(bodies,caller,session,rejection,absorption):
    n=shape.names(bodies)
    s.require(caller['functions']['executor']==n['executor'] and
        caller['helpers']['copy_wrapper_checks_equal_lengths'] and
        caller['helpers']['geometry']==shape.absorb.squeeze.shape.digest.helpers.geometry() and
        caller['callbacks']['context_is_zero_sized'] and not caller['callbacks']['host_callback_accepted'] and
        session['functions']['session']==n['session'] and
        session['caller_output_after_revalidation_and_checked_counter'] and
        session['success_error_and_callback_unwind_scratch_clearing_composed'] and
        rejection['first_cancel_callback_uses_original_control_context'] and
        rejection['normal_rejection_clears_workspace_staging_then_destinations'] and
        absorption['cursor_block_count_and_absorbing_to_ready_transition_checked'],
        'replayed vector copy/session/poll/absorption prerequisites')
    code=life.code(bodies[n['executor']])
    s.require(len(code)==1676 and code[992:1253]==shape.shape(n),'complete vector grouping/charge/transfer region')
    # The synthetic callee effect exercises byte provenance only. The real
    # session/transpose/kernel must separately pass its own saved-code review.
    samples=[{},dict(cancel=True),dict(budget=3),dict(charged=model.MASK),
        dict(counter=model.MASK),dict(vector_calls=model.MASK),dict(blocks=model.MASK),
        dict(ready=(0,0,0,0)),dict(ready=(0,1,1,1)),dict(eligible=(1,0,1,1)),dict(kernel=1)]
    for case in samples:model.check(code[992:1253],n,**case)
    return dict(function=n['executor'],region=[992,1253],instruction_positions=261,
        selected_indices='ascending ready==1 and eligible==1, complete width only',
        source_state_region=[1920,2720],group_region=[2720,3520],cpu_scratch_region=[0,1920],
        state_stride=200,group_wipe_bytes=800,checked_control_budget_offset=16,
        checked_control_used_offset=24,control_charge_committed_before_state_copy=True,
        session_uses_original_authority_group_and_cpu_scratch=True,
        session_counter_must_increment_exactly_once=True,
        scatter_returns_each_group_lane_to_original_slot=True,
        accelerated_slot_mask_and_vector_call_block_counters_checked=True,
        completed_group_readiness_cleared_before_rescan=True,
        saved_region_oracle_cases=len(samples),synthetic_permutation_is_not_crypto_evidence=True,
        two_lane_selection_tested_but_no_arm_kernel_execution_claimed=True,
        scalar_fallback_and_final_report_serialization_qualified=False,
        all_incoming_pointer_lifetimes_and_storage_nonoverlap_qualified=False,
        rejection_edge_and_exception_private_frame_cleanup_composed=False)
