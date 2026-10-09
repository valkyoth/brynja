"""Saved scalar fallback composition; common exit and frame cleanup stay open."""
import windows_enclave_sha3_simd_scalar_shape as shape
import windows_enclave_sha3_simd_scalar_model as model
life,s=shape.life,shape.s


def inspect(bodies,ir,constants,caller,vector):
    n=shape.names(bodies)
    s.require(caller['functions']['executor']==n['executor'] and
        caller['helpers']['functions']['scalar_wipe']==n['scalar_wipe'] and
        caller['helpers']['copy_wrapper_checks_equal_lengths'] and
        caller['helpers']['geometry']==shape.vector.absorb.squeeze.shape.digest.helpers.geometry() and
        caller['callbacks']['context_is_zero_sized'] and not caller['callbacks']['host_callback_accepted'] and
        vector['function']==n['executor'] and vector['completed_group_readiness_cleared_before_rescan'] and
        vector['scatter_returns_each_group_lane_to_original_slot'],
        'replayed scalar copy/wipe/poll and incoming vector composition')
    code=life.code(bodies[n['executor']])
    s.require(len(code)==1676 and code[1253:1343]==shape.shape(n),'complete scalar fallback region')
    kernel=shape.inspect_kernel(bodies,ir,constants,n)
    cases=[{},dict(authority=False),dict(ready=(0,2,255,0)),dict(cancel_at=2),
        dict(revoke_at=2),dict(budget=1),dict(charged=model.MASK),dict(blocks=model.MASK),
        dict(healthy=False),dict(quarantined=True),dict(copy_failure=2)]
    for case in cases:model.check(code[1253:1343],n,**case)
    return dict(function=n['executor'],region=[1253,1343],instruction_positions=90,scalar_kernel=kernel,
        ready_exactly_one_selected_in_physical_order=True,state_stride=200,
        original_poll_precedes_checked_charge=True,charge_precedes_executor_and_authority_health=True,
        revalidator_receives_current_kernel_and_failure_retains_authority_pointer=True,
        scratch_regions=[[4960,5000],[5000,5040],[5040,5240]],scalar_state_region=[4256,4456],
        owner_region=[4208,5248],scratch_wipes_before_copyback=True,
        whole_scalar_owner_wiped_before_checked_report_increment=True,
        scalar_count_overflow_never_wraps=True,readiness_and_vector_accounting_preserved=True,
        absorption_continuation_pointers_restored=True,saved_region_oracle_cases=len(cases),
        synthetic_permutation_is_not_crypto_evidence=True,
        callback_abi_and_no_mutation_of_live_authority_or_storage_required=True,
        common_exit_rejection_and_final_report_composed=False,
        all_incoming_pointer_lifetimes_and_storage_nonoverlap_qualified=False,
        private_frame_and_exception_cleanup_qualified=False)
