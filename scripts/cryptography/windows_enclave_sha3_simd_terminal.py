"""Saved normal terminal composition; full lifetimes/exception frames stay open."""
import windows_enclave_sha3_simd_terminal_shape as shape
import windows_enclave_sha3_simd_terminal_model as model
life,s=shape.life,shape.s


def inspect(bodies,ir,caller,output,rejection,scalar):
    n=shape.names(bodies);code=life.code(bodies[n['executor']])
    s.require(caller['functions']['executor']==n['executor'] and
        caller['helpers']['geometry']==shape.reject.digest.helpers.geometry() and
        caller['helpers']['copy_wrapper_checks_equal_lengths'] and
        caller['callbacks']['context_is_zero_sized'] and not caller['callbacks']['host_callback_accepted'] and
        output['output_borrow_pointer_ir_uses_closed'] and
        output['all_four_source_extents_preflight_before_first_copy'] and
        rejection['normal_rejection_clears_workspace_staging_then_destinations'] and
        scalar['whole_scalar_owner_wiped_before_checked_report_increment'] and
        scalar['absorption_continuation_pointers_restored'],
        'replayed terminal metadata/copy/cleanup and scalar continuation prerequisites')
    s.require(len(code)==1676 and code[1343:1425]==shape.bridges(n) and
        code[1425:1482]==shape.preflight(n) and code[1596:1676]==shape.report(n),
        'complete final health/error/size/report regions')
    s.require(life.code(bodies[n['check']])==shape.check_shape(),'complete executor final health helper')
    abi=f'define internal fastcc noundef range(i8 -1, 5) i8 @{n["check"]}('+(
        'ptr noundef nonnull readonly align 8 captures(none) %0) unnamed_addr { uwtable '+
        shape.reject.digest.target()+' } personality ptr @__CxxFrameHandler3 {')
    s.require(life.reuse.abi(ir,n['check'])==abi,'final health helper actual readonly-pointer ABI')
    # Normal-only composition. The callback unwind/funclet state and complete
    # incoming register/pointer lifetimes require the remaining frame review.
    error_code=code[1343:1425]+shape.rejection_entry(n)+code[510:588]
    for entry in ('.B207','.B208','.B210','.B211','.B212','.B213','.B214',
        '.B215','.B216','.B217','.B218','.B224','.B225'):
        model.bridge(error_code,n,entry)
    for case in ({},dict(authority=False),dict(cancel=True),dict(healthy=False),
        dict(revalidate=False),dict(quarantined=True)):model.final_health(error_code,n,**case)
    for case in ({},dict(tags=(255,255,255,255)),dict(bits=(8192,1,0,0)),dict(kernel=255)):
        model.preflight(code[1425:1482],n,**case)
        model.report(code[1596:1676],n,**case)
    return dict(function=n['executor'],bridge_region=[1343,1425],size_admission_region=[1425,1482],
        report_region=[1596,1676],executor_check=n['check'],executor_check_instruction_positions=len(shape.check_shape()),
        final_poll_and_actual_executor_health_before_output_validation=True,
        ordinary_rejection_retains_reuse_and_integrity_failure_quarantines=True,
        shared_error_wipes_workspace_staging_and_present_destinations=True,
        successful_report_after_workspace_and_staging_wipe=True,
        final_output_bytes_recomputed_and_bounded_by_1024=True,
        vector_call_counter_preserved_across_mixed_width_serialization=True,
        result_fields=dict(descriptors=[0,64],output_bits=[64,96],identities=[96,100],
            vector_calls=[104,112],vector_blocks=[112,120],scalar_blocks=[120,128],accelerated_mask=128,kernel=129),
        copied_padding_region=[100,104],untouched_result_padding=[130,136],
        report_padding_not_claimed_initialized_or_erased=True,
        bridge_predecessor_register_contracts_assumed=True,
        callback_must_preserve_live_authority_and_abi=True,
        final_copy_region_review_reused_not_interpreted_here=True,
        complete_machine_pointer_lifetimes_and_nonoverlap_qualified=False,
        private_frame_and_exception_cleanup_qualified=False)
