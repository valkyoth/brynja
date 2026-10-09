"""Entry/admission and normal failure retirement; inner/unwind work separate."""
import windows_enclave_sha3_simd_reject_shape as shape
import windows_enclave_sha3_simd_reject_model as model
import windows_enclave_sha3_simd_output_ir as provenance
life,s=shape.life,shape.s


def inspect(bodies,ir,caller,output,framing):
    n=shape.digest.helpers.names(bodies)|{'validate':s.one(bodies,r'hardened_batch6output8validate$')}
    s.require(caller['functions']['executor']==n['executor'] and
        caller['helpers']['geometry']==shape.digest.helpers.geometry() and
        caller['callbacks']['context_is_zero_sized'] and
        not caller['callbacks']['host_callback_accepted'] and
        output['output_borrow_pointer_ir_uses_closed'] and
        framing['public_framing_fields_and_output_offsets_checked'],
        'replayed rejection caller/output/framing prerequisites')
    code=life.code(bodies[n['executor']])
    gate,cleanup=shape.eligibility(),shape.cleanup(n)
    s.require(len(code)==1676 and code[:69]==shape.entry(n) and
        code[454:510]==gate and code[510:588]==cleanup,
        'complete saved entry/eligibility/normal-failure regions')
    lines=provenance.graph.function(ir,n['executor'])
    provenance.sequence(lines,'''%.val.i.i = load ptr, ptr %6, align 8
%90 = getelementptr inbounds nuw i8, ptr %6, i64 8
%.val1.i.i = load ptr, ptr %90, align 8
%91 = getelementptr inbounds nuw i8, ptr %.val1.i.i, i64 32
%92 = load ptr, ptr %91, align 8
%93 = invoke noundef zeroext i1 %92(ptr noundef nonnull %.val.i.i) #27
to label %.noexc.i unwind label %798
.noexc.i:
br i1 %93, label %.loopexit538.thread, label %94''')
    # This first invocation joins the caller's closed, internal vtable. Later
    # polls/charges and exceptional guard composition are separate obligations.
    actual=code[454:588]
    for error in model.VALID_ERRORS:model.check(actual,n,error=error,outputs=(None,0,1,256))
    for case in ({},{'total':1025},{'eligible':(1,1,1,0)},{'cancel':True}):
        model.check(actual,n,**case)
    return dict(function=n['executor'],entry_region=[0,69],eligibility_region=[454,510],
        normal_rejection_region=[510,588],
        first_cancel_callback_slot=32,first_cancel_callback_uses_original_control_context=True,
        first_cancel_callback_is_internal_false_leaf=True,
        required_simd_counts_exactly_eligible_slots=True,
        routine_error_tags_preserving_reuse=sorted(model.ROUTINE),
        normal_rejection_clears_workspace_staging_then_destinations=True,
        result_error_discriminant_offset=129,
        saved_region_oracle_cases=len(model.VALID_ERRORS)+4,
        secret_input_pages_mapped_in_model=False,
        all_error_predecessor_pointer_lifetimes_qualified=False,
        later_callback_and_inner_engine_paths_qualified=False,
        exception_and_private_frame_erasure_qualified=False)
