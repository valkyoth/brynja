"""Saved resident caller, bounded result copies and staged cleanup obligations.

This binds the caller, not the executor's returned pointers or private frame.
"""
import re
import windows_enclave_sha3_simd_digest_helpers as helpers
import windows_enclave_sha3_simd_digest_shape as shape
import windows_enclave_sha3_simd_digest_cleanup as cleanup
life,s,L=shape.life,shape.s,shape.L


def target():
    return '"target-cpu"="x86-64" "target-features"="'+helpers.receive.worker.resident.session.zero.SIMD_FEATURES+'"'


def callbacks(bodies,ir,vtables):
    slots={str(offset):s.one(bodies,pattern) for offset,pattern in (
        (24,r'^_RNS.*digests2_.*call_once6vtable'),(32,r'^_RNC.*digests2_'))}
    v=vtables.get(shape.VTABLE,{})
    s.require(v.get('bytes')==40 and v.get('metadata')==[0,0,1] and v.get('slots')==slots,
        'linked internal no-cancellation callback table')
    for offset,name in slots.items():
        s.require(life.code(bodies[name])==L('xorl %eax, %eax|retq'),'internal callback returns false without memory access')
        args='ptr readnone captures(none) %0' if offset=='24' else 'ptr noalias nofree nonnull readonly captures(none) %0'
        expected=f'define internal noundef zeroext i1 @{name}({args}) unnamed_addr '+(
            '{ inlinehint mustprogress nofree norecurse nosync nounwind willreturn memory(none) uwtable '+target()+' } '+
            ('personality ptr @__CxxFrameHandler3 {' if offset=='24' else '{'))
        s.require(life.reuse.abi(ir,name)==expected,'exact internal callback ABI')
    return dict(slots=slots,context_is_zero_sized=True,host_callback_accepted=False,
        executor_callback_invocation_provenance_qualified=False)


def dispatch(asm):
    rows=list(re.finditer(r'^\.LJTI40_0:\n((?:\s*\.long[^\n]*\n)+)',asm,re.M))
    s.require(len(rows)==1,'unique digest identity dispatch table')
    expected=[f'.LBB40_{block}-.LJTI40_0' for block in (11,13,14,12,3,3,4,4)]
    actual=[line.strip().split(None,1)[1] for line in rows[0][1].splitlines()]
    s.require(actual==expected,'exact eight typed identity dispatch destinations')
    return dict(targets=[11,13,14,12,3,3,4,4],requires_receiver_validated_identity=True,
        out_of_range_tag_is_not_independently_rejected=True)


def geometry():
    # All these objects are simultaneously live at executor entry. Initialization
    # temporaries reuse some ranges only before the executor sees secret inputs.
    objects={'workspace':(-64,5260),'staging':(5200,1024),'scratch':(7120,1024),
        'inputs':(8144,448),'result':(8608,136),'control':(8752,32),
        'destinations':(8784,64),'executor':(8888,18),'plan_widths':(8912,32),
        'authority':(8944,8),'owner':(8960,8),'plan_tags':(8970,4),'operation_flag':(8975,1)}
    occupied=set()
    for name,(at,size) in objects.items():
        points=set(range(at,at+size))
        s.require(at>=-96 and at+size<=8984 and not occupied&points,'executor-entry frame object '+name)
        occupied|=points
    slots=[[7120+256*i,7376+256*i] for i in range(4)]
    return dict(executor_entry_objects={k:[a,a+b] for k,(a,b) in objects.items()},
        destination_slots=slots,workspace_and_scratch_erasure_bytes=5260+2048,
        frame_allocation_bytes=9112,complete_frame_erasure_qualified=False,
        executor_returned_sources_equal_destination_slots_qualified=False)


def inspect(bodies,asm,ir,vtables,session,receiver,descriptors):
    n=helpers.names(bodies)
    s.require(receiver['functions']['digest']==n['digest'] and
        receiver['actual_bitstring_inputs_use_local_buffers_not_host_addresses'] and
        receiver['all_twelve_inputs_bounded_to_separate_1024_byte_worker_slots'],
        'receiver-bounded local input prerequisite')
    s.require(descriptors['no_input_pointer_published_to_global_or_heap_storage'],
        'descriptor construction prerequisite')
    helpers.receive.abis(ir,n)
    code=life.code(bodies[n['digest']])
    s.require([line.replace('.LJTI40_0','TABLE') for line in code]==shape.shape(n),
        'complete resident digest caller')
    helper_review=helpers.inspect(bodies,ir,session)
    # The executor ABI is a caller obligation, not evidence of its body semantics.
    args=('ptr dead_on_unwind noalias nofree noundef nonnull writable writeonly align 8 captures(none) dereferenceable(136) %0, '
        'ptr noundef nonnull align 8 %1, ptr noalias nofree noundef nonnull readonly align 8 captures(address_is_null) dereferenceable(448) %2, '
        'ptr dead_on_return noalias nofree noundef nonnull readonly align 8 captures(none) dereferenceable(64) %3, '
        'ptr noalias nofree noundef nonnull dereferenceable(5260) %4, ptr noalias nofree noundef nonnull %5, '
        'ptr noalias nofree noundef nonnull align 8 captures(none) dereferenceable(32) %6')
    s.require(life.reuse.abi(ir,n['executor'])==f'define internal fastcc void @{n["executor"]}({args}) unnamed_addr '+
        '{ uwtable '+target()+' } personality ptr @__CxxFrameHandler3 {','exact executor caller ABI')
    # Direct suffixes are also checked as control flow, separately from exact shape.
    body=bodies[n['digest']]
    paths={start:s.normal_returns(body,start,shape.retire(n)) for start in ('.B46','.B47','.B67')}
    return dict(functions=n,instruction_positions={n['digest']:len(code)},helpers=helper_review,
        cleanup=cleanup.inspect(bodies,asm,n),callbacks=callbacks(bodies,ir,vtables),
        dispatch=dispatch(asm),geometry=geometry(),retirement_suffix_return_paths=paths,
        accepted_report_requires_avx2_nonzero_vector_calls_and_four_accelerated_slots=True,
        result_copies_require_nonnull_sources_and_lengths_at_most_256=True,
        output_dropped_before_final_authority_check=True,
        retained_plan_published_only_after_final_authority_check=True,
        normal_error_retires_initialized_objects_then_quarantines=True,
        executor_body_pointer_lifetimes_and_nonoverlap_qualified=False,
        private_frame_erasure_qualified=False,whole_image_cleanup_qualified=False)
