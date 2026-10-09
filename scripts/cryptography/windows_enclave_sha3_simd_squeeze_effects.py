"""Original squeeze-copy/mask footprints; descriptor lifetimes stay open."""
import windows_enclave_sha3_simd_copy_effects as copies
import windows_enclave_sha3_simd_squeeze as squeeze
w,o,s,life,loop=copies.w,copies.o,copies.s,copies.life,copies.loop
m=loop.model
SITES={961,985}
MASK=(1<<64)-1


def admitted_window(bits,written,start,rate):
    """Integer meaning of the emitted overflow/minimum/empty-path checks.

    The public bit count is arbitrary u64, not restricted to test sample sizes.
    Admission makes the subsequent address arithmetic bounded by real objects.
    """
    s.require(all(type(v) is int and 0<=v<=MASK for v in (bits,written,start)) and
        type(rate) is int and rate in squeeze.model.RATES,'u64 metadata and validated identity rate')
    total=(bits>>3)+int(bool(bits&7))
    if written>total:return None
    take=min(total-written,rate)
    if written==total:return dict(copy=False)
    offset=start+written;end=offset+take
    if offset>MASK or end>MASK or end>=1025:return None
    s.require(0<take<=168 and 0<=offset<end<=1024,'nonempty bounded staging window')
    return dict(copy=True,offset=offset,take=take,end=end,
        mask_index=end-1 if bits&7 and written+take==total else None)


def flow(code,edges,n):
    expected=squeeze.shape.squeeze(n)
    s.require(code[920:992]==expected,'complete emitted checked squeeze-copy and final-byte-mask slice')
    incoming={(p,v) for p,ds in edges.items() for v in ds if p not in range(920,992) and v in range(920,992)}
    s.require(incoming=={(647,920)},'one original lane-loop entry into the squeeze region')
    for at in range(921,992):
        s.require({p for p,ds in edges.items() if at in ds}=={at-1},'no entry past overflow, empty or mask guards')
    for at,label in ((931,'.B207:'),(937,'.B88:'),(941,'.B207:'),(948,'.B207:'),
        (963,'.B207:'),(973,'.B88:'),(976,'.B89:')):
        s.require(edges[at]==[code.index(label),at+1],'actual guard rejection bypasses copy or mask')
    # Both copy and mask must cross these nonempty/overflow success edges.
    for cut in ((931,932),(937,938),(941,942),(948,949)):
        copies.dominates(edges,cut,SITES)
    for cut in ((963,964),(973,974),(976,977)):
        copies.dominates(edges,cut,{985})


def origins(code,edges,spans,states):
    loop.loop_entry(code,edges,states)
    direct=o.analyse(code,edges,spans)
    s.require(direct[920]['rbx']=={'workspace'} and direct[953]['r15']=={'staging'} and
        direct[985]['rbx']=={'workspace'},'original workspace/staging roots across every normal predecessor')
    s.require(loop.roots(code,states,955,960,slots=(*m.SLOTS,960))=={1920},
        'original state array under the source-lane multiplication')
    lanes=[]
    for lane in range(4):
        observed=set()
        def inspect(at,before):
            if at in (920,954):
                s.require(before['r9']==m.one('number',lane),'bounded original lane survives all restores before state addressing')
                observed.add(at)
        result=m.check_lane(code,edges,spans,lane,inspect)
        s.require(observed=={920,954},'nonvacuous squeeze-entry and copy-source lane observations')
        lanes.append(dict(lane=lane,reachable_positions=result['reachable_positions'],observed_sites=sorted(observed)))
    return lanes


def separation(geometry):
    objects=geometry['executor_entry_objects'];wa,wb=objects['workspace'];sa,sb=objects['staging']
    s.require(wb-wa==5260 and sb-sa==1024,'original workspace and staging allocation extents')
    copies.clear.separate([dict(site=961,root='staging',write_spans=[[0,1024]]),
        dict(site=985,root='staging',write_spans=[[0,1024]])],geometry)
    loop.separation([[1920+200*lane,1920+200*lane+168] for lane in range(4)],geometry)
    effects=[]
    for lane in range(4):
        source=[wa+1920+200*lane,wa+1920+200*lane+168]
        s.require(source[1]<=sa or sb<=source[0],'all admitted state reads and staging writes are physically disjoint')
        effects.append(dict(lane=lane,source_envelope=source,destination_envelope=[sa,sb]))
    return effects


def inspect(bodies,assembly,caller,framing,squeezing,previous):
    n=squeeze.names(bodies);code=life.code(bodies[n['executor']])
    s.require(caller['functions']['executor']==framing['function']==squeezing['function']==previous['function']==n['executor'] and
        caller['helpers']['functions']['copy']==n['copy'] and caller['helpers']['copy_wrapper_checks_equal_lengths'] and
        caller['helpers']['copy_leaf_length_limit']==1024 and
        framing['public_framing_fields_and_output_offsets_checked'] and
        squeezing['linked_rates']==list(squeeze.model.RATES) and
        squeezing['mask']['functions']['mask']==n['mask'] and
        squeezing['copy_lengths_equal_and_at_most_rate'] and squeezing['final_partial_byte_uses_low_bit_mask'] and
        squeezing['restored_lane_index_input_control_and_frame_pointers_checked'] and
        previous['original_pointers_lengths_and_saved_index_restores_checked'] and not previous['pending_non_frame_store_sites'],
        'replayed framing, validated rate table, copy/mask helper and previous footprint contracts')
    geometry=o.reconcile.terminal.shape.reject.digest.geometry()
    s.require(caller['geometry']==geometry,'same original caller allocations')
    edges,_=o.reconcile.graph(code,assembly);spans,_,_=o.frame_writes(code,edges)
    states=w.definitions(code,edges,spans,(*m.SLOTS,960))
    flow(code,edges,n);lanes=origins(code,edges,spans,states);physical=separation(geometry)
    pending=set(previous['pending_callee_effect_sites'])
    s.require(SITES<=pending and len(pending-SITES)==22,'exact remaining squeeze-effect population')
    return dict(function=n['executor'],call_sites=sorted(SITES),lane_provenance=lanes,
        physical_copy_envelopes=physical,copy_length_range=[1,168],staging_capacity=1024,
        mask_writes_last_byte_of_successful_nonempty_copy=True,
        staging_integer_bounds_checked_before_payload_pointer_addition=True,
        original_state_staging_roots_and_lane_induction_checked=True,
        overflow_empty_copy_failure_and_nonfinal_mask_guards_dominate=True,
        requires_receiver_validated_identity_and_live_descriptor_metadata=True,
        pending_non_frame_store_sites=[],pending_callee_effect_sites=sorted(pending-SITES),
        other_callee_memory_effects_and_win64_nonvolatile_abi_required=True,
        allocation_lifetimes_and_private_frame_exception_cleanup_qualified=False)
