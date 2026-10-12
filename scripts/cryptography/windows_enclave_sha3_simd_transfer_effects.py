"""Output descriptor capture, validator, copy and rejection-clear footprints."""
import itertools
import windows_enclave_sha3_simd_source_effects as previous
import windows_enclave_sha3_simd_output as output
import windows_enclave_sha3_simd_transfer_model as model
import windows_enclave_sha3_simd_frame_effects as frame
w,o,s,life=previous.w,previous.o,previous.s,previous.life
SITES={54,563,570,573,1430,1547,1559,1571,1583}
COPIES=(1547,1559,1571,1583)


def capture(code,edges,spans):
    s.require(code[17:21]==output.digest.L('''vmovups (%r9), %ymm0|vmovups 32(%r9), %ymm1|
        vmovups %ymm0, 592(%rbp)|vmovups %ymm1, 624(%rbp)'''),
        'byte-exact original output descriptor capture')
    for at in range(1,21):
        s.require({p for p,ds in edges.items() if at in ds}=={at-1},'no entry bypasses original descriptor capture')
    for at in range(17):
        op,args=o.instruction(code[at])
        s.require(op!='callq' and not (args and o.ALIASES.get(args[-1])=='r9' and op in o.WRITE),
            'original incoming output-array argument retained until capture')
    overlaps={at:span for at,span in spans.items() if span[0]<656 and 592<span[1]}
    s.require(overlaps=={19:(592,624),20:(624,656)},'no later direct overwrite of captured descriptor bytes')


def validate_calls(code,states,n):
    for site in (54,1430):
        s.require(code[site]=='callq '+n['validate'],'same fully reviewed readonly validator')
        previous.input_root(code,states,site,'rcx')
        s.require(frame.frame_origins(code,states,site,'rdx')=={592},'validator reads original 64-byte descriptor capture')


def region_entries(code,edges):
    # Retain every branch in the complete reviewed prepare/copy and rejection
    # regions. Global predecessors cannot jump past pointer or size guards.
    for lo,hi,entries in ((1482,1586,{1482}),(549,574,{549})):
        for at in range(lo,hi):
            outside={p for p,ds in edges.items() if at in ds and not lo<=p<hi}
            # The adjacent invariant-error label is intentionally reachable
            # from another executor region; it exits before copying anything.
            s.require(not outside or at in entries|({1493} if lo==1482 else set()),
                'no external entry past output/clear guards')


def placement(caller,frame_effects):
    geometry=output.digest.geometry();s.require(caller['geometry']==geometry and
        frame_effects['child_frame_origin_in_parent']==-1200,'same replayed caller and child allocations')
    objects=geometry['executor_entry_objects'];staging=objects['staging'];scratch=objects['scratch']
    slots=geometry['destination_slots']
    s.require(staging==[5200,6224] and scratch==[7120,8144] and
        slots==[[7120+256*i,7376+256*i] for i in range(4)],'four disjoint caller output slots')
    for lane,(lo,hi) in enumerate(slots):
        s.require(scratch[0]<=lo<hi<=scratch[1] and hi-lo==256 and
            all(hi<=a or b<=lo for key,(a,b) in objects.items() if key!='scratch') and
            all(hi<=a or b<=lo for j,(a,b) in enumerate(slots) if j!=lane),'output slot excludes every other live caller object')
    return dict(staging=staging,destinations=slots,metadata_parent_ranges=[[-544,-512],[-512,-508]])


def inspect(bodies,assembly,caller,checked_output,frame_effects,prior):
    n=checked_output['functions']|{'zero':life.ZERO};code=life.code(bodies[n['executor']])
    s.require(caller['functions']['executor']==prior['function']==frame_effects['function']==n['executor'] and
        checked_output['output_borrow_pointer_ir_uses_closed'] and
        checked_output['all_four_source_extents_preflight_before_first_copy'] and
        caller['helpers']['copy_wrapper_checks_equal_lengths'] and
        frame_effects['bounded_frame_effects_exclude_live_pointer_cells_and_caller_objects'] and
        not prior['pending_non_frame_store_sites'],'replayed descriptor IR, copy helper and frame-write contracts')
    edges,_=o.reconcile.graph(code,assembly);spans,_,_=o.frame_writes(code,edges)
    states=w.definitions(code,edges,spans,previous.SLOTS)
    capture(code,edges,spans);validate_calls(code,states,n);region_entries(code,edges)
    s.require(code[1482:1542]==output.prepare_shape() and code[1542:1602]==output.copy_shape(n),
        'complete guarded copy sequence, not an invented model path')
    original=o.analyse(code,edges,spans)
    s.require(original[1482]['r12']=={'staging'},'all predecessors retain original staging root')
    # Exact full rejection-region shape is replayed before this checker. Bind
    # its metadata roots independently of the pointer/length loop oracle.
    s.require(code[544:549]==output.digest.L('''leaq 656(%rbp), %rdi|leaq 688(%rbp), %rbx|
        movb %r13b, (%rsi)|movb $-1, 129(%rsi)|xorl %esi, %esi'''),
        'original metadata regions and zero starting descriptor offset')
    rows=[]
    for present in itertools.product((False,True),repeat=4):
        for lengths in ((0,1,255,256),(256,)*4,(0,)*4):
            events=model.copies(code,n,present,lengths);model.clears(code,n,present,lengths)
            rows.append(dict(present=list(present),lengths=list(lengths),copy_events=events))
    pending=set(prior['pending_callee_effect_sites'])
    s.require(SITES<=pending and len(pending-SITES)==9,'exact remaining output-call population')
    return dict(function=n['executor'],call_sites=sorted(SITES),physical_envelopes=placement(caller,frame_effects),
        replay_cases=rows,original_output_descriptors_captured_and_directly_preserved=True,
        validators_read_original_inputs_and_descriptors=True,
        copies_preserve_destination_lane_matching_lengths_and_contiguous_staging=True,
        rejection_clears_only_present_nonempty_destinations_and_metadata=True,
        pending_non_frame_store_sites=[],pending_callee_effect_sites=sorted(pending-SITES),
        other_callee_alias_effects_allocation_lifetimes_and_win64_abi_required=True,
        allocation_lifetimes_and_private_frame_exception_cleanup_qualified=False)
