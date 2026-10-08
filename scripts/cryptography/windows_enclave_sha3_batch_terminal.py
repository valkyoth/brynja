"""Changed AVX2 terminal helpers: bounded staging and normal-return cleanup.

Requires the actual checked batch caller and replayed helpers. This does not
qualify arbitrary entry, construction, caller spills, or exceptional exits.
"""
import windows_enclave_sha3_batch_terminal_shapes as shapes
import windows_enclave_sha3_batch_copy as copies

life,L=shapes.life,shapes.L
s=life.s


def names(bodies):
    n={k:s.one(bodies,p) for k,p in (
        ('fixed','State12finish_fixed$'),('squeeze','State7squeeze$'),
        ('wipe','Memory4wipe$'),('engine_finish','Engine6finish$'),('read','Engine4read$'),
        ('clear','Core5clear$'),('drop','drop_glue.*4Core'),('mask','22apply_secret_byte_mask$'))}
    n['copy']=copies.WRAPPER
    return n


def check_shapes(bodies):
    n=names(bodies);expected={n[k]:getattr(shapes,k)(n) for k in ('fixed','squeeze')}
    for name,want in expected.items():
        s.require(life.code(bodies[name])==want,'complete terminal State body, checks and cleanup')
    return n,expected


def staging_returns(lines,n):
    """Conservative normal CFG, including read failures with partial writes.

All branches are explored, not just successful traces. This is a supplemental
data-flow check; full shapes bind definitions/arguments and transfer targets.
Calls returning normally are modeled here; no exception-edge claim is made.
"""
    labels={l[:-1]:i for i,l in enumerate(lines) if l.endswith(':')}
    s.require(len(labels)==sum(l.endswith(':') for l in lines),'unique terminal CFG labels')
    pending=[(0,False,False)];seen=set();returns=set();reads=set();clears=set()
    while pending:
        at,live,dirty=pending.pop()
        if (at,live,dirty) in seen:continue
        seen.add((at,live,dirty));s.require(at<len(lines),'bounded normal terminal CFG')
        line=lines[at]
        if line=='callq memset':
            s.require(not dirty,'no ordinary overwrite in place of secret staging erasure')
            live=True
        elif line=='callq '+n['read']:
            s.require(live,'read requires initialized live scratch');dirty=True;reads.add(at)
        elif line=='callq '+life.ZERO and lines[max(0,at-2):at]==shapes.wipe(n)[:2]:
            s.require(live,'full staging clear requires initialized scratch');dirty=False;clears.add(at)
        elif line=='callq '+n['copy']:
            s.require(live and dirty,'commit uses live read staging, not caller storage')
        if line=='retq':
            s.require(not dirty,'every normal return clears possibly written staging')
            returns.add(at);continue
        if line.startswith('j'):
            op,target=line.split(maxsplit=1);s.require(target in labels,'local terminal CFG edge')
            pending.append((labels[target],live,dirty))
            if op in ('jmp','jmpq'):continue
        pending.append((at+1,live,dirty))
    s.require(len(returns)==len(reads)==1 and len(clears)>=2,'nonvacuous terminal read/return/erase paths')
    return dict(normal_return_sites=len(returns),read_sites=len(reads),full_clear_sites=len(clears),
        all_normal_returns_after_read_clear_staging=True,read_failure_treated_as_partial_write=True,
        exception_edges_qualified=False)


def output_shape(length,last):
    """Emitted squeeze byte predicates and wrapping u64 bit-length check."""
    s.require(type(length) is int and 0<=length<1<<63 and type(last) is int and 0<=last<256,
              'slice length and u8 terminal count')
    if length==0:return last==0
    if length>=1025:return False
    previous=(last-1)&255
    if previous>=8:return False
    return ((7-8*length)&((1<<64)-1))>=last


def inspect(bodies,ir,prior,caller):
    s.require(prior['prior_semantics_replayed'],'terminal helpers require fresh lower review')
    s.require(caller['input_pointer_preserved_to_descriptor'] and caller['prefix_width_sum_and_end_both_checked'] and
        caller['outer_rejection_clears_entire_output_and_quarantines'] and caller['state_span']==[1216,2208] and
        caller['output_base']==0 and caller['output_capacity']==1024,'actual bounded and disjoint terminal caller')
    n,expected=check_shapes(bodies)
    s.require(n['fixed']==caller['functions']['finish_fixed'] and n['squeeze']==caller['functions']['squeeze'],
        'changed helpers must be actual caller targets')
    helpers=[n[k] for k in ('wipe','engine_finish','read','clear','drop','mask')]+[life.ZERO]
    s.require(set(helpers)<=set(prior['exact_body_reference_extent_and_abi']),
        'all internal terminal helpers freshly replayed with exact bodies, references and ABI')
    copy_review=copies.inspect(bodies,ir,prior['changed_abi_requiring_explicit_review'])
    for name in helpers:
        s.require(life.reuse.accelerated.digest(life.reuse.abi(ir,name).encode())==
            prior['exact_body_reference_extent_and_abi'][name]['abi_sha256'],'actual helper ABI still matches replay')
    for name in helpers+[copies.LEAF,copies.WRAPPER]:
        s.require('nounwind' in life.reuse.abi(ir,name),'actual lower helper nonunwinding ABI')
    s.require('dereferenceable(864)' in life.reuse.abi(ir,n['read']) and
        'range(i64 0, 1025)' in life.reuse.abi(ir,n['read']),'engine live extent and staged read bound')
    s.require('dereferenceable(234)' in life.reuse.abi(ir,n['wipe']),'nested memory wipe extent')
    s.require('dereferenceable(1)' in life.reuse.abi(ir,n['mask']),'mask live byte extent')
    # Actual spans: home [0,32), unused gap [32,40), scratch [40,1064).
    # Saved incoming registers start at 1064, never in the staging buffer.
    return dict(functions=n,instructions_and_labels={k:len(v) for k,v in expected.items()},
        lower_helpers_replayed_and_exact=helpers,widened_copy_helpers=copy_review['functions'],
        normal_cfg={k:staging_returns(v,n) for k,v in expected.items()},
        frame_bytes=1064,staging_span=[40,1064],staging_capacity=1024,
        fixed_saved_register_bytes=32,squeeze_saved_register_bytes=48,
        staging_disjoint_from_home_and_saved_registers=True,
        engine_span=[0,864],nested_memory_span=[624,858],state_extent=992,
        fixed_requires_absorbing_phase_and_matching_fixed_width=True,
        squeeze_requires_squeezing_phase_and_canonical_output_shape=True,
        health_epoch_and_kernel_checked_before_work=True,
        descriptor_and_suffix_forwarded_to_finish=True,
        output_pointer_and_equal_bounded_lengths_forwarded_to_copy=True,
        copy_source_is_live_disjoint_stack_staging=True,
        partial_mask_only_on_nonempty_final_staging_byte=True,
        normal_success_clears_core_staging_and_sets_empty=True,
        lower_rejection_poisoned_core_composed_with_outer_quarantine=True,
        output_is_retained_secret_not_exported=True,normal_terminal_paths_composed=True,
        terminal_true_specialization_only=True,valid_initialized_state_required=True,
        runtime_memset_qualification_pending=True,private_frame_erasure_qualified=False,
        all_unwind_paths_qualified=False,whole_image_qualified=False)
