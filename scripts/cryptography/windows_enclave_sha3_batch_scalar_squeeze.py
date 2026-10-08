"""Scalar terminal squeezing: bounded copies, cursor progress and owned clears.

Actual full body plus fresh helper replay and the placed outer caller are
required. This is not start construction, arbitrary entry or frame erasure.
"""
import windows_enclave_sha3_batch_scalar_squeeze_shapes as shapes
import windows_enclave_sha3_batch_scalar_xof as xof

life,s,L=xof.life,xof.s,xof.L


def names(bodies):
    return {k:s.one(bodies,p) for k,p in (
        ('squeeze','State7squeeze$'),('wipe','OwnerKj48_E4wipe'),
        ('drop','drop_glue.*5state5State'),('copy','18copy_secret_region$'),
        ('bytes','10copy_bytes$'),('mask','22apply_secret_byte_mask$'),
        ('permute','11permutation6native6scalar$'))}


def check_shape(bodies):
    n=names(bodies);expected=shapes.shape(n)
    s.require(life.code(bodies[n['squeeze']])==expected,'complete scalar terminal squeeze body')
    return n,expected


def staging_returns(lines,n):
    """Conservative normal CFG: branches include failed/partial copy writes.

Every copy_bytes call can dirty stack staging. Copy_secret_region is also
treated conservatively as dirtying it even when its destination is elsewhere.
Only the exact final full volatile clear discharges that state, not memset.
"""
    labels={l[:-1]:i for i,l in enumerate(lines) if l.endswith(':')}
    s.require(len(labels)==sum(l.endswith(':') for l in lines),'unique squeeze CFG labels')
    pending=[(0,False,False)];seen=set();returns=set();copies=set();clears=set()
    while pending:
        at,live,dirty=pending.pop()
        if (at,live,dirty) in seen:continue
        seen.add((at,live,dirty));s.require(at<len(lines),'bounded scalar squeeze CFG')
        line=lines[at]
        if line=='callq memset':
            s.require(not dirty,'initialization is not secret erasure');live=True
        elif line in ('callq '+n['copy'],'callq '+n['bytes']):
            s.require(live,'copies require live stack staging');dirty=True;copies.add(at)
        elif line=='callq '+life.ZERO and lines[max(0,at-2):at]==L(
                'leaq 120(%rsp), %rcx|movl $1024, %edx'):
            s.require(live,'clear requires live staging');dirty=False;clears.add(at)
        if line=='retq':
            s.require(live and not dirty,'normal return clears all possibly written staging')
            returns.add(at);continue
        if line.startswith('j'):
            op,target=line.split(maxsplit=1);s.require(target in labels,'local scalar squeeze edge')
            pending.append((labels[target],live,dirty))
            if op in ('jmp','jmpq'):continue
        pending.append((at+1,live,dirty))
    s.require(len(returns)==len(clears)==1 and len(copies)==10,'nonvacuous squeeze copy/clear/return paths')
    return dict(copy_sites=len(copies),normal_return_sites=1,full_volatile_clear_sites=1,
        failed_copy_treated_as_partial_write=True,normal_returns_clear_staging=True,exception_edges_qualified=False)


def geometry(rate,cursor,length,last):
    """Metadata-only model of the checked bulk/inner/partial loops.

No cryptographic oracle claim: actual permutation/copy/mask semantics come
from the separately replayed helpers. Triples are (output offset,cursor,size).
"""
    s.require(type(rate) is int and rate in (136,168) and type(cursor) is int and
        0<=cursor<=rate,'valid initialized squeeze rate/cursor')
    prefix,tail=xof.input_partition(length,last)
    initialized=0;remaining=prefix;permutations=0;copies=[];chunks=[]
    while remaining:
        chunk=min(rate,remaining);filled=0
        while filled<chunk:
            if cursor==rate:permutations+=1;cursor=0
            take=min(rate-cursor,chunk-filled)
            s.require(take>0 and filled+take<=rate and cursor+take<=rate,'progress and bounded inner regions')
            copies.append((initialized+filled,cursor,take));filled+=take;cursor+=take
        end=initialized+chunk
        s.require(end<1<<64 and end<=length,'checked initialized prefix before stack copy')
        chunks.append((initialized,end));initialized=end;remaining=max(0,remaining-chunk)
    mask=None
    if tail is not None:
        if cursor==rate:permutations+=1;cursor=0
        copies.append((initialized,cursor,1));cursor+=1
        # Emitted saturating 8-last and unsigned byte shift; canonical last is 1..7.
        shift=max(0,8-last);mask=(255>>(shift&31)) if shift<8 else 0
        s.require(initialized+1<=length,'bounded partial byte before stack copy');initialized+=1
    s.require(initialized==length,'exact terminal initialized output extent')
    return dict(copies=copies,chunks=chunks,cursor=cursor,permutations=permutations,
        prefix_bytes=prefix,initialized=initialized,mask=mask)


def inspect(bodies,ir,prior,caller,storage):
    s.require(prior['prior_semantics_replayed'],'squeeze requires freshly replayed lower semantics')
    s.require(caller['prefix_width_sum_and_end_both_checked'] and caller['output_capacity']==1024 and
        caller['output_base']==1344 and caller['state_span']==[16,1152] and
        caller['outer_rejection_clears_entire_output_and_quarantines'] and
        caller['success_destroys_state_and_returns_to_collecting'],'actual bounded/disjoint caller and cleanup')
    n,lines=check_shape(bodies)
    s.require(n['squeeze']==caller['functions']['squeeze'],'actual caller squeeze target')
    s.require(storage['state_pointer_inside_owner'] and storage['state_destructor']['function']==n['drop'] and
        storage['state_destructor']['typed_payload_cleanup_composed'] and
        prior['state_destructor_rebinding']['function']==n['drop'] and
        prior['state_destructor_rebinding']['exact_code_references_extent_and_renamed_abi'],
        'actual placed state and replayed renamed typed destructor')
    helpers=[n[k] for k in ('wipe','copy','bytes','mask','permute')]+[life.ZERO]
    s.require(set(helpers)<=set(prior['exact_body_reference_extent_and_abi']),'six exact replayed squeeze helpers')
    for name in helpers:
        abi=life.reuse.abi(ir,name)
        s.require('nounwind' in abi and life.reuse.accelerated.digest(abi.encode())==
            prior['exact_body_reference_extent_and_abi'][name]['abi_sha256'],'squeeze helper ABI matches fresh replay')
    abi=life.reuse.abi(ir,n['squeeze'])
    s.require('(ptr noalias nofree noundef nonnull align 16 dereferenceable(1136) %0, '
        'ptr noalias nofree noundef nonnull %1, i64 noundef range(i64 0, -9223372036854775808) %2, '
        'i8 noundef %3)' in abi and 'nounwind' in abi,'actual squeeze exclusive state/output and nonunwinding ABI')
    s.require('nounwind' in life.reuse.abi(ir,n['drop']),'actual typed destructor is nonunwinding')
    spans=[[18,34],[50,250],[586,754],[754,794],[794,834],[834,1034],[1041,1042]]
    s.require(all(2<=a<b<=1042 for a,b in spans) and all(a[1]<=b[0] for a,b in zip(spans,spans[1:])),
        'counter, lanes, staging, permutation scratch and cursor are disjoint within owner')
    locals_=[[40,48],[48,56],[56,64],[64,72],[72,80],[80,96],[96,104],[104,112],[112,120],[120,1144]]
    s.require(all(32<=a<b<=1144 for a,b in locals_) and all(a[1]<=b[0] for a,b in zip(locals_,locals_[1:])),
        'separate home, spill/metadata, staging and saved-register extents')
    return dict(function=n['squeeze'],instructions_and_labels_checked=len(lines),helpers=helpers,
        destructor=n['drop'],normal_cfg=staging_returns(lines,n),frame_bytes=1144,saved_register_bytes=64,
        stack_regions=locals_,staging_span=[120,1144],destination_pointer_spill=104,
        state_extent=1136,nested_owner_span=[2,1042],owner_regions=spans,
        required_lifecycle=1,working_lifecycle=2,success_state_tag=0,rates=[168,136],
        canonical_output_and_1024_bound_before_work=True,output_counter_uses_checked_u128_complete_bytes=True,
        bulk_cursor_and_initialized_prefix_bounded=True,permutation_only_at_rate_boundary=True,
        permutation_scratch_cleared_before_resume=True,internal_stage_clear_bytes=168,
        partial_byte_low_bits_only=True,owner_wiped_before_destination_copy=True,
        source_is_disjoint_stack_staging=True,success_requires_full_output_copy=True,
        empty_copy_has_zero_length_and_nonnull_source=True,normal_paths_composed=True,
        retained_output_not_exported_here=True,valid_initialized_state_required=True,
        state_construction_qualified=False,runtime_memset_qualification_pending=True,
        private_frame_erasure_qualified=False,all_unwind_paths_qualified=False,whole_image_qualified=False)
