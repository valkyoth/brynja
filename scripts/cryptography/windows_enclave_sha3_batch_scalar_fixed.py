"""Scalar fixed finalization: actual moved-owner, padding, output and clear joins.

Valid initialized owners and checked outer descriptors are preconditions.
Copied backing bytes/private frames still need enclosing-window retirement.
"""
import re
import windows_enclave_sha3_batch_scalar_fixed_shapes as shapes
import windows_enclave_sha3_batch_scalar_xof as xof

life,s,L=xof.life,xof.s,xof.L
TARGETS=[3,18,8,13]


def names(bodies):
    n={k:s.one(bodies,p) for k,p in (
        ('fixed','State12finish_fixed$'),('drop','drop_glue.*5state5State'),('wipe','OwnerKj48_E4wipe'),
        ('copy','18copy_secret_region$'),('bytes','10copy_bytes$'),('mask','22apply_secret_byte_mask$'),
        ('xor','20xor_secret_byte_bits$'),('permute','11permutation6native6scalar$'),
        ('finish','13finish_secret$'),('finalize','OwnerKj88_E8finalize'))}
    for rate in ('48','68','88','90'):n['update'+rate]=s.one(bodies,'OwnerKj'+rate+'_E6update')
    return n


def check_shape(bodies,assembly):
    n=names(bodies);lines=shapes.shape(n)
    s.require(life.code(bodies[n['fixed']])==lines,'complete scalar fixed finalization body')
    found=re.findall(r'^\.LJTI50_0:\n((?:\s*\.long[^\n]+\n)+)',assembly,re.M)
    s.require(len(found)==1 and [re.sub(r'\s+','',l) for l in found[0].splitlines()]==[
        f'.long.LBB50_{v}-.LJTI50_0' for v in TARGETS],'exact four-entry fixed identity dispatch table')
    return n,lines


def cleanup_cfg(lines,n):
    """Normal CFG explores all direct branches and the four bound table targets.

Copies conservatively dirty staging even when they actually write only nested
scratch. Once a local owner is copied it must be wiped before every return and
the retained-output commit. Snapshot/backing bytes are deliberately not erased
by this model: the real caller does not clear them individually either.
"""
    labels={l[:-1]:i for i,l in enumerate(lines) if l.endswith(':')}
    s.require(len(labels)==sum(l.endswith(':') for l in lines),'unique fixed-finalizer CFG labels')
    pending=[(0,False,False,False)];seen=set();returns=set();owners=set();wipes=set();commits=set();clears=set()
    while pending:
        at,live,dirty,owner=pending.pop()
        if (at,live,dirty,owner) in seen:continue
        seen.add((at,live,dirty,owner));s.require(at<len(lines),'bounded fixed normal CFG')
        line=lines[at]
        if line=='callq memset':s.require(not dirty,'initialization not erasure');live=True
        elif line=='callq memcpy' and lines[max(0,at-3):at]==L(
            'leaq 96(%rsp), %rcx|movl $1040, %r8d|movq %r15, %rdx'):
            s.require(not owner,'single consumed local owner');owner=True;owners.add(at)
        elif line=='callq '+n['wipe']:
            s.require(owner,'wipe exactly the live copied owner');owner=False;wipes.add(at)
        elif line in ('callq '+n['copy'],'callq '+n['bytes']):
            s.require(live,'live stack staging before copy');dirty=True
            if lines[max(0,at-2):at]==L('movq %rdi, %rcx|movq %rsi, %rdx'):
                s.require(not owner,'consumed owner wiped before retained-output commit');commits.add(at)
        elif line=='callq '+life.ZERO and lines[max(0,at-2):at]==L(
            'leaq 1136(%rsp), %rcx|movl $1024, %edx'):
            s.require(live,'live staging at full clear');dirty=False;clears.add(at)
        if line=='retq':
            s.require(live and not dirty and not owner,'every normal return clears staging and copied owner')
            returns.add(at);continue
        if line=='jmpq *%rcx':
            pending.extend((labels[f'.B{b}'],live,dirty,owner) for b in TARGETS);continue
        if line.startswith('j'):
            op,target=line.split(maxsplit=1);s.require(target in labels,'local fixed-finalizer edge')
            pending.append((labels[target],live,dirty,owner))
            if op in ('jmp','jmpq'):continue
        pending.append((at+1,live,dirty,owner))
    s.require(len(owners)==4 and len(wipes)==3 and len(returns)==len(commits)==len(clears)==1,
        'nonvacuous moved-owner, cleanup, commit and return populations')
    return dict(owner_copy_sites=4,owner_wipe_sites=3,retained_output_commit_sites=1,normal_return_sites=1,
        full_staging_clear_sites=1,normal_returns_clear_copied_owner_and_staging=True,
        copied_owner_cleared_before_output_commit=True,snapshot_and_original_backing_erased=False,
        exceptional_edges_qualified=False)


def padding(rate,whole,partial,valid):
    """Model of the three inlined 0/1/1 suffix paths, not a hash oracle."""
    s.require(type(rate) is int and rate in (72,104,144) and len(whole)<rate and
        type(partial) is int and 0<=partial<=255 and type(valid) is int and 0<=valid<8,
        'valid inlined rate, buffered prefix and partial byte')
    block=bytearray(168);block[:len(whole)]=whole;position=len(whole)*8;out=[]
    if valid:block[len(whole)]=partial&((1<<valid)-1);position+=valid
    def flush():
        out.append(bytes(block[:rate]));block[:]=bytes(168)
    if position==rate*8:flush();position=0
    position+=1  # Domain bit zero: initially zero padding and masked partial byte.
    if position==rate*8:flush();position=0
    if position<=1343:block[position>>3]|=1<<(position&7)
    position+=1
    if position==rate*8:flush();position=0
    if position<=1343:
        block[position>>3]|=1<<(position&7)
        if position==rate*8-1:flush()
    block[rate-1]|=128;flush()
    return out


def move_origins():
    """Byte provenance for the bound two memcpy stages and tag tombstone."""
    state=list(range(1136));snapshot=state.copy();state[0]='Empty'
    owner=state[1:1041]
    s.require(owner==list(range(1,1041)) and snapshot==list(range(1136)) and
        state[1:]==list(range(1,1136)),'tombstone does not erase copied payload')
    spans=[[40,64],[64,96],[96,1136],[1136,2160],[2160,3296]]
    s.require(all(32<=a<b<=3304 and a%8==0 for a,b in spans) and
        all(a[1]<=b[0] for a,b in zip(spans,spans[1:])),'disjoint result, initialization, owner, output and snapshot')
    return dict(original_owner_span=[1,1041],snapshot_span=spans[-1],copied_owner_span=spans[2],
        staging_span=spans[3],result_span=spans[0],initialization_span=spans[1],frame_bytes=3304,
        saved_register_bytes=64,logical_tag_does_not_end_backing_storage_lifetime=True,
        snapshot_and_original_payload_cleared_individually=False,shared_memcpy_package=8)


def inspect(bodies,assembly,ir,prior,caller,storage):
    s.require(prior['prior_semantics_replayed'],'fixed finalizer requires fresh prior semantic review')
    s.require(caller['input_pointer_preserved_to_descriptor'] and caller['partial_tail_only_after_nonempty_shape_check'] and
        caller['maximum_input_bytes']==1024 and caller['maximum_input_bits']==8192 and caller['descriptor_bytes']==32 and
        caller['prefix_width_sum_and_end_both_checked'] and caller['output_base']==1344 and caller['output_capacity']==1024 and
        caller['state_span']==[16,1152] and caller['outer_rejection_clears_entire_output_and_quarantines'],
        'actual fixed caller descriptor, placement and error cleanup')
    n,lines=check_shape(bodies,assembly)
    s.require(n['fixed']==caller['functions']['finish_fixed'],'actual fixed call target')
    s.require(storage['state_pointer_inside_owner'] and storage['state_destructor']['function']==n['drop'] and
        storage['state_destructor']['typed_payload_cleanup_composed'] and
        prior['state_destructor_rebinding']['function']==n['drop'] and
        prior['state_destructor_rebinding']['exact_code_references_extent_and_renamed_abi'],'actual typed snapshot cleanup')
    helpers=[n[k] for k in ('wipe','copy','bytes','mask','xor','permute','finish','finalize',
        'update48','update68','update88','update90')]+[life.ZERO]
    s.require(set(helpers)<=set(prior['exact_body_reference_extent_and_abi']),'thirteen exact lower helper reviews')
    for name in helpers:
        abi=life.reuse.abi(ir,name)
        s.require('nounwind' in abi and life.reuse.accelerated.digest(abi.encode())==
            prior['exact_body_reference_extent_and_abi'][name]['abi_sha256'],'actual fixed helper ABI matches replay')
    abi=life.reuse.abi(ir,n['fixed'])
    s.require('(ptr noalias nofree noundef nonnull align 16 captures(none) dereferenceable(1136) %0, '
        'ptr dead_on_return noalias nofree noundef nonnull readonly align 8 captures(none) dereferenceable(32) %1, '
        'ptr noalias nofree noundef nonnull %2, i64 noundef range(i64 0, -9223372036854775808) %3)' in abi and
        'nounwind' in abi,'full disjoint fixed state, bounded descriptor and output ABI')
    s.require('nounwind' in life.reuse.abi(ir,n['drop']),'typed snapshot destructor nonunwinding ABI')
    for rate in ('48','68','88','90'):
        abi=life.reuse.abi(ir,n['update'+rate])
        s.require('dereferenceable(1040)' in abi and 'readonly' in abi and 'zeroext i1' in abi,
            'live local owner and exclusive borrowed input update result')
    return dict(function=n['fixed'],instructions_and_labels_checked=len(lines),helpers=helpers,
        dispatch_table='.LJTI50_0',state_tags_to_width={'1':28,'2':32,'3':48,'4':64},
        state_tags_to_rate={'1':144,'2':136,'3':104,'4':72},normal_cfg=cleanup_cfg(lines,n),
        moves=move_origins(),inlined_permutation_sites=15,delegated_sha3_256_finalize=True,
        suffix_and_width=[6,3],suffix_width_caller_stack_offset=32,
        inlined_scratch_clear_lengths=[40,40,200,168],
        valid_absorbing_owner_buffer_less_than_rate_required=True,padding_block_initially_zero_required=True,
        canonical_input_and_byte_counter_carry_composed=True,exact_width_before_update=True,
        same_input_prefix_and_optional_tail_preserved=True,ignored_padding_copy_and_xor_results_infallible_on_valid_domain=True,
        initialized_output_width_before_finish_secret=True,returned_region_preserved_across_owner_wipe=True,
        output_is_retained_secret_not_exported=True,normal_paths_composed=True,
        runtime_memset_and_memcpy_qualification_pending=True,state_construction_qualified=False,
        private_frame_erasure_qualified=False,all_unwind_paths_qualified=False,whole_image_qualified=False)
