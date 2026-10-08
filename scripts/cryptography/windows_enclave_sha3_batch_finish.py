"""Final-message/output caller review, with changed lower finalizers left open."""
import re
import windows_enclave_sha3_batch_finish_shapes as shapes
import windows_enclave_sha3_batch_chunks as chunks
import windows_enclave_sha3_batch_terminal as terminal
import windows_enclave_sha3_batch_scalar_xof as scalar_xof

life,s,L=chunks.life,chunks.s,chunks.L


def names(bodies,lane):
    n={k:s.one(bodies,('Owner' if k in ('finish','operation') else 'State')+str(len(k))+k+'$')
       for k in ('finish','operation','finish_fixed','finish_xof','squeeze')}
    n['mask']=s.one(bodies,r'24secret_byte_mask_is_zero$')
    if lane=='avx2':
        n.update(glue=s.one(bodies,r'drop_glue.*9OperationE'),
                 funclet=s.one(bodies,r'^\?dtor\$51@.*Owner6finish@'))
    return n


def check_shapes(bodies,lane):
    s.require(lane in life.LAYOUT,'sequential finish lane');n=names(bodies,lane)
    expected={n['finish']:getattr(shapes,lane)(n)}
    if lane=='avx2':
        expected[n['funclet']]=[l.replace('.B22:','.B51:') for l in chunks.funclet(n)]
        expected[n['glue']]=life.guard('avx2')
    for name,want in expected.items():
        s.require(life.code(bodies[name])==want,'complete final-message caller/cleanup contract')
    return n,expected


def unwind(assembly,bodies,n):
    name=n['finish'];prefix={p:p+name for p in ('$cppxdata$','$stateUnwindMap$','$ip2state$')}
    expected={prefix['$cppxdata$']:['429065506','1',prefix['$stateUnwindMap$']+'@IMGREL',
                '0','0','3',prefix['$ip2state$']+'@IMGREL','96','0','1'],
        prefix['$stateUnwindMap$']:['-1','"'+n['funclet']+'"@IMGREL'],
        prefix['$ip2state$']:['.Lfunc_begin46@IMGREL','-1','.Ltmp12@IMGREL','0','.Ltmp15@IMGREL','-1']}
    for label,want in expected.items():
        found=re.findall(r'^'+re.escape(label)+r':\n((?:\s*\.long[^\n]*\n)+)',assembly,re.M)
        s.require(len(found)==1 and [l.strip().split(None,1)[1] for l in found[0].splitlines()]==want,
            'exact finish cleanup header, state and IP map')
    labels=set(re.findall(r'^(\$(?:cppxdata|stateUnwindMap|ip2state)\$'+re.escape(name)+r'[^:\n]*):',assembly,re.M))
    s.require(labels==set(expected),'complete finish cleanup table population')
    lines=s.lines(bodies[name])
    intervals={12:L(f'leaq -48(%rbp), %rdx|movq %r12, %rcx|callq {n["finish_xof"]}|nop'),
        16:L(f'leaq -48(%rbp), %rdx|movq %r15, %r8|movq %rbx, %r9|callq {n["finish_fixed"]}|nop'),
        14:L(f'movq %r12, %rcx|movq %r15, %rdx|movq %rbx, %r8|movl %r14d, %r9d|callq {n["squeeze"]}|nop')}
    positions=[]
    for first,want in intervals.items():
        start,end=f'.Ltmp{first}:',f'.Ltmp{first+1}:'
        s.require(lines.count(start)==lines.count(end)==1,'unique finalizer interval endpoints')
        lo,hi=lines.index(start),lines.index(end)
        s.require(lines[lo+1:hi]==want,'exact protected lower-finalizer arguments and call')
        positions.extend((lo,hi))
    s.require(positions==sorted(positions),'all three finalizer calls inside single live-guard unwind state')
    s.require('.seh_handler __CxxFrameHandler3, @unwind, @except' in lines and
        '.long $cppxdata$'+name+'@IMGREL' in lines,'finish selects actual parent cleanup metadata')
    return dict(expected_tables=expected,protected_calls=[n[k] for k in ('finish_xof','finish_fixed','squeeze')],
        cleanup_funclet=n['funclet'],guard_owner_offset=-16,guard_complete_offset=-1,
        guard_frame_pointer_offset=96,selected_guard_cleanup_composed=True,os_dispatcher_qualified=False)


def arguments(ir,bodies,lane):
    n=names(bodies,lane);chunks.receive.arguments(ir,chunks.receive.names(bodies,lane),lane)
    a=life.LAYOUT[lane];size=1136 if lane=='scalar' else 992
    owner=f'ptr noalias nofree noundef nonnull align {a["align"]}'
    bits='ptr dead_on_return noalias nofree noundef nonnull readonly align 8 captures(none) dereferenceable(32) %1'
    output='ptr noalias nofree noundef nonnull'
    length='i64 noundef range(i64 0, -9223372036854775808)'
    for kind in ('finish_xof','finish_fixed','squeeze'):
        state=owner+(' captures(none)' if lane=='scalar' and kind=='finish_fixed' else '')+f' dereferenceable({size}) %0'
        tail=bits if kind=='finish_xof' else bits+', '+output+' %2, '+length+' %3' if kind=='finish_fixed' else (
            output+' %1, '+length+' %2, i8 noundef %3')
        abi=life.reuse.abi(ir,n[kind])
        s.require('('+state+', '+tail+')' in abi,'actual bounded state, descriptor and disjoint output ABI')
        if lane=='scalar':s.require('nounwind' in abi,'scalar lower-finalizer nonunwinding contract')
    mask=life.reuse.abi(ir,n['mask'])
    s.require('(ptr noalias nofree noundef nonnull readonly captures(address, read_provenance) dereferenceable(1) %0, '
        'i8 noundef range(i8 -128, 0) %1)' in mask and 'nounwind' in mask,'valid one-byte mask argument')
    if lane=='avx2':
        s.require('(ptr nonnull %.0.val, i8 range(i8 0, 2) %.8.val)' in life.reuse.abi(ir,n['glue']),
            'live saved owner and Boolean completion on selected unwind')


def output_span(widths,slot):
    """Public u64 additions/overflow conditions in both checked callers."""
    s.require(len(widths)==8 and all(type(v) is int and 0<=v<1<<64 for v in widths),'eight public u64 widths')
    s.require(type(slot) is int and 0<=slot<1<<64,'u64 slot')
    if slot>7:return None
    mask=(1<<64)-1;start=0
    for width in widths[:slot]:
        new=(start+width)&mask
        if new<start:return None
        start=new
    end=(start+widths[slot])&mask
    if end<start or end>=1025:return None
    return start,end


def inspect(bodies,assembly,ir,lane,prior,storage,transitions,receiver):
    s.require(prior['prior_semantics_replayed'],'finish requires freshly replayed exact helper semantics')
    s.require(storage['state_destructor']['typed_payload_cleanup_composed'] and storage['state_pointer_inside_owner'],
        'finish requires live placed state and typed destruction')
    s.require(transitions['checked_next_sequence'] and transitions['phase_match_before_admission'] and
        transitions['unfinished_guard_clears_and_quarantines'],'finish requires actual phase/sequence and guard cleanup')
    s.require(receiver['payload_pointer_retained_from_worker_buffer'] and receiver['payload_limit']==1024,
        'finish descriptor input must be the bounded copied worker payload')
    n,expected=check_shapes(bodies,lane);arguments(ir,bodies,lane)
    s.require(n['finish']==receiver['functions']['finish'] and n['operation']==transitions['functions']['operation'],
        'actual receive and admission targets for finish')
    helpers=[n['mask'],life.ZERO]+([n['finish_xof']] if lane=='avx2' else [])
    s.require(set(helpers)<=set(prior['exact_body_reference_extent_and_abi']),
        'only actually replayed exact helpers are claimed reused')
    frame,saved,descriptor,regions=(80,56,32,[[32,64],[64,80]]) if lane=='scalar' else (
        104,64,48,[[32,48],[48,80],[80,96],[96,104]])
    s.require(all(32<=lo<hi<=frame for lo,hi in regions) and all(a[1]<=b[0] for a,b in zip(regions,regions[1:])),
        'disjoint descriptor/result/guard/exception regions outside outgoing home space')
    incoming=[176,184] if lane=='scalar' else [208,216]
    s.require(incoming==[frame+saved+40,frame+saved+48] and descriptor%8==0,'incoming final arguments and descriptor alignment')
    a=life.LAYOUT[lane];state=[a['state'],a['state']+(1136 if lane=='scalar' else 992)]
    out=[a['output'],a['output']+1024]
    s.require(state[1]<=out[0] or out[1]<=state[0],'final output is disjoint from the live state allocation')
    result=dict(functions=n,instructions_and_labels={k:len(v) for k,v in expected.items()},
        lower_helpers_replayed_and_exact=helpers,
        lower_finalizer_review_pending=[n[k] for k in ('finish_fixed','finish_xof','squeeze') if not (lane=='avx2' and k=='finish_xof')],
        all_lower_finalizers_composed=False,required_outer_phase=3,active_slot_must_match=True,slot_upper_bound=7,
        input_pointer_preserved_to_descriptor=True,maximum_input_bytes=1024,maximum_input_bits=8192,
        checked_budget_before_dispatch=True,partial_tail_only_after_nonempty_shape_check=True,
        descriptor_bytes=32,descriptor_semantic_bytes=25,descriptor_from_rsp=descriptor,
        frame_bytes=frame,saved_register_bytes=saved,incoming_length_and_bits_from_rsp=incoming,
        disjoint_local_regions=regions,output_base=out[0],output_capacity=1024,state_span=state,
        prefix_width_sum_and_end_both_checked=True,empty_output_may_be_one_past_end=True,
        fixed_identities=[1,2,3,4],xof_identities=[5,6,7,8],lower_success_required_before_completed_bit=True,
        success_destroys_state_and_returns_to_collecting=True,retained_output_not_exported_here=True,
        outer_rejection_clears_entire_output_and_quarantines=True,
        selected_unwind=unwind(assembly,bodies,n) if lane=='avx2' else None,
        valid_initialized_state_and_valid_plan_required=True,start_establishes_state_invariant_qualified=False,
        private_frame_erasure_qualified=False,all_unwind_paths_qualified=False,whole_image_qualified=False)
    result['changed_avx2_terminal_normal_paths']=terminal.inspect(bodies,ir,prior,result) if lane=='avx2' else None
    result['scalar_xof_normal_paths']=scalar_xof.inspect(bodies,ir,prior,result) if lane=='scalar' else None
    if lane=='avx2':
        result['lower_finalizer_review_pending']=[]
        result['all_lower_finalizers_normal_paths_composed']=True
    else:
        result['lower_finalizer_review_pending']=[n[k] for k in ('finish_fixed','squeeze')]
        result['all_lower_finalizers_normal_paths_composed']=False
    # Normal composition is not a proof of every finalizer's exceptional frame erasure.
    return result
