"""Saved executor FH3 cleanup, guard captures and synchronous unwind ordering.

OS dispatch, fatal exits and physical stack retirement are not qualified here.
"""
import re
import windows_enclave_sha3_simd_service_effects as previous
import windows_enclave_sha3_simd_digest_shape as shape
w,o,s,life=previous.w,previous.o,previous.s,previous.life
THROWS={43:2,502:0,1059:0,1129:0,1266:0,1289:1,1393:0,1399:0}
IPS=[('.Lfunc_begin30',-1),('.Ltmp28',2),('.Ltmp29',-1),('.Ltmp30',0),
    ('.Ltmp38',1),('.Ltmp40',0),('.Ltmp43',-1)]


def names(bodies):
    n=o.reconcile.terminal.shape.names(bodies)
    n['operation_drop']=s.one(bodies,r'^_RINv.*hardened_batch9OperationE')
    n['output_drop']=s.one(bodies,r'^_RNvXs_.*SecretBatchOutput.*Drop4drop$')
    return n


def operation_shape(n):
    return shape.L(f'''pushq %rsi|subq $32, %rsp|movq %rcx, %rsi|movq 8(%rcx), %rcx|
        callq {n['workspace_wipe']}|movq 24(%rsi), %rdx|testq %rdx, %rdx|je .B2|
        movq 16(%rsi), %rcx|callq {life.ZERO}|.B2:|cmpb $0, 32(%rsi)|jne .B5|
        movq (%rsi), %rax|movb $1, 16(%rax)|movq (%rax), %rax|testq %rax, %rax|
        je .B5|movb $0, 16(%rax)|.B5:|addq $32, %rsp|popq %rsi|retq''')


def handlers(bodies,n):
    found={};expected={}
    for number,slot in ((281,952),(282,968),(283,None)):
        name=s.one(bodies,r'^\?dtor\$'+str(number)+r'@\?0\?'+re.escape(n['executor'])+r'@')
        found[number]=name
        code=[f'.B{number}:','movq %rdx, 16(%rsp)']+['pushq %'+r for r in shape.SAVES]+[
            'subq $40, %rsp','leaq 128(%rdx), %rbp']
        if slot is not None:code+=['movq '+str(slot)+'(%rbp), %rax','movb $0, 16(%rax)']
        else:code+=shape.L(f'''leaq 440(%rbp), %rcx|callq {n['operation_drop']}|
            leaq 592(%rbp), %rcx|callq {n['output_drop']}|nop''')
        code+=['addq $40, %rsp']+['popq %'+r for r in reversed(shape.SAVES)]+['retq']
        s.require(life.code(bodies[name])==code,'complete executor cleanup funclet')
        expected[name]=code
    return found,expected


def tables(assembly,n,h):
    prefix={p:p+n['executor'] for p in ('$cppxdata$','$stateUnwindMap$','$ip2state$')}
    states=[(-1,283),(0,281),(0,282)]
    expected={prefix['$cppxdata$']:['429065506','3',prefix['$stateUnwindMap$']+'@IMGREL',
        '0','0','7',prefix['$ip2state$']+'@IMGREL','1120','0','1'],
        prefix['$stateUnwindMap$']:[v for parent,handler in states for v in (str(parent),'"'+h[handler]+'"@IMGREL')],
        prefix['$ip2state$']:[v for label,state in IPS for v in (label+'@IMGREL',str(state))]}
    for label,want in expected.items():
        rows=re.findall(r'^'+re.escape(label)+r':\n((?:\s*\.long[^\n]*\n)+)',assembly,re.M)
        s.require(len(rows)==1 and [line.strip().split(None,1)[1] for line in rows[0].splitlines()]==want,
            'exact executor FH3 state, handler order and frame displacement')
    return expected


def call_states(body,code):
    # Read IP labels from the actual body, not the separately normalized code.
    # Map each marker using its complete actual suffix. This preserves labels
    # that precede flag-preserving moves rather than immediately preceding CALL.
    markers={}
    for label,_ in IPS:
        token=label+':'
        s.require(body.count(token)==1,'unique executor instruction-state label')
        suffix=life.code('partial:\n'+body.split(token,1)[1])
        position=len(code)-len(suffix)
        s.require(code[position:]==suffix,'state label maps to exact normalized body suffix')
        markers[label]=position
    transitions=[(markers[label],state) for label,state in IPS]
    s.require(transitions==sorted(transitions),'FH3 IP states follow actual instruction order')
    actual={at:next(state for pos,state in reversed(transitions) if pos<=at) for at in THROWS}
    s.require(actual==THROWS,'every synchronous throwing service call has its required cleanup state')
    return dict(markers=markers,call_states={str(k):v for k,v in actual.items()})


def guard_lifetimes(code,edges,spans,states,origins):
    original=o.analyse(code,edges,spans)
    for site in THROWS:
        s.require(original[site][448]=={'workspace'} and original[site][456]=={'staging'} and
            origins[site][440]=={'executor'},'live operation guard retains all original allocation roots at every throw')
        s.require(states[site][464]=={25} and code[25]=='movq $1024, 464(%rbp)' and
            states[site][472]=={26} and code[26]=='movb $0, 472(%rbp)',
            'guard retains complete staging extent and armed quarantine at every throw')
    for site,slot in ((43,968),(1289,952)):
        s.require(origins[site][slot]=={'authority'},'cleanup state retains original authority rather than reused lane index')
    guard_writes={at:span for at,span in spans.items() if span[0]<473 and 440<span[1]}
    s.require(guard_writes=={22:(440,448),23:(448,456),24:(456,464),25:(464,472),26:(472,473),1481:(472,473)},
        'only initial guard capture and post-last-throw disarm directly write guard fields')
    return dict(operation=[440,473],output=[592,696],armed_throw_sites=sorted(THROWS),disarm=1481)


def health_cleanup(bodies,assembly,n):
    name=s.one(bodies,r'^\?dtor\$4@\?0\?'+re.escape(n['check'])+r'@')
    expected=shape.L('''.B4:|movq %rdx, 16(%rsp)|pushq %rbp|subq $32, %rsp|
        leaq 48(%rdx), %rbp|movq -16(%rbp), %rax|movb $0, 16(%rax)|
        addq $32, %rsp|popq %rbp|retq''')
    s.require(life.code(bodies[name])==expected,'final health unwind quarantines original authority')
    prefix={p:p+n['check'] for p in ('$cppxdata$','$stateUnwindMap$','$ip2state$')}
    metadata={prefix['$cppxdata$']:['429065506','1',prefix['$stateUnwindMap$']+'@IMGREL',
        '0','0','3',prefix['$ip2state$']+'@IMGREL','40','0','1'],
        prefix['$stateUnwindMap$']:['-1','"'+name+'"@IMGREL'],
        prefix['$ip2state$']:['.Lfunc_begin31@IMGREL','-1','.Ltmp44@IMGREL','0','.Ltmp45@IMGREL','-1']}
    for label,want in metadata.items():
        rows=re.findall(r'^'+re.escape(label)+r':\n((?:\s*\.long[^\n]*\n)+)',assembly,re.M)
        s.require(len(rows)==1 and [v.strip().split(None,1)[1] for v in rows[0].splitlines()]==want,
            'complete final health FH3 states and frame displacement')
    body=bodies[n['check']];code=life.code(body)
    markers={}
    for label in ('.Lfunc_begin31','.Ltmp44','.Ltmp45'):
        s.require(body.count(label+':')==1,'unique final health cleanup-state marker')
        suffix=life.code('partial:\n'+body.split(label+':',1)[1]);at=len(code)-len(suffix)
        s.require(code[at:]==suffix,'health IP state maps to actual instruction suffix');markers[label]=at
    s.require(markers=={'.Lfunc_begin31':0,'.Ltmp44':14,'.Ltmp45':17} and
        code[13:17]==['movzbl 17(%rdx), %ecx','movq %rdx, -16(%rbp)','callq *8(%rdx)','nop'],
        'same authority saved before the only protected callback, at its actual IP state')
    return dict(function=n['check'],funclet=name,handler_code=expected,expected_tables=metadata,
        instruction_markers=markers,authority_health_byte_cleared_on_invoked_unwind=True,
        actual_callback_is_internal_nounwind=True)


def inspect(bodies,assembly,caller,services):
    n=names(bodies);code=life.code(bodies[n['executor']])
    s.require(caller['functions']['executor']==services['function']==n['executor'] and
        services['all_executor_call_site_footprints_assigned'] and not services['pending_callee_effect_sites'] and
        caller['helpers']['output_drop_clears_four_present_nonempty_destinations'] and
        caller['helpers']['output_drop_clears_output_bits_and_identities_not_slice_descriptors'],
        'replayed complete normal call effects and output/workspace destructors')
    s.require(life.code(bodies[n['operation_drop']])==operation_shape(n),'complete operation-guard destructor')
    h,shapes=handlers(bodies,n);metadata=tables(assembly,n,h);mapping=call_states(bodies[n['executor']],code)
    health=health_cleanup(bodies,assembly,n)
    edges,_=o.reconcile.graph(code,assembly);spans,_,_=o.frame_writes(code,edges)
    states=w.definitions(code,edges,spans,tuple(sorted(set(previous.SLOTS)|{464,472})))
    origins=previous.control.analyse(code,edges,spans)
    guards=guard_lifetimes(code,edges,spans,states,origins)
    return dict(function=n['executor'],operation_destructor=n['operation_drop'],funclets=h,
        instruction_positions={k:len(v) for k,v in shapes.items()},expected_tables=metadata,
        actual_ip_mapping=mapping,guard_captures=guards,final_health_cleanup=health,
        ordered_handler_chains={str(at):[h[282 if state==2 else 281],h[283]] if state else [h[283]] for at,state in THROWS.items()},
        workspace_then_staging_then_quarantine_then_outputs_cleared=True,
        original_guard_fields_live_at_all_synchronous_throw_sites=True,
        exception_callback_targets_are_nounwind_in_this_closed_image=True,
        os_unwind_dispatch_shared_runtime_and_physical_allocation_lifetimes_required=True,
        asynchronous_fault_and_fatal_abort_cleanup_claimed=False,
        complete_private_frame_erasure_qualified=False)
