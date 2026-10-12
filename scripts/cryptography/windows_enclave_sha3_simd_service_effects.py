"""Last executor service-call footprints; physical lifetimes remain separate."""
import windows_enclave_sha3_simd_transfer_effects as previous
import windows_enclave_sha3_simd_control_effects as control
import windows_enclave_sha3_simd_copy_effects as copies
import windows_enclave_sha3_simd_loop_effects as loop
w,o,s,life=previous.w,previous.o,previous.s,previous.life
SLOTS=tuple(sorted(set(previous.previous.SLOTS)|set(copies.SLOTS)|{912,928}))
POLLS={502,1059,1266,1393}
AUTHORITY={43,1289}
SITES=POLLS|AUTHORITY|{1129,1399,1466}


def unique_definition(code,states,site,key,definition,line):
    s.require(states[site][key]=={definition} and code[definition]==line,
        'single complete original service argument/target definition')


def callbacks(code,states,origins,n,caller,construction):
    s.require(caller['callbacks']['context_is_zero_sized'] and not caller['callbacks']['host_callback_accepted'] and
        set(caller['callbacks']['slots'])=={'24','32'} and construction['callback_is_pure_compiled_tag_check'] and
        construction['public_callback_not_host_supplied'],
        'replayed internal false callbacks and immutable compiled-tag callback')
    for site,load in ((502,497),(1059,1057),(1266,1264),(1393,1391)):
        target='*%rax' if site==502 else '*912(%rbp)'
        s.require(code[site]=='callq '+target,'actual internal cancellation call operand')
        unique_definition(code,states,site,'rcx',load,'movq (%r12), %rcx' if site==502 else 'movq 928(%rbp), %rcx')
        unique_definition(code,states,site,928,500,'movq %rcx, 928(%rbp)')
        unique_definition(code,states,500,'rcx',497,'movq (%r12), %rcx')
        unique_definition(code,states,site,912,501,'movq %rax, 912(%rbp)')
        unique_definition(code,states,501,'rax',499,'movq 32(%rax), %rax')
        unique_definition(code,states,499,'rax',498,'movq 8(%r12), %rax')
        s.require(origins[497]['r12']==origins[498]['r12']=={'control'},'original control supplies both target and context')
        if site==502:unique_definition(code,states,site,'rax',499,'movq 32(%rax), %rax')
    for site,load in ((43,40),(1289,1287)):
        s.require(code[site]=='callq *8(%rax)' and origins[site]['rax']=={'authority'} and
            origins[load]['rax']=={'authority'},'same original authority supplies callback and kernel tag')
        unique_definition(code,states,site,'rcx',load,'movzbl 17(%rax), %ecx')
    return [dict(site=site,target=caller['callbacks']['slots']['32'],read=[],write=[]) for site in sorted(POLLS)]+[
        dict(site=site,target=construction['compiled_callback'],read=[],write=[],
            caller_reads_authority=[[8,16],[17,18]]) for site in sorted(AUTHORITY)]


def session_call(code,edges,states,origins,n,session):
    s.require(code[1129]=='callq '+n['session'] and session['functions']['session']==n['session'] and
        session['full_scratch_wipe_ranges']==[[0,800],[800,960],[960,1120],[1120,1920]],
        'actual previously reviewed four-lane session and complete scratch range')
    s.require(origins[1129]['rcx']=={'authority'},'session receives original executor authority')
    s.require(loop.roots(code,states,1129,'rdx',slots=SLOTS)=={2720} and
        loop.roots(code,states,1129,'r8',slots=SLOTS)=={0},
        'session receives original compacted group and CPU scratch')
    s.require(code[1055:1057]==['cmpq $0, (%rdi)','je .B227'] and
        origins[1055]['rdi']=={'executor'},'nonnull original authority guard')
    copies.dominates(edges,(1056,1057),{1129})
    ranges={'scratch':[0,1920],'group':[2720,3520]}
    s.require(ranges['scratch'][1]<=ranges['group'][0] and ranges['group'][1]<=5260,
        'disjoint scratch and group within original workspace')
    return dict(site=1129,target=n['session'],read_roots=dict(authority=[[0,18]],workspace=list(ranges.values())),
        write_roots=dict(authority=[[0,8],[16,17]],workspace=list(ranges.values())),
        group_written_only_after_successful_revalidation=True)


def health_call(code,origins,n,terminal):
    s.require(code[1399]=='callq '+n['check'] and origins[1399]['rcx']=={'executor'} and
        terminal['executor_check']==n['check'] and terminal['final_poll_and_actual_executor_health_before_output_validation'],
        'reviewed final health helper on original executor')
    return dict(site=1399,target=n['check'],read_roots=dict(executor=[[0,8],[16,17]],authority=[[8,18]]),
        write_roots=dict(authority=[[16,17]]))


def panic_terminal(code,bodies,n):
    s.require(code[1465:1468]==['vzeroupper','callq '+n['panic'],'ud2'],
        'overflow terminal cannot return into output publication')
    fmt=s.one(bodies,r'^[^?].*panicking9panic_fmt$')
    s.require(life.code(bodies[n['panic']])==previous.output.digest.L(f'''pushq %rbp|subq $32, %rsp|
        leaq 32(%rsp), %rbp|callq {fmt}|ud2'''), 'complete no-argument overflow panic wrapper')
    return dict(site=1466,target=n['panic'],normal_return=False,forwarded_to=fmt,
        abort_runtime_and_fatal_exit_cleanup_qualified=False)


def inspect(bodies,assembly,caller,construction,session,terminal,prior):
    n=o.reconcile.terminal.shape.names(bodies)|{'session':session['functions']['session']}
    code=life.code(bodies[n['executor']]);edges,_=o.reconcile.graph(code,assembly)
    spans,_,_=o.frame_writes(code,edges);states=w.definitions(code,edges,spans,SLOTS)
    origins=control.analyse(code,edges,spans)
    s.require(caller['functions']['executor']==terminal['function']==prior['function']==n['executor'] and
        not prior['pending_non_frame_store_sites'] and set(prior['pending_callee_effect_sites'])==SITES,
        'exact final nine executor call sites and replayed store/output contracts')
    effects=callbacks(code,states,origins,n,caller,construction)
    effects += [session_call(code,edges,states,origins,n,session),health_call(code,origins,n,terminal)]
    terminal_effect=panic_terminal(code,bodies,n)
    return dict(function=n['executor'],call_sites=sorted(SITES),service_effects=effects,
        nonreturning_terminal=terminal_effect,original_service_targets_and_arguments_checked=True,
        all_executor_call_site_footprints_assigned=True,pending_callee_effect_sites=[],pending_non_frame_store_sites=[],
        authority_control_payload_placement_and_allocation_lifetimes_required=True,
        shared_runtime_and_win64_abi_required=True,
        allocation_lifetimes_and_private_frame_exception_cleanup_qualified=False)
