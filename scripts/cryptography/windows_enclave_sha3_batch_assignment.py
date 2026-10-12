"""Finite SHA-3 family assignments after semantic replay, not a stack proof.

Every transient frame is assigned to the existing package-8 window obligation;
this does not assert that typed destruction erases all copies or saved registers.
"""
import re
import windows_enclave_sha2_batch_assignment as common
import windows_enclave_sha3_batch_lifecycle as life
s=common.s
ROLES={
 'worker_transport_buffers':['^RetainedWork$',r'worker7receive$',r'worker7BuffersE',r'Buffers5clear$',r'Header6decode$',r'try_from_fn.*worker7receive'],
 'owner_lifecycle':[r'Owner\d+(?:quarantine|seal|begin|clear|start|cancel|finish|update|operation|setup_chunk|finish_setup|validate_plan)$',
                    r'Operation.*(?:Drop4drop$|E)'],
 'typed_state':[r'state.*StateE',r'State\d+(?:initial|finish_fixed|finish_xof|squeeze|setup_chunk)$',r'HardenedCshake(?:128|256)8new_bits$'],
 'resident':[r'Resident\d+(?:new|cancel|digest|quarantine)$',r'Resident.*Drop4drop$'],
 'authority_callback':[r'15check_authority$',r'keccak_simd5check$',r'Kernel8compiled$',r'Owner6digests2_',r'Executor5check$'],
 'plan_comparison':[r'SlicePartialEq.*equal_same_length'],
 'scalar_and_four_lane_permutation':[r'transfer9transpose',r'3x86.*permute',r'Session13permute_bytes$',r'permutation6native6scalar$'],
 'workspace_output_clearing':[r'workspace9WorkspaceE',r'Workspace4wipe$',r'HardenedFips202Owner.*4wipe',r'SecretBatchOutput.*Drop4drop$'],
 'executor_framing_and_output':[r'Executor13digest_secret$',r'hardened_batch6output8validate$',r'Fips202BitString3new$'],
 'memory_leaves':[r'secret_memory',r'secret_byte_mask'],
 'fatal_terminal':[r'panic_const_add_overflow$',r'panicking9panic_fmt$',r'rust_begin_unwind$']}


def functions(records,review,lane):
    assigned={}
    if lane!='simd':
        prior=review['prior_helpers']
        s.require(prior['prior_semantics_replayed'],'fresh sequential helper semantic replay')
        for name in prior['exact_body_reference_extent_and_abi']:
            s.require(name in records,'reproduced helper belongs to current population')
            assigned[name]='reproduced exact primitive'
    for name in sorted(set(records)-set(assigned)):
        roles=['invoked cleanup funclet'] if name.startswith('?dtor$') else [
            role for role,patterns in ROLES.items() if any(re.search(p,name) for p in patterns)]
        s.require(len(roles)==1,'one explicit SHA-3 reviewed role: '+name+' '+repr(roles))
        assigned[name]=roles[0]
    s.require(set(assigned)==set(records),'complete private family function assignment')
    return assigned


def indirect(review,lane):
    if lane!='simd':return {}
    n=review['simd_digest']['functions'];session=review['simd_session_cleanup']['functions']['session']
    owner=review['simd_owner_admission']['functions']
    return {session:['callq *8(%rbx)']*2,n['executor']:[
        'callq *8(%rax)','callq *%rax','callq *912(%rbp)','callq *912(%rbp)','callq *8(%rax)','callq *912(%rbp)'],
        review['simd_terminal']['executor_check']:['callq *8(%rdx)'],
        owner['check']:['callq *8(%rax)']*2,owner['operation']:['callq *8(%rax)']*2,
        n['digest']:['callq *8(%r8)']*2}


def population(records,bodies,tables,vtables,review,lane):
    expected=indirect(review,lane)
    # Reuse only the family-neutral reachability/table mechanism. The expected
    # target/operand contracts above come from this family's replayed callers.
    return common.population(records,bodies,tables,vtables,
        {'simd_authority':{'indirect_population':expected}},'simd256' if lane=='simd' else 'scalar')


def storage(records,sizes,vectors,review,lane):
    s.require(set(records)==set(sizes)==set(vectors),'every bound function has its actual emitted frame geometry')
    for name,size in sizes.items():
        s.require(type(size) is int and 0<=size<65536,'bounded per-function private frame')
        for reg,offset in vectors[name]:
            s.require(6<=reg<=15 and 0<=offset and offset+16<=size,'incoming vector save within assigned frame')
    if lane=='simd':
        place=review['simd_resident_construction']['placement'];work=review['simd_retained_worker']
        s.require(place['authority_page_span']==[0,24] and place['owner_page_span']==[24,1136] and
            work['page_bytes']==4096 and work['close_erases_page_before_identity_reset'],
            'complete backing-page retirement for typed owner and padding')
        resident=dict(page_bytes=4096,authority=place['authority_page_span'],owner=place['owner_page_span'])
        typed=dict(workspace_bytes=5260,staging_bytes=1024,output_scratch_bytes=1024,
            cleanup='replayed workspace/staging/output destructors and normal-return ordering',
            descriptor_pointers_or_frame_padding_individually_erased=False)
        buffers=dict(payload_bytes=12288,header_bytes=384)
    else:
        work=review['sequential_retained_worker'];layout=life.LAYOUT[lane]
        s.require(work['page_bytes']==4096 and work['typed_teardown_and_full_page_erasure_before_close_success'],
            'complete sequential backing-page retirement')
        resident=dict(page_bytes=4096,owner_bytes=layout['size'],subobjects=review['sequential_state_storage']['owner_subobjects'])
        typed=dict(state_bytes=review['sequential_state_storage']['state_destructor']['state_bytes'],output_bytes=1024,
            cleanup='replayed typed destruction and complete output clearing',entire_state_allocation_individually_erased=False)
        readback=work['buffer_readback'];buffers=dict(payload_bytes=readback['payload_reads'],header_bytes=readback['header_reads'])
    return dict(resident=resident,typed_storage=typed,worker_buffers=buffers,
        transient=dict(frames={n:dict(local_bytes=sizes[n],saved_vectors=vectors[n],
            cleanup='enclosing protected window; typed clearing is additional') for n in sorted(records)},
            window_bytes=65536,whole_window_reclamation_package=8,
            individual_spills_moves_padding_or_registers_erased=False,cumulative_stack_depth_qualified=False),
        caller_input_and_declassified_host_outputs_protected=False,
        mutable_globals='reviewed live/page identity only; no secret payload allocation')


def terminals(bodies,lane):
    selected={n for n in bodies if re.search(r'(panic_const_add_overflow|panicking9panic_fmt|rust_begin_unwind)$',n)}
    if lane!='simd':
        s.require(not selected,'no new sequential fatal terminal');return dict(fatal_cleanup_success=False,functions=[])
    fmt=s.one(selected,r'panicking9panic_fmt$');abort=s.one(selected,r'rust_begin_unwind$')
    overflow=s.one(selected,r'panic_const_add_overflow$')
    for caller,callee in ((overflow,fmt),(fmt,abort),(abort,'PublicProbeAbort')):
        s.sequences(bodies[caller],['callq '+callee+'|ud2'])
        s.require('retq' not in s.lines(bodies[caller]),'fatal exit is not a cleanup return')
    incoming=[(name,line.split(' ',1)[1]) for name,body in bodies.items() if name not in selected
        for line in s.lines(body) if line.startswith(('callq ','jmp ')) and line.split(' ',1)[1] in selected]
    s.require(incoming==[(s.one(bodies,r'Executor13digest_secret$'),overflow)],'only the reviewed executor overflow terminal')
    return dict(fatal_cleanup_success=False,functions=sorted(selected),incoming=incoming,
        fatal_abort_or_arbitrary_corrupted_state_cleanup_claimed=False)
