"""Finite private frame/storage assignments; not an OS-window erase proof.

Roles compose already reviewed, frozen emitted bodies. A matching symbol alone
is not semantic qualification. SDK frames, cumulative stack admission and full
window reclamation remain shared completion-package 8 obligations.
"""
import re
import windows_enclave_kmac_shapes as s

ROLES={
    'worker_transport_and_owned_buffers':[r'^RetainedWork$',r'worker7receive$',
        r'worker.*Buffers(?:E|5clear$)',r'Header6decode$',r'try_from_fn.*worker7receive'],
    'owner_lifecycle_and_guards':[r'Owner\d+(?:quarantine|seal|begin|clear|start|cancel|finish|update|operation)$',
        r'Operation.*(?:Drop4drop$|E)',r'Owner.*Drop4drop$'],
    'resident_placement_and_lifecycle':[r'Resident\d+(?:new|cancel|digest)$',r'Resident.*Drop4drop$'],
    'state_finalizer':[r'state.*State6finish$'],
    'authority_and_cancellation':[r'15check_authority$',r'simd5check$',r'Kernel8compiled$',
        r'Owner6digests2_0',r'Executor5check$'],
    'simd_compression_and_transposes':[r'transfer9transpose',r'3x86.*compress',r'Session14compress_bytes$'],
    'typed_workspace_and_output_cleanup':[r'workspace9WorkspaceE',r'Workspace4wipe$',r'SecretBatchOutput.*Drop4drop$'],
    'simd_scalar_tail_and_executor':[r'hardened_batch(?:512)?6engine7padding$',r'Executor13digest_secret$'],
    'public_startup_kat':[r'static_execution.*operations12known_answer$'],
    'memory_primitives':[r'secret_memory_predicate12mask_is_zero$',r'secret_memory22apply_secret_byte_mask$',
        r'secret_memory_mask9mask_byte$'],
    'fail_stop_never_cleanup_success':[r'panic_const_(?:shr|add)_overflow$',r'panicking9panic_fmt$',
        r'rust_begin_unwind$',r'len_mismatch_fail$',r'slice_index_fail$']}


def functions(records,reused,lane,semantics):
    assigned={}
    def add(name,role):
        s.require(name in records and name not in assigned,'one existing batch function per assignment')
        assigned[name]=role
    if lane in ('scalar','sha_ni'):
        s.require(reused['prior_semantic_review_replayed'] is True,'fresh sequential primitive replay')
        for name in reused['exact_helper_contracts']:add(name,'reproduced_sequential_primitive')
        for name in reused.get('reproduced_scalar_fallbacks',{}):add(name,'reproduced_scalar_fallback')
    else:
        prior=semantics['simd_primitive_contracts']
        s.require(prior['prior_semantic_review_replayed'] is True,'fresh SIMD primitive replay')
        for value in prior['exact_instruction_contracts'].values():add(value['function'],'reproduced_simd_primitive')
        add(prior['changed_zeroizer_separately_reviewed']['function'],'reviewed_positive_length_zeroizer')
    for name in sorted(set(records)-set(assigned)):
        roles=['invoked_cleanup_funclet'] if name.startswith('?dtor$') else [
            role for role,patterns in ROLES.items() if any(re.search(p,name) for p in patterns)]
        s.require(len(roles)==1,'one explicit batch review role: '+name+' '+repr(roles))
        add(name,roles[0])
    s.require(set(assigned)==set(records),'complete private batch function assignment')
    return assigned


def population(records,bodies,tables,vtables,semantics,lane):
    s.require(set(records)==set(bodies) and 'RetainedWork' in records,'same complete bound body population')
    graph={name:set(row['reference_targets']) & set(records) for name,row in records.items()}
    handlers={};used_tables=set()
    for name,row in records.items():
        handlers[name]={v['symbol'] for v in row.get('metadata',[]) if v['symbol'] in records}
        for target in row['reference_targets']:
            if target not in vtables:continue
            used_tables.add(target);table=vtables[target]
            s.require(table['bytes']==40 and table['metadata']==[0,0,1] and set(table['slots'])=={'24','32'},
                      'complete stateless callback table assignment')
            destinations=set(table['slots'].values())
            s.require(destinations<=set(records),'every callback points to a bound private body')
            graph[name]|=destinations
    s.require(used_tables==set(vtables),'no unassigned callback table')
    calls={};jumps={}
    for name,body in bodies.items():
        lines=s.lines(body)
        actual=[v for v in lines if v.startswith('callq *')]
        if actual:calls[name]=actual
        actual=[v for v in lines if v.startswith('jmpq *')]
        if actual:jumps[name]=actual
    expected=semantics['simd_authority']['indirect_population'] if lane.startswith('simd') else {}
    s.require(calls==expected,'every actual indirect call has its existing authority/cancellation review')
    s.require(set(jumps)==set(tables) and all(len(jumps[n])==len(tables[n]['operands']) for n in jumps),
              'every indirect jump has its bound local dispatch table')
    def reach(include_handlers):
        found=set();todo=['RetainedWork']
        while todo:
            name=todo.pop()
            if name in found:continue
            s.require(name in graph,'reachable private edge has an assignment');found.add(name)
            todo.extend(graph[name] | (handlers[name] if include_handlers else set()))
        return found
    normal=reach(False);complete=reach(True)
    s.require(complete==set(records),'no orphan or unassigned batch body')
    funclets={n for n in records if n.startswith('?dtor$')}
    s.require(funclets==set().union(*handlers.values()),'all cleanup funclets have incoming bound metadata')
    return dict(functions=len(complete),normal_or_callback_reachable=len(normal),funclets=len(funclets),
        entry='RetainedWork',all_private_bodies_assigned=True,indirect_call_sites=sum(map(len,calls.values())),
        bound_dispatch_sites=sum(map(len,jumps.values())),arbitrary_exception_dispatch_qualified=False)


def storage(records,sizes,vectors,runtime,lane,semantics):
    s.require(set(records)==set(sizes)==set(vectors),'every private body has frame and saved-register geometry')
    for n,size in sizes.items():
        s.require(type(size) is int and 0<=size<65536,'finite private frame below worker-window size')
        for register,offset in vectors[n]:
            s.require(type(register) is int and 6<=register<=15 and type(offset) is int and
                      0<=offset and offset+16<=size,'incoming nonvolatile vector save within frame')
    if 'memcmp' in runtime:
        s.require(lane=='scalar' and runtime['memcmp']['callers']==[s.one(records,r'worker7receive$')],
                  'memcmp compares only the scalar public 64-byte batch plan')
        s.require(semantics['lifecycle']['export']['identity_bytes_compared']==64,'reviewed public plan comparison')
    offset,size={'scalar':(0,1784),'sha_ni':(16,2624),'simd256':(24,288),'simd512':(24,296)}[lane]
    if lane.startswith('simd'):
        wipe=semantics['simd_storage']['wiping'];retire=semantics['simd_storage']['worker_retirement']
        s.require(retire['page_retirement_bytes']==4096,'full SIMD backing-page retirement')
        active=dict(workspace_bytes=wipe['workspace_bytes'],declared_field_bytes=wipe['declared_field_bytes'],
                    padding=wipe['unwiped_alignment_padding'],regions=wipe['workspace_regions'])
        payload,header=retire['worker_buffer_payload_bytes'],retire['worker_buffer_header_bytes']
    else:
        retire=semantics['lifecycle']['retirement']
        s.require(retire['page_erasure_bytes']==4096,'full sequential backing-page retirement')
        active=dict(taken_state_bytes=semantics['lifecycle']['clearing']['taken_state_bytes'],output_bytes=512)
        payload,header=retire['payload_bytes'],retire['header_bytes']
    return dict(resident=dict(page_bytes=4096,owner_offset=offset,owner_bytes=size,
            active_cleanup='reviewed typed destruction and output clearing',
            inactive_and_padding_cleanup='reviewed full backing-page retirement',admission_release_package=8),
        typed_storage=active,worker_buffers=dict(payload_bytes=payload,header_bytes=header,
            cleanup='reviewed buffer destructor before normal return'),
        transient=dict(window_bytes=65536,frames={n:dict(local_bytes=sizes[n],saved_vectors=vectors[n],
                cleanup='enclosing window; typed scratch cleanup is additional') for n in sorted(records)},
            individual_spills_moves_padding_or_registers_erased=False,
            shared_runtime_frames_included=False,cumulative_depth_qualified=False,window_reclamation_package=8),
        mutable_globals='resident/page identity only; no secret payload allocation',
        caller_input_and_declassified_host_outputs_protected=False,arbitrary_exception_cleanup_qualified=False)
