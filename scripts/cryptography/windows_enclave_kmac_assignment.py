"""Finite author-review assignments, not a machine proof or release waiver.

Complete frozen bodies and image edges are checked by the caller. These roles
record the source/assembly review and component campaigns for the distinct
functions; they do not turn a matching name into a semantic qualification.
"""
import re
import windows_enclave_kmac_shapes as s

REUSE=('exact_body_reference_and_abi_reuse','explicitly_rebound_renamed_helpers',
       'changed_abi_checked_by_widened_xor_review','explicitly_compared_prefix_specializations')
ROLES={
    'entry_and_wire': [r'^RetainedWork$',r'worker7receive$',r'Header6decode$'],
    'owner_lifecycle': [r'Owner\d+(?:clear|quarantine|operation|cancel|update|finish|squeeze|verify)$',
                        r'Owner\d+(?:begin_setup|rekey_setup|customization|finish_customization|key|finish_setup)$'],
    'active_state_and_guards': [r'drop_glue.*(?:State|Guard|Operation)E',r'Operation.*Drop4drop$'],
    'resident_placement_and_retirement': [r'Resident\d+(?:new|quarantine)$',r'Resident.*Drop4drop$'],
    'public_bit_shape': [r'Fips202BitString3new$'],
    'public_length_encoding': [r'sp800185(?:11encode_u128|19cshake_prefix_bytes)$'],
    'difference_and_public_decision': [r'secret_memory(?:25secret_difference_is_zero|33accumulate_secret_byte_difference)$',
                                       r'secret_memory_difference15accumulate_byte$'],
    'suffix_and_pending_bits': [r'13append_suffix',r'SecretPacker.*E9push_bits',r'Key4bits$'],
    'scalar_setup_and_transfer': [r'kmac_stream_setup.*State12finish_setup$',
                                  r'kmac5setup.*Kmac(?:128|256)Setup',r'kmac5setup6engine'],
    'scalar_core_cleanup': [r'kmac10core_state.*E4wipe'],
    'scalar_construction_and_reader_transfer': [r'CshakeState8new_kmac$',r'take_reader_erasing_source$'],
    'scalar_fixed_and_xof_finalization': [r'Kmac(?:128|256)20finalize_secret_bits$',
                                         r'KmacXof(?:128|256)17finalize_bits_xof$'],
    'scalar_secret_readers': [r'KmacXof(?:128|256)Reader\d+squeeze',r'CshakeReader25squeeze_final_bits_secret$'],
    'accelerated_state': [r'kmac_accelerated_state.*State\d+(?:setup|key|finish_setup|fixed)$',
                           r'sha3_accelerated_state.*State\d+(?:update|squeeze)$'],
}


def functions(names,prior):
    assigned={}
    def add(name,role):
        s.require(name in names and name not in assigned,'one existing function per review assignment')
        assigned[name]=role
    for role in REUSE:
        for name in prior[role]: add(name,'reproduced_sha3/'+role)
    for name in sorted(set(names)-set(assigned)):
        if name.startswith('?dtor$'):
            add(name,'invoked_cleanup_funclet');continue
        roles=[role for role,patterns in ROLES.items() if any(re.search(p,name) for p in patterns)]
        s.require(len(roles)==1,'one explicit distinct review role: '+name+' '+repr(roles))
        add(name,roles[0])
    s.require(set(assigned)==set(names),'complete finite KMAC review assignment')
    return assigned


def storage(records,sizes,vectors,runtime,lane):
    # All actual memory/runtime targets are already resolved from relocations.
    # No allocator is silently included in the runtime allowlist. The page and
    # stack-window admission contracts are shared obligations, not established
    # by merely listing storage classes here.
    if 'memcmp' in runtime:
        s.require(lane=='avx2' and len(runtime['memcmp']['callers'])==1 and
                  runtime['memcmp']['callers'][0].endswith('operations12known_answer'),
                  'memcmp only handles the public startup known-answer test')
    return dict(
        resident=dict(bytes=4096,owner_offset=0 if lane=='scalar' else 32,
                      owner_maximum_bytes=4096 if lane=='scalar' else 2176,
                      active_state_cleanup='typed state/owner destructors',
                      inactive_padding_cleanup='full volatile page retirement',
                      host_page_admission_and_release_package=8),
        transient=dict(window_bytes=65536,
            frames={n:dict(local_bytes=sizes[n],incoming_vector_saves=vectors[n],
                cleanup='enclosing window; typed scratch cleanup is additional') for n in sorted(records)},
            aggregate_moves_individually_erased=False,
            shared_runtime_frames_included=False,complete_window_reclamation_package=8),
        transport=dict(input='bounded copy into owned worker buffer',
                       export='explicit tag export or one-byte verification decision',
                       source_buffers_and_declassified_host_outputs_protected=False,
                       shared_sdk_boundary_package=8),
        mutable_globals='resident pointer identity only; no secret payload allocation',
        arbitrary_exception_cleanup_qualified=False)
