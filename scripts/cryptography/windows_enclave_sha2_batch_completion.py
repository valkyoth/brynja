"""Compose the finite SHA-2 private review, retaining shared prerequisites."""
import windows_enclave_sha2_batch_assignment as assignment
import windows_enclave_sha2_batch_terminals as terminals
s=assignment.s

SEQUENTIAL=(('lifecycle','sealing','each_nonempty_slot_requires_completion_bit'),
    ('lifecycle','export','copy_result_checked'),('lifecycle','operation_guard','incomplete_guard_quarantines'),
    ('state_transitions','slot_selection','equality_to_selected_slot_bounds_plan_load'),
    ('state_transitions','update','only_reproduced_update_helpers_called'),
    ('placement_and_plan','plan','nonempty_required'))
SIMD=(('simd_constructor','full_body_including_failure_edges'),
    ('simd_constructor','all_lanes_checked_before_publication'),
    ('simd_worker','entry','page_window_disjoint'),('simd_worker','entry','buffer_ranges_checked_before_receive'),
    ('simd_worker','input_copies','digest_receives_private_lane_pointers'),
    ('simd_metadata_preservation','conditional_input_and_authority_field_preservation_checked'),
    ('simd_metadata_preservation','compact_reads_require_completed_initialization_since_last_wipe'),
    ('simd_compact_pointer_lifetimes','current_phase_definitions_checked'),
    ('simd_physical_allocation_lifetimes','constructor_result_and_worker_use_joined'),
    ('simd_physical_allocation_lifetimes','conditional_physical_separation'),
    ('simd_whole_function_cleanup_order','all_normal_return_paths_checked'),
    ('simd_whole_function_cleanup_order','terminal_paths_are_not_cleanup_success'))
EXTRA={
    'scalar':(('state_transitions','constructor_transfer','old_owner_wiped_before_replacement'),
              ('state_transitions','scalar_finish','canonical_tail_checked'),
              ('state_transitions','scalar_finish','state_invalidated_before_call')),
    'sha_ni':(('state_transitions','constructor_transfer','old_state_wiped_before_replacement'),
              ('finalizer_caller','canonical_tail_checked'),('finalizer_caller','completion_committed_only_on_success'),
              ('state_transitions','finish_funclet','actual_handler_metadata_bound_by_parent')),
    'simd256':(('simd_narrow_output_interfaces','all_narrow_returning_interfaces_assigned'),
               ('simd_narrow_output_interfaces','output_arguments_and_normal_effects_joined')),
    'simd512':(('simd_parent_remaining_interfaces','all_parent_call_interfaces_assigned'),
               ('simd_wide_output_effects','all_child_normal_calls_assigned'),
               ('simd_wide_output_effects','original_destination_source_and_length_lifetimes_conditionally_joined'),
               ('simd_wide_output_effects','final_copy_and_error_clear_effects_conditionally_disjoint'))}


def prerequisites(semantics,lane):
    paths=(*SIMD,*EXTRA[lane]) if lane.startswith('simd') else (*SEQUENTIAL,*EXTRA[lane])
    for path in paths:
        value=semantics
        for part in path:
            s.require(isinstance(value,dict) and part in value,'existing review path present: '+'.'.join(path))
            value=value[part]
        s.require(value is True,'existing private review passed: '+'.'.join(path))
    if lane=='simd256':
        stage=semantics['simd_narrow_output_interfaces']
        s.require(stage['assigned_narrow_returning_interfaces']==62 and stage['remaining_narrow_calls']==[],
                  'complete narrow interface population before frame composition')
    elif lane=='simd512':
        s.require(semantics['simd_parent_remaining_interfaces']['assigned_parent_call_count']==27 and
                  semantics['simd_wide_output_effects']['child_returning_call_count']==36,
                  'complete wide parent and child interface populations')
    return ['.'.join(p) for p in paths]


def inspect(records,bodies,sizes,vectors,runtime,tables,vtables,semantics,reused,lane):
    joined=prerequisites(semantics,lane)
    roles=assignment.functions(records,reused,lane,semantics)
    population=assignment.population(records,bodies,tables,vtables,semantics,lane)
    storage=assignment.storage(records,sizes,vectors,runtime,lane,semantics)
    failstop=terminals.inspect(bodies,lane,semantics)
    s.require(set(roles)==set(storage['transient']['frames']),
              'every assigned constructor/caller/helper/funclet has storage disposition')
    return dict(author_private_review_complete=True,review_kind='finite conditional author composition',
        joined_reviews=joined,functions=roles,population=population,storage=storage,fail_stop=failstop,
        remaining_private_assignments=[],shared_completion_package=8,
        shared_prerequisites=['valid typed exclusive owner/state and original caller allocations',
            'serialized nonreentrant synchronous transport and lifetime through retirement',
            'bound SDK/probe implementations, Win64 ABI and supported invoked-cleanup behavior',
            'cumulative stack admission plus complete protected-window reclamation'],
        whole_frame_erasure_qualified=False,whole_image_qualified=False,
        independent_retest=False,arbitrary_exception_cleanup_qualified=False)
