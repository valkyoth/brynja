"""Close the finite author family review under its existing shared contracts.

No independently verified, whole-image, OS-unwind or cumulative-stack claim is
made. Package 8 must discharge those shared contracts before release claims.
"""
import windows_enclave_sha3_batch_assignment as assignment
s=assignment.s
SEQUENTIAL={
 'sequential_plan_admission':('all_instructions_and_dispatch_cases_checked','checked_total','nonempty_required'),
 'sequential_lifecycle':('checked_next_sequence','phase_match_before_admission','unfinished_guard_clears_and_quarantines','seal_requires_all_active_slots_complete'),
 'sequential_state_storage':('state_pointer_inside_owner',),
 'sequential_retained_worker':('initialization_precedes_live_publication','exact_page_identity_before_receive','typed_teardown_and_full_page_erasure_before_close_success'),
 'sequential_receiver':('payload_pointer_retained_from_worker_buffer','export_checks_all_admitted_plan_fields','export_success_clears_owner','export_failure_guard_then_quarantine'),
 'sequential_start_admission_and_placement':('slot_equality_before_indexed_plan_read','successful_placement_destroys_previous_typed_state_first','successful_slot_and_phase_commit_after_state_copy'),
 'sequential_update':('lower_helpers_replayed_and_exact','copied_input_pointer_and_length_preserved_to_absorption','checked_budget_subtraction_before_absorption','failed_update_typed_state_and_output_cleared'),
 'sequential_setup_chunks':('input_pointer_and_length_preserved','checked_budget_before_fragment','last_byte_read_only_after_nonempty_and_partial_checks','normal_rejection_typed_cleanup_and_quarantine_composed'),
 'sequential_finish_caller':('all_lower_finalizers_normal_paths_composed','input_pointer_preserved_to_descriptor','prefix_width_sum_and_end_both_checked','lower_success_required_before_completed_bit','success_destroys_state_and_returns_to_collecting','outer_rejection_clears_entire_output_and_quarantines')}
SCALAR={
 'scalar_empty_constructors':('empty_constructor_paths_qualified',),
 'scalar_fixed_constructors':('active_fixed_constructor_initialization_qualified',),
 'scalar_shake_constructors':('scalar_shake_constructor_joins_qualified',),
 'scalar_cshake_initialization':('cshake_initial_arithmetic_and_fields_qualified',),
 'scalar_cshake_prefix':('success_only_after_both_prefix_updates_and_advance','initialized_failure_clears_pending_and_typed_owner'),
 'scalar_cshake_transfers':('scalar_active_constructor_transfers_qualified','scalar_start_instruction_coverage_complete'),
 'scalar_setup_completion':('operation_result_consumed_before_storage_reuse','emitted_expected_full_u128_equality','pending_bit_count_must_be_zero','setup_pending_byte_volatile_clear','normal_failure_typed_cleanup_and_quarantine_composed')}
AVX2={
 'avx2_direct_constructors':('direct_constructor_caller_transfers_qualified','armed_failure_uses_reviewed_clear_and_quarantine'),
 'avx2_cshake_prefix':('initialized_failures_destroy_local_core_before_outer_rejection','cshake_prefix_calls_and_failure_joins_qualified'),
 'avx2_cshake_transfers':('avx2_start_instruction_coverage_complete','cshake_constructor_transfer_origins_qualified'),
 'avx2_setup_completion':('emitted_expected_full_u128_equality','pending_bit_count_must_be_zero','inner_health_epoch_and_kernel_checked','prefix_pending_byte_volatile_clear_before_absorbing','normal_failure_typed_cleanup_and_quarantine_composed')}
SIMD={
 'simd_session_cleanup':('success_error_and_callback_unwind_scratch_clearing_composed','caller_output_after_revalidation_and_checked_counter'),
 'simd_resident_construction':('publication_after_authority_and_owner_initialization','callback_is_pure_compiled_tag_check'),
 'simd_owner_admission':('phase_and_nonwrapping_sequence_before_authority','sequence_commit_after_two_revalidations','rejected_operation_clears_output_and_quarantines'),
 'simd_retained_worker':('page_stack_nonoverlap_checked','live_identity_checked_before_receive','close_erases_page_before_identity_reset','return_after_buffer_drop_on_all_normal_request_paths'),
 'simd_receiver':('actual_bitstring_inputs_use_local_buffers_not_host_addresses','all_twelve_inputs_bounded_to_separate_1024_byte_worker_slots'),
 'simd_descriptors':('no_input_pointer_published_to_global_or_heap_storage',),
 'simd_digest':('output_dropped_before_final_authority_check','retained_plan_published_only_after_final_authority_check','normal_error_retires_initialized_objects_then_quarantines'),
 'simd_terminal':('shared_error_wipes_workspace_staging_and_present_destinations','successful_report_after_workspace_and_staging_wipe'),
 'simd_service_call_effects':('all_executor_call_site_footprints_assigned',),
 'simd_exception_call_effects':('original_guard_fields_live_at_all_synchronous_throw_sites','workspace_then_staging_then_quarantine_then_outputs_cleared'),
 'simd_physical_allocation_lifetimes':('original_payload_and_authority_allocations_joined','conditional_page_payload_frame_nonoverlap_checked'),
 'simd_executor_effect_composition':('all_57_executor_call_footprints_composed','indirect_call_writes_preserve_original_inputs_authority_and_descriptor_cells')}


def prerequisites(review,lane):
    required=SIMD if lane=='simd' else SEQUENTIAL|(SCALAR if lane=='scalar' else AVX2)
    paths=[]
    for section,fields in required.items():
        for field in fields:
            s.require(isinstance(review.get(section),dict) and review[section].get(field) is True,
                'complete replayed family contract: '+section+'.'+field)
            paths.append(section+'.'+field)
    if lane=='simd':
        s.require(review['simd_service_call_effects']['pending_callee_effect_sites']==[] and
            review['simd_service_call_effects']['pending_non_frame_store_sites']==[] and
            len(review['simd_executor_effect_composition']['call_assignments'])==57,
            'no remaining executor store/call assignment')
        s.require(review['simd_exception_call_effects']['final_health_cleanup']['authority_health_byte_cleared_on_invoked_unwind'],
            'final-health cleanup is part of the invoked-handler population')
    return paths


def inspect(records,bodies,sizes,vectors,tables,vtables,review,lane):
    s.require(lane in ('scalar','avx2','simd'),'finite reviewed SHA-3 family route')
    joined=prerequisites(review,lane)
    roles=assignment.functions(records,review,lane)
    population=assignment.population(records,bodies,tables,vtables,review,lane)
    storage=assignment.storage(records,sizes,vectors,review,lane)
    terminals=assignment.terminals(bodies,lane)
    s.require(set(roles)==set(storage['transient']['frames']),'all private bodies have a temporary/frame disposition')
    return dict(author_private_review_complete=True,review_kind='finite conditional author composition',
        joined_reviews=joined,functions=roles,population=population,storage=storage,fatal_terminals=terminals,
        remaining_private_assignments=[],shared_completion_package=8,
        shared_prerequisites=['valid typed exclusive owner/state and original caller allocations',
            'serialized nonreentrant synchronous transport, live page and lifetime through retirement',
            'bound SDK/probe/memory helpers and Win64 call, home-space and nonvolatile ABI',
            'cumulative stack admission, nested frame effects and complete protected-window reclamation'],
        historical_component_pending_flags_superseded_only_by_named_joined_reviews=True,
        whole_frame_erasure_qualified=False,whole_image_qualified=False,independent_retest=False,
        arbitrary_exception_or_fatal_abort_cleanup_qualified=False)
