#!/usr/bin/env python3
"""Check explicit portable registrations and fixture versions without running crypto."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import tomllib
import unittest
import verification_hkdf_dynamic_tests as hkdf_dynamic
import verification_hkdf_public_dynamic_tests as hkdf_public_dynamic
from verification_sanitizer_tests import SanitizerRegistryTests
from verification_miri_tests import MiriBindingTests
from verification_kani_tests import KaniBindingTests
from verification_additional_tests import AdditionalBindingTests
from verification_script_tests import ScriptBindingTests
from verification_assessment_tests import AssessmentBindingTests
from verification_engine_tests import EngineBindingTests
from verification_md5_checker_tests import Md5CheckerBindingTests
from verification_hosted_tests import HostedBindingTests
from verification_compiler_tests import CompilerBindingTests
from verification_codegen_tests import CodegenBindingTests
from verification_shell_tests import ShellBindingTests
from verification_checker_tests import CheckerBindingTests
from verification_source_policy_tests import PolicyBindingTests
from verification_legacy_policy_tests import LegacyPolicyBindingTests
from verification_hardened_tests import HardenedBindingTests
from verification_inventory_tests import InventoryBindingTests
from verification_control_tests import ControlBindingTests
from verification_record_policy_tests import RecordPolicyBindingTests
from verification_package_tests import PackageBindingTests
from verification_execution_tests import ExecutionBindingTests
from verification_owner_tests import OwnerBindingTests
from verification_acceptance_tests import AcceptanceBindingTests
from verification_final_tests import FinalBindingTests

ROOT = Path(__file__).resolve().parents[2]

# Include fail-closed runner tests in the normal registry regression suite.
aes_spec = importlib.util.spec_from_file_location('aes_runner_tests', ROOT / 'scripts/aes/test-aes-runners.py')
aes_runner_tests = importlib.util.module_from_spec(aes_spec)
aes_spec.loader.exec_module(aes_runner_tests)
AesApiRunnerTests = aes_runner_tests.ApiTests
AesKaniRunnerTests = aes_runner_tests.KaniTests
AesMutationTests = aes_runner_tests.MutationTests
AesOwnerCodegenTests = aes_runner_tests.OwnerCodegenTests
AesOperationCodegenTests = aes_runner_tests.OperationCodegenTests

wide_operation_spec = importlib.util.spec_from_file_location('aes_wide_operation_tests', ROOT / 'scripts/aes/test-aes-wide-operation-cleanup.py')
wide_operation_tests = importlib.util.module_from_spec(wide_operation_spec)
wide_operation_spec.loader.exec_module(wide_operation_tests)
AesWideOperationCodegenTests = wide_operation_tests.WideOperationTests

aes_consumer_spec = importlib.util.spec_from_file_location('aes_consumer_tests', ROOT / 'scripts/aes/test-aes-consumer.py')
aes_consumer_tests = importlib.util.module_from_spec(aes_consumer_spec)
aes_consumer_spec.loader.exec_module(aes_consumer_tests)
AesConsumerTests = aes_consumer_tests.ConsumerTests

aes_packaged_spec = importlib.util.spec_from_file_location('aes_packaged_tests', ROOT / 'scripts/aes/test-aes-packaged.py')
aes_packaged_tests = importlib.util.module_from_spec(aes_packaged_spec)
aes_packaged_spec.loader.exec_module(aes_packaged_tests)
AesPackagedTests = aes_packaged_tests.PackagedTests

aes_avs_spec = importlib.util.spec_from_file_location('aes_avs_tests', ROOT / 'scripts/aes/test-aes-avs.py')
aes_avs_tests = importlib.util.module_from_spec(aes_avs_spec)
aes_avs_spec.loader.exec_module(aes_avs_tests)
AesAvsTests = aes_avs_tests.AvsTests

aes_kernel_spec = importlib.util.spec_from_file_location('aes_kernel_tests', ROOT / 'scripts/aes/test-aes-kernel-candidate.py')
aes_kernel_tests = importlib.util.module_from_spec(aes_kernel_spec)
aes_kernel_spec.loader.exec_module(aes_kernel_tests)
AesKernelCandidateTests = aes_kernel_tests.KernelCandidateTests

aes_expansion_spec = importlib.util.spec_from_file_location('aes_expansion_tests', ROOT / 'scripts/aes/test-aes-expansion-candidate.py')
aes_expansion_tests = importlib.util.module_from_spec(aes_expansion_spec)
aes_expansion_spec.loader.exec_module(aes_expansion_tests)
AesExpansionCandidateTests = aes_expansion_tests.ExpansionCandidateTests

aes_static_spec = importlib.util.spec_from_file_location('aes_static_tests', ROOT / 'scripts/aes/test-aes-static.py')
aes_static_tests = importlib.util.module_from_spec(aes_static_spec)
aes_static_spec.loader.exec_module(aes_static_tests)
AesStaticTests = aes_static_tests.StaticTests

aes_hosted_spec = importlib.util.spec_from_file_location('aes_hosted_tests', ROOT / 'scripts/aes/test-aes-hosted.py')
aes_hosted_tests = importlib.util.module_from_spec(aes_hosted_spec)
aes_hosted_spec.loader.exec_module(aes_hosted_tests)
AesHostedTests = aes_hosted_tests.HostedTests

aes_dit_spec = importlib.util.spec_from_file_location('aes_dit_tests', ROOT / 'scripts/aes/test-aes-dit.py')
aes_dit_tests = importlib.util.module_from_spec(aes_dit_spec)
aes_dit_spec.loader.exec_module(aes_dit_tests)
AesDitTests = aes_dit_tests.DitTests
aes_dit_linked_spec = importlib.util.spec_from_file_location('aes_dit_linked_tests', ROOT / 'scripts/aes/test-aes-dit-linked.py')
aes_dit_linked_tests = importlib.util.module_from_spec(aes_dit_linked_spec)
aes_dit_linked_spec.loader.exec_module(aes_dit_linked_tests)
AesDitLinkedTests = aes_dit_linked_tests.DitLinkedTests
aes_dit_finite_spec = importlib.util.spec_from_file_location('aes_dit_finite_tests', ROOT / 'scripts/aes/test-aes-dit-finite.py')
aes_dit_finite_tests = importlib.util.module_from_spec(aes_dit_finite_spec)
aes_dit_finite_spec.loader.exec_module(aes_dit_finite_tests)
AesDitFiniteTests = aes_dit_finite_tests.FiniteTests
aes_dit_finite_analysis_spec = importlib.util.spec_from_file_location('aes_dit_finite_analysis_tests', ROOT / 'scripts/aes/test-aes-dit-finite-analysis.py')
aes_dit_finite_analysis_tests = importlib.util.module_from_spec(aes_dit_finite_analysis_spec)
aes_dit_finite_analysis_spec.loader.exec_module(aes_dit_finite_analysis_tests)
AesDitFiniteAnalysisTests = aes_dit_finite_analysis_tests.FiniteAnalysisTests
aes_dit_sensitivity_spec = importlib.util.spec_from_file_location('aes_dit_sensitivity_tests', ROOT / 'scripts/aes/test-aes-dit-sensitivity.py')
aes_dit_sensitivity_tests = importlib.util.module_from_spec(aes_dit_sensitivity_spec)
aes_dit_sensitivity_spec.loader.exec_module(aes_dit_sensitivity_tests)
AesDitSensitivityTests = aes_dit_sensitivity_tests.DitSensitivityTests

aes_execution_api_spec = importlib.util.spec_from_file_location('aes_execution_api_tests', ROOT / 'scripts/aes/test-aes-execution-api.py')
aes_execution_api_tests = importlib.util.module_from_spec(aes_execution_api_spec)
aes_execution_api_spec.loader.exec_module(aes_execution_api_tests)
AesExecutionApiTests = aes_execution_api_tests.ExecutionApiTests

aes_campaign_spec = importlib.util.spec_from_file_location('aes_campaign_tests', ROOT / 'scripts/aes/test-aes-accelerated-campaigns.py')
aes_campaign_tests = importlib.util.module_from_spec(aes_campaign_spec)
aes_campaign_spec.loader.exec_module(aes_campaign_tests)
AesAcceleratedCampaignTests = aes_campaign_tests.AcceleratedCampaignTests

aes_accelerated_linked_spec = importlib.util.spec_from_file_location('aes_accelerated_linked_tests', ROOT / 'scripts/aes/test-aes-accelerated-linked.py')
aes_accelerated_linked_tests = importlib.util.module_from_spec(aes_accelerated_linked_spec)
aes_accelerated_linked_spec.loader.exec_module(aes_accelerated_linked_tests)
AesAcceleratedLinkedTests = aes_accelerated_linked_tests.AcceleratedLinkedTests
aes_apple_linked_spec = importlib.util.spec_from_file_location('aes_apple_linked_tests', ROOT / 'scripts/aes/test-aes-apple-linked-kernels.py')
aes_apple_linked_tests = importlib.util.module_from_spec(aes_apple_linked_spec)
aes_apple_linked_spec.loader.exec_module(aes_apple_linked_tests)
AesAppleLinkedTests = aes_apple_linked_tests.AppleKernelTests
aes_apple_cleanup_spec = importlib.util.spec_from_file_location('aes_apple_cleanup_tests', ROOT / 'scripts/aes/test-aes-apple-linked-cleanup.py')
aes_apple_cleanup_tests = importlib.util.module_from_spec(aes_apple_cleanup_spec)
aes_apple_cleanup_spec.loader.exec_module(aes_apple_cleanup_tests)
AesAppleCleanupTests = aes_apple_cleanup_tests.AppleCleanupTests
aes_apple_import_spec = importlib.util.spec_from_file_location('aes_apple_import_tests', ROOT / 'scripts/aes/test-aes-apple-unwind-import.py')
aes_apple_import_tests = importlib.util.module_from_spec(aes_apple_import_spec)
aes_apple_import_spec.loader.exec_module(aes_apple_import_tests)
AesAppleImportTests = aes_apple_import_tests.AppleImportTests
aes_apple_sessions_spec = importlib.util.spec_from_file_location('aes_apple_sessions_tests', ROOT / 'scripts/aes/test-aes-apple-linked-sessions.py')
aes_apple_sessions_tests = importlib.util.module_from_spec(aes_apple_sessions_spec)
aes_apple_sessions_spec.loader.exec_module(aes_apple_sessions_tests)
AesAppleSessionTests = aes_apple_sessions_tests.AppleSessionTests
aes_apple_constructors_spec = importlib.util.spec_from_file_location('aes_apple_constructors_tests', ROOT / 'scripts/aes/test-aes-apple-linked-constructors.py')
aes_apple_constructors_tests = importlib.util.module_from_spec(aes_apple_constructors_spec)
aes_apple_constructors_spec.loader.exec_module(aes_apple_constructors_tests)
AesAppleConstructorTests = aes_apple_constructors_tests.AppleConstructorTests
aes_apple_cached_spec = importlib.util.spec_from_file_location('aes_apple_cached_tests', ROOT / 'scripts/aes/test-aes-apple-linked-cached.py')
aes_apple_cached_tests = importlib.util.module_from_spec(aes_apple_cached_spec)
aes_apple_cached_spec.loader.exec_module(aes_apple_cached_tests)
AesAppleCachedTests = aes_apple_cached_tests.AppleCachedTests
aes_apple_ephemeral_public_spec = importlib.util.spec_from_file_location('aes_apple_ephemeral_public_tests', ROOT / 'scripts/aes/test-aes-apple-linked-ephemeral-public.py')
aes_apple_ephemeral_public_tests = importlib.util.module_from_spec(aes_apple_ephemeral_public_spec)
aes_apple_ephemeral_public_spec.loader.exec_module(aes_apple_ephemeral_public_tests)
AesAppleEphemeralPublicTests = aes_apple_ephemeral_public_tests.AppleEphemeralPublicTests
aes_apple_ephemeral_secret_spec = importlib.util.spec_from_file_location('aes_apple_ephemeral_secret_tests', ROOT / 'scripts/aes/test-aes-apple-linked-ephemeral-secret.py')
aes_apple_ephemeral_secret_tests = importlib.util.module_from_spec(aes_apple_ephemeral_secret_spec)
aes_apple_ephemeral_secret_spec.loader.exec_module(aes_apple_ephemeral_secret_tests)
AesAppleEphemeralSecretTests = aes_apple_ephemeral_secret_tests.AppleEphemeralSecretTests
aes_apple_startup_spec = importlib.util.spec_from_file_location('aes_apple_startup_tests', ROOT / 'scripts/aes/test-aes-apple-startup-static.py')
aes_apple_startup_tests = importlib.util.module_from_spec(aes_apple_startup_spec)
aes_apple_startup_spec.loader.exec_module(aes_apple_startup_tests)
AesAppleStaticStartupTests = aes_apple_startup_tests.AppleStaticStartupTests
aes_apple_hosted_startup_spec = importlib.util.spec_from_file_location('aes_apple_hosted_startup_tests', ROOT / 'scripts/aes/test-aes-apple-startup-hosted.py')
aes_apple_hosted_startup_tests = importlib.util.module_from_spec(aes_apple_hosted_startup_spec)
aes_apple_hosted_startup_spec.loader.exec_module(aes_apple_hosted_startup_tests)
AesAppleHostedStartupTests = aes_apple_hosted_startup_tests.AppleHostedStartupTests
aes_apple_control_spec = importlib.util.spec_from_file_location('aes_apple_control_tests', ROOT / 'scripts/aes/test-aes-apple-startup-controls.py')
aes_apple_control_tests = importlib.util.module_from_spec(aes_apple_control_spec)
aes_apple_control_spec.loader.exec_module(aes_apple_control_tests)
AesAppleStartupControlTests = aes_apple_control_tests.AppleStartupControlTests
aes_accelerated_expansion_spec = importlib.util.spec_from_file_location('aes_accelerated_expansion_tests', ROOT / 'scripts/aes/test-aes-accelerated-expansion.py')
aes_accelerated_expansion_tests = importlib.util.module_from_spec(aes_accelerated_expansion_spec)
aes_accelerated_expansion_spec.loader.exec_module(aes_accelerated_expansion_tests)
AesAcceleratedExpansionTests = aes_accelerated_expansion_tests.AcceleratedExpansionTests
aes_accelerated_public_spec = importlib.util.spec_from_file_location('aes_accelerated_public_tests', ROOT / 'scripts/aes/test-aes-accelerated-public.py')
aes_accelerated_public_tests = importlib.util.module_from_spec(aes_accelerated_public_spec)
aes_accelerated_public_spec.loader.exec_module(aes_accelerated_public_tests)
AesAcceleratedPublicTests = aes_accelerated_public_tests.AcceleratedPublicTests
aes_accelerated_secret_spec = importlib.util.spec_from_file_location('aes_accelerated_secret_tests', ROOT / 'scripts/aes/test-aes-accelerated-secret.py')
aes_accelerated_secret_tests = importlib.util.module_from_spec(aes_accelerated_secret_spec)
aes_accelerated_secret_spec.loader.exec_module(aes_accelerated_secret_tests)
AesAcceleratedSecretTests = aes_accelerated_secret_tests.AcceleratedSecretTests
aes_accelerated_ephemeral_spec = importlib.util.spec_from_file_location('aes_accelerated_ephemeral_tests', ROOT / 'scripts/aes/test-aes-accelerated-ephemeral.py')
aes_accelerated_ephemeral_tests = importlib.util.module_from_spec(aes_accelerated_ephemeral_spec)
aes_accelerated_ephemeral_spec.loader.exec_module(aes_accelerated_ephemeral_tests)
AesAcceleratedEphemeralTests = aes_accelerated_ephemeral_tests.AcceleratedEphemeralTests

aes_accelerated_sessions_spec = importlib.util.spec_from_file_location('aes_accelerated_sessions_tests', ROOT / 'scripts/aes/test-aes-accelerated-sessions.py')
aes_accelerated_sessions_tests = importlib.util.module_from_spec(aes_accelerated_sessions_spec)
aes_accelerated_sessions_spec.loader.exec_module(aes_accelerated_sessions_tests)
AesAcceleratedSessionTests = aes_accelerated_sessions_tests.AcceleratedSessionTests

aes_accelerated_ephemeral_public_spec = importlib.util.spec_from_file_location('aes_accelerated_ephemeral_public_tests', ROOT / 'scripts/aes/test-aes-accelerated-ephemeral-public.py')
aes_accelerated_ephemeral_public_tests = importlib.util.module_from_spec(aes_accelerated_ephemeral_public_spec)
aes_accelerated_ephemeral_public_spec.loader.exec_module(aes_accelerated_ephemeral_public_tests)
AesAcceleratedEphemeralPublicTests = aes_accelerated_ephemeral_public_tests.AcceleratedEphemeralPublicTests

aes_accelerated_lifecycle_spec = importlib.util.spec_from_file_location('aes_accelerated_lifecycle_tests', ROOT / 'scripts/aes/test-aes-accelerated-lifecycle.py')
aes_accelerated_lifecycle_tests = importlib.util.module_from_spec(aes_accelerated_lifecycle_spec)
aes_accelerated_lifecycle_spec.loader.exec_module(aes_accelerated_lifecycle_tests)
AesAcceleratedLifecycleTests = aes_accelerated_lifecycle_tests.AcceleratedLifecycleTests

aes_accelerated_arm_cleanup_spec = importlib.util.spec_from_file_location('aes_accelerated_arm_cleanup_tests', ROOT / 'scripts/aes/test-aes-accelerated-arm-cleanup.py')
aes_accelerated_arm_cleanup_tests = importlib.util.module_from_spec(aes_accelerated_arm_cleanup_spec)
aes_accelerated_arm_cleanup_spec.loader.exec_module(aes_accelerated_arm_cleanup_tests)
AesAcceleratedArmCleanupTests = aes_accelerated_arm_cleanup_tests.AcceleratedArmCleanupTests

aes_accelerated_arm_constructor_spec = importlib.util.spec_from_file_location('aes_accelerated_arm_constructor_tests', ROOT / 'scripts/aes/test-aes-accelerated-arm-constructors.py')
aes_accelerated_arm_constructor_tests = importlib.util.module_from_spec(aes_accelerated_arm_constructor_spec)
aes_accelerated_arm_constructor_spec.loader.exec_module(aes_accelerated_arm_constructor_tests)
AesAcceleratedArmConstructorTests = aes_accelerated_arm_constructor_tests.AcceleratedArmConstructorTests

aes_accelerated_arm_cached_spec = importlib.util.spec_from_file_location('aes_accelerated_arm_cached_tests', ROOT / 'scripts/aes/test-aes-accelerated-arm-cached.py')
aes_accelerated_arm_cached_tests = importlib.util.module_from_spec(aes_accelerated_arm_cached_spec)
aes_accelerated_arm_cached_spec.loader.exec_module(aes_accelerated_arm_cached_tests)
AesAcceleratedArmCachedTests = aes_accelerated_arm_cached_tests.AcceleratedArmCachedTests

aes_accelerated_arm_ephemeral_spec = importlib.util.spec_from_file_location('aes_accelerated_arm_ephemeral_tests', ROOT / 'scripts/aes/test-aes-accelerated-arm-ephemeral.py')
aes_accelerated_arm_ephemeral_tests = importlib.util.module_from_spec(aes_accelerated_arm_ephemeral_spec)
aes_accelerated_arm_ephemeral_spec.loader.exec_module(aes_accelerated_arm_ephemeral_tests)
AesAcceleratedArmEphemeralTests = aes_accelerated_arm_ephemeral_tests.AcceleratedArmEphemeralTests
aes_accelerated_arm_session_spec = importlib.util.spec_from_file_location('aes_accelerated_arm_session_tests', ROOT / 'scripts/aes/test-aes-accelerated-arm-sessions.py')
aes_accelerated_arm_session_tests = importlib.util.module_from_spec(aes_accelerated_arm_session_spec)
aes_accelerated_arm_session_spec.loader.exec_module(aes_accelerated_arm_session_tests)
AesAcceleratedArmSessionTests = aes_accelerated_arm_session_tests.AcceleratedArmSessionTests
aes_accelerated_startup_spec = importlib.util.spec_from_file_location('aes_accelerated_startup_tests', ROOT / 'scripts/aes/test-aes-accelerated-startup.py')
aes_accelerated_startup_tests = importlib.util.module_from_spec(aes_accelerated_startup_spec)
aes_accelerated_startup_spec.loader.exec_module(aes_accelerated_startup_tests)
AesAcceleratedStartupTests = aes_accelerated_startup_tests.AcceleratedStartupTests
aes_accelerated_hosted_startup_spec = importlib.util.spec_from_file_location('aes_accelerated_hosted_startup_tests', ROOT / 'scripts/aes/test-aes-accelerated-startup-hosted.py')
aes_accelerated_hosted_startup_tests = importlib.util.module_from_spec(aes_accelerated_hosted_startup_spec)
aes_accelerated_hosted_startup_spec.loader.exec_module(aes_accelerated_hosted_startup_tests)
AesAcceleratedHostedStartupTests = aes_accelerated_hosted_startup_tests.HostedStartupTests
aes_accelerated_x86_startup_spec = importlib.util.spec_from_file_location('aes_accelerated_x86_startup_tests', ROOT / 'scripts/aes/test-aes-accelerated-startup-x86.py')
aes_accelerated_x86_startup_tests = importlib.util.module_from_spec(aes_accelerated_x86_startup_spec)
aes_accelerated_x86_startup_spec.loader.exec_module(aes_accelerated_x86_startup_tests)
AesAcceleratedX86StartupTests = aes_accelerated_x86_startup_tests.X86StartupTests

aes_accelerated_sanitizer_spec = importlib.util.spec_from_file_location('aes_accelerated_sanitizer_tests', ROOT / 'scripts/aes/test-aes-accelerated-sanitizers.py')
aes_accelerated_sanitizer_tests = importlib.util.module_from_spec(aes_accelerated_sanitizer_spec)
aes_accelerated_sanitizer_spec.loader.exec_module(aes_accelerated_sanitizer_tests)
AesAcceleratedSanitizerTests = aes_accelerated_sanitizer_tests.AcceleratedSanitizerTests

aes_accelerated_no_std_spec = importlib.util.spec_from_file_location('aes_accelerated_no_std_tests', ROOT / 'scripts/aes/test-aes-accelerated-no-std.py')
aes_accelerated_no_std_tests = importlib.util.module_from_spec(aes_accelerated_no_std_spec)
aes_accelerated_no_std_spec.loader.exec_module(aes_accelerated_no_std_tests)
AesAcceleratedNoStdTests = aes_accelerated_no_std_tests.AcceleratedNoStdTests

aes_performance_spec = importlib.util.spec_from_file_location('aes_performance_tests', ROOT / 'scripts/aes/test-aes-performance.py')
aes_performance_tests = importlib.util.module_from_spec(aes_performance_spec)
aes_performance_spec.loader.exec_module(aes_performance_tests)
AesPerformanceTests = aes_performance_tests.AesPerformanceTests

aes_accelerated_timing_spec = importlib.util.spec_from_file_location('aes_accelerated_timing_tests', ROOT / 'scripts/aes/test-aes-accelerated-fixed-random.py')
aes_accelerated_timing_tests = importlib.util.module_from_spec(aes_accelerated_timing_spec)
aes_accelerated_timing_spec.loader.exec_module(aes_accelerated_timing_tests)
AesAcceleratedTimingTests = aes_accelerated_timing_tests.AesAcceleratedTimingTests

aes_crossover_spec = importlib.util.spec_from_file_location('aes_crossover_tests', ROOT / 'scripts/aes/test-aes-timing-slot-crossover.py')
aes_crossover_tests = importlib.util.module_from_spec(aes_crossover_spec)
aes_crossover_spec.loader.exec_module(aes_crossover_tests)
AesCrossoverTests = aes_crossover_tests.CrossoverTests

aes_packaged_diff_spec = importlib.util.spec_from_file_location('aes_packaged_diff_tests', ROOT / 'scripts/aes/test-aes-packaged-differential.py')
aes_packaged_diff_tests = importlib.util.module_from_spec(aes_packaged_diff_spec)
aes_packaged_diff_spec.loader.exec_module(aes_packaged_diff_tests)
AesPackagedDifferentialTests = aes_packaged_diff_tests.PackagedDifferentialTests

aes_fixed_random_spec = importlib.util.spec_from_file_location('aes_fixed_random_tests', ROOT / 'scripts/aes/test-aes-fixed-random.py')
aes_fixed_random_tests = importlib.util.module_from_spec(aes_fixed_random_spec)
aes_fixed_random_spec.loader.exec_module(aes_fixed_random_tests)
AesFixedRandomTests = aes_fixed_random_tests.FixedRandomTests

aes_timing_spec = importlib.util.spec_from_file_location('aes_timing_tests', ROOT / 'scripts/aes/test-aes-timing.py')
aes_timing_tests = importlib.util.module_from_spec(aes_timing_spec)
aes_timing_spec.loader.exec_module(aes_timing_tests)
AesTimingTests = aes_timing_tests.TimingTests
aes_wide_timing_spec = importlib.util.spec_from_file_location('aes_wide_timing_tests', ROOT / 'scripts/aes/test-aes-wide-timing.py')
aes_wide_timing_tests = importlib.util.module_from_spec(aes_wide_timing_spec)
aes_wide_timing_spec.loader.exec_module(aes_wide_timing_tests)
AesWideTimingTests = aes_wide_timing_tests.WideTimingTests
aes_differential_spec = importlib.util.spec_from_file_location('aes_differential_tests', ROOT / 'scripts/aes/test-aes-differential.py')
aes_differential_tests = importlib.util.module_from_spec(aes_differential_spec)
aes_differential_spec.loader.exec_module(aes_differential_tests)
AesDifferentialTests = aes_differential_tests.DifferentialTests
aes_dataflow_spec = importlib.util.spec_from_file_location('aes_dataflow_tests', ROOT / 'scripts/aes/test-aes-dataflow.py')
aes_dataflow_tests = importlib.util.module_from_spec(aes_dataflow_spec)
aes_dataflow_spec.loader.exec_module(aes_dataflow_tests)
AesDataflowTests = aes_dataflow_tests.DataflowTests
aes_arm_spec = importlib.util.spec_from_file_location('aes_arm_tests', ROOT / 'scripts/aes/test-aes-aarch64-dataflow.py')
aes_arm_tests = importlib.util.module_from_spec(aes_arm_spec)
aes_arm_spec.loader.exec_module(aes_arm_tests)
AesAarch64DataflowTests = aes_arm_tests.Aarch64DataflowTests
aes_arm_helpers_spec = importlib.util.spec_from_file_location('aes_arm_helper_tests', ROOT / 'scripts/aes/test-aes-aarch64-helpers.py')
aes_arm_helper_tests = importlib.util.module_from_spec(aes_arm_helpers_spec)
aes_arm_helpers_spec.loader.exec_module(aes_arm_helper_tests)
AesAarch64HelperTests = aes_arm_helper_tests.Aarch64HelperTests
aes_arm_rounds_spec = importlib.util.spec_from_file_location('aes_arm_round_tests', ROOT / 'scripts/aes/test-aes-aarch64-rounds.py')
aes_arm_round_tests = importlib.util.module_from_spec(aes_arm_rounds_spec)
aes_arm_rounds_spec.loader.exec_module(aes_arm_round_tests)
AesAarch64RoundTests = aes_arm_round_tests.Aarch64RoundTests
aes_arm_wrappers_spec = importlib.util.spec_from_file_location('aes_arm_wrapper_tests', ROOT / 'scripts/aes/test-aes-aarch64-wrappers.py')
aes_arm_wrapper_tests = importlib.util.module_from_spec(aes_arm_wrappers_spec)
aes_arm_wrappers_spec.loader.exec_module(aes_arm_wrapper_tests)
AesAarch64WrapperTests = aes_arm_wrapper_tests.Aarch64WrapperTests
aes_arm_core_spec = importlib.util.spec_from_file_location('aes_arm_core_tests', ROOT / 'scripts/aes/test-aes-aarch64-core.py')
aes_arm_core_tests = importlib.util.module_from_spec(aes_arm_core_spec)
aes_arm_core_spec.loader.exec_module(aes_arm_core_tests)
AesAarch64CoreTests = aes_arm_core_tests.Aarch64CoreTests
aes_arm_public_spec = importlib.util.spec_from_file_location('aes_arm_public_tests', ROOT / 'scripts/aes/test-aes-aarch64-public.py')
aes_arm_public_tests = importlib.util.module_from_spec(aes_arm_public_spec)
aes_arm_public_spec.loader.exec_module(aes_arm_public_tests)
AesAarch64PublicTests = aes_arm_public_tests.Aarch64PublicTests
aes_arm_constructors_spec = importlib.util.spec_from_file_location('aes_arm_constructors_tests', ROOT / 'scripts/aes/test-aes-aarch64-constructors.py')
aes_arm_constructors_tests = importlib.util.module_from_spec(aes_arm_constructors_spec)
aes_arm_constructors_spec.loader.exec_module(aes_arm_constructors_tests)
AesAarch64ConstructorTests = aes_arm_constructors_tests.Aarch64ConstructorTests
aes_arm_callers_spec = importlib.util.spec_from_file_location('aes_arm_callers_tests', ROOT / 'scripts/aes/test-aes-aarch64-callers.py')
aes_arm_callers_tests = importlib.util.module_from_spec(aes_arm_callers_spec)
aes_arm_callers_spec.loader.exec_module(aes_arm_callers_tests)
AesAarch64CallerTests = aes_arm_callers_tests.Aarch64CallerTests
aes_arm_native_spec = importlib.util.spec_from_file_location('aes_arm_native_tests', ROOT / 'scripts/aes/test-aes-aarch64-native.py')
aes_arm_native_tests = importlib.util.module_from_spec(aes_arm_native_spec)
aes_arm_native_spec.loader.exec_module(aes_arm_native_tests)
AesAarch64NativeTests = aes_arm_native_tests.Aarch64NativeTests
aes_arm_linked_spec = importlib.util.spec_from_file_location('aes_arm_linked_tests', ROOT / 'scripts/aes/test-aes-aarch64-linked.py')
aes_arm_linked_tests = importlib.util.module_from_spec(aes_arm_linked_spec)
aes_arm_linked_spec.loader.exec_module(aes_arm_linked_tests)
AesAarch64LinkedTests = aes_arm_linked_tests.Aarch64LinkedTests

aes_arm_linked_wrappers_spec = importlib.util.spec_from_file_location('aes_arm_linked_wrapper_tests', ROOT / 'scripts/aes/test-aes-aarch64-linked-wrappers.py')
aes_arm_linked_wrappers_tests = importlib.util.module_from_spec(aes_arm_linked_wrappers_spec)
aes_arm_linked_wrappers_spec.loader.exec_module(aes_arm_linked_wrappers_tests)
AesAarch64LinkedWrapperTests = aes_arm_linked_wrappers_tests.Aarch64LinkedWrapperTests
aes_arm_linked_public_spec = importlib.util.spec_from_file_location('aes_arm_linked_public_tests', ROOT / 'scripts/aes/test-aes-aarch64-linked-public.py')
aes_arm_linked_public_tests = importlib.util.module_from_spec(aes_arm_linked_public_spec)
aes_arm_linked_public_spec.loader.exec_module(aes_arm_linked_public_tests)
AesAarch64LinkedPublicTests = aes_arm_linked_public_tests.Aarch64LinkedPublicTests
aes_arm_linked_cleanup_spec = importlib.util.spec_from_file_location('aes_arm_linked_cleanup_tests', ROOT / 'scripts/aes/test-aes-aarch64-linked-cleanup.py')
aes_arm_linked_cleanup_tests = importlib.util.module_from_spec(aes_arm_linked_cleanup_spec)
aes_arm_linked_cleanup_spec.loader.exec_module(aes_arm_linked_cleanup_tests)
AesAarch64LinkedCleanupTests = aes_arm_linked_cleanup_tests.Aarch64LinkedCleanupTests
aes_linked_spec = importlib.util.spec_from_file_location('aes_linked_tests', ROOT / 'scripts/aes/test-aes-linked.py')
aes_linked_tests = importlib.util.module_from_spec(aes_linked_spec)
aes_linked_spec.loader.exec_module(aes_linked_tests)
AesLinkedTests = aes_linked_tests.LinkedTests
aes_linked_helpers_spec = importlib.util.spec_from_file_location('aes_linked_helper_tests', ROOT / 'scripts/aes/test-aes-linked-helpers.py')
aes_linked_helper_tests = importlib.util.module_from_spec(aes_linked_helpers_spec)
aes_linked_helpers_spec.loader.exec_module(aes_linked_helper_tests)
AesLinkedHelperTests = aes_linked_helper_tests.LinkedHelperTests
aes_linked_mix_spec = importlib.util.spec_from_file_location('aes_linked_mix_tests', ROOT / 'scripts/aes/test-aes-linked-mix.py')
aes_linked_mix_tests = importlib.util.module_from_spec(aes_linked_mix_spec)
aes_linked_mix_spec.loader.exec_module(aes_linked_mix_tests)
AesLinkedMixTests = aes_linked_mix_tests.LinkedMixTests
aes_linked_sub_spec = importlib.util.spec_from_file_location('aes_linked_sub_tests', ROOT / 'scripts/aes/test-aes-linked-substitute.py')
aes_linked_sub_tests = importlib.util.module_from_spec(aes_linked_sub_spec)
aes_linked_sub_spec.loader.exec_module(aes_linked_sub_tests)
AesLinkedSubstituteTests = aes_linked_sub_tests.LinkedSubstituteTests
aes_linked_round_spec = importlib.util.spec_from_file_location('aes_linked_round_tests', ROOT / 'scripts/aes/test-aes-linked-rounds.py')
aes_linked_round_tests = importlib.util.module_from_spec(aes_linked_round_spec)
aes_linked_round_spec.loader.exec_module(aes_linked_round_tests)
AesLinkedRoundsTests = aes_linked_round_tests.LinkedRoundsTests
aes_lifecycle_spec = importlib.util.spec_from_file_location('aes_lifecycle_tests', ROOT / 'scripts/aes/test-aes-linked-lifecycle.py')
aes_lifecycle_tests = importlib.util.module_from_spec(aes_lifecycle_spec)
aes_lifecycle_spec.loader.exec_module(aes_lifecycle_tests)
AesLinkedLifecycleTests = aes_lifecycle_tests.LinkedLifecycleTests
aes_wrapper_spec = importlib.util.spec_from_file_location('aes_wrapper_tests', ROOT / 'scripts/aes/test-aes-linked-wrappers.py')
aes_wrapper_tests = importlib.util.module_from_spec(aes_wrapper_spec)
aes_wrapper_spec.loader.exec_module(aes_wrapper_tests)
AesLinkedWrapperTests = aes_wrapper_tests.LinkedWrapperTests
aes_public_spec = importlib.util.spec_from_file_location('aes_public_tests', ROOT / 'scripts/aes/test-aes-linked-public.py')
aes_public_tests = importlib.util.module_from_spec(aes_public_spec)
aes_public_spec.loader.exec_module(aes_public_tests)
AesLinkedPublicTests = aes_public_tests.LinkedPublicTests
aes_cleanup_spec = importlib.util.spec_from_file_location('aes_cleanup_tests', ROOT / 'scripts/aes/test-aes-linked-cleanup.py')
aes_cleanup_tests = importlib.util.module_from_spec(aes_cleanup_spec)
aes_cleanup_spec.loader.exec_module(aes_cleanup_tests)
AesLinkedCleanupTests = aes_cleanup_tests.LinkedCleanupTests
sys.path.insert(0, str(ROOT / 'scripts/cryptography'))
aes_contract_spec = importlib.util.spec_from_file_location('aes_contract_tests', ROOT / 'scripts/cryptography/test-aes-owner-contract.py')
aes_contract_tests = importlib.util.module_from_spec(aes_contract_spec)
aes_contract_spec.loader.exec_module(aes_contract_tests)
AesDevelopmentOwnerTests = aes_contract_tests.OwnerContractTests

wide_contract_spec = importlib.util.spec_from_file_location('aes_wide_contract_tests', ROOT / 'scripts/cryptography/test-aes-wide-owner-contract.py')
wide_contract_tests = importlib.util.module_from_spec(wide_contract_spec)
wide_contract_spec.loader.exec_module(wide_contract_tests)
AesWideDevelopmentOwnerTests = wide_contract_tests.WideOwnerTests

provider_spec = importlib.util.spec_from_file_location('aes_provider_tests', ROOT / 'scripts/aes/test-aes-provider-runner.py')
provider_tests = importlib.util.module_from_spec(provider_spec)
provider_spec.loader.exec_module(provider_tests)
AesProviderRunnerTests = provider_tests.ProviderRunnerTests

# Reviewed, explicit build closures for these portable harness commands only.
# This is not automatic feature/dependency analysis or a release-family planner.
CLOSURES = {
    'brynja-legacy-hkdf': {'brynja-core', 'brynja-hash-core', 'brynja-legacy-hmac',
                          'brynja-legacy-sha1', 'brynja-legacy-md5'},
    # HKDF metadata is tested through the composition crate, so its default
    # compiled dependencies remain declared even though no hash is exercised.
    'brynja-crypto': {'brynja-core', 'brynja-hash-core', 'brynja-hash-sha2',
                      'brynja-hash-sha3', 'brynja-hash-tuple', 'brynja-hash-parallel',
                      'brynja-mac-kmac', 'brynja-mac-hmac'},
    'brynja-legacy-md5': {'brynja-core', 'brynja-hash-core'},
    'brynja-legacy-sha1': {'brynja-core', 'brynja-hash-core'},
    'brynja-hash-sha2': {'brynja-core', 'brynja-hash-core'},
    'brynja-hash-sha3': {'brynja-core', 'brynja-hash-core'},
    'brynja-mac-kmac': {'brynja-core', 'brynja-hash-core', 'brynja-hash-sha3'},
    'brynja-hash-tuple': {'brynja-core', 'brynja-hash-core', 'brynja-hash-sha3'},
    'brynja-mac-hmac': {'brynja-core', 'brynja-hash-core', 'brynja-hash-sha2', 'brynja-hash-sha3'},
    'brynja-legacy-hmac': {'brynja-core', 'brynja-hash-core', 'brynja-legacy-md5', 'brynja-legacy-sha1'},
    # Cargo builds these dev dependencies even though the portable vector
    # harness does not request native execution. Their inputs are not omitted.
    'brynja-hash-parallel': {'brynja-core', 'brynja-hash-core', 'brynja-hash-sha3',
                           'brynja-hash-sha2', 'brynja-crypto-cpu', 'brynja-crypto-cpu-std'},
}


def validate(registry):
    seen = set()
    for check in registry['checks']:
        if check.get('category', 'portable') != 'portable':
            continue
        key = (check['component'], check['id'])
        assert key not in seen, 'duplicate check'
        seen.add(key)
        argv = check['command']
        assert argv[:3] == ['cargo', '+1.99.1', 'test'], 'unexpected executable'
        assert all(flag in argv for flag in ('--offline', '--locked', '--no-default-features'))
        assert '--workspace' not in argv and '--all-features' not in argv
        package = argv[argv.index('-p') + 1]
        if '--lib' in argv:
            assert key == ('hkdf', 'parameters'), 'unexpected library test selection'
            assert argv[-2:] == ['--lib', 'hkdf::parameters::tests::']
            test = 'crates/brynja-crypto/src/hkdf/parameter_tests.rs'
        else:
            assert '--test' in argv, 'missing test harness selection'
            harness = argv[argv.index('--test') + 1]
            test = f'crates/{package}/tests/{harness}.rs'
        assert package in CLOSURES
        groups = [registry['groups'][name] for name in check['inputs']]
        paths = {path for group in groups for path in group.get('paths', [])}
        manifests = {path for group in groups for path in group.get('toml', {})}
        locks = {name for group in groups for lock in group.get('locks', []) for name in lock['packages']}
        for name in CLOSURES[package] | {package}:
            assert f'crates/{name}/src' in paths, f'missing source: {name}'
            assert f'crates/{name}/Cargo.toml' in manifests, f'missing manifest: {name}'
            assert name in locks, f'missing lock row: {name}'
        assert test in paths, 'missing harness input'
        source = (ROOT / test).read_text()
        assert check['success']['minimum_tests'] >= 1
        for marker in check['success']['contains']:
            if marker.startswith('test ') and marker.endswith(' ... ok'):
                name = marker.removeprefix('test ').removesuffix(' ... ok')
                assert re.search(r'#\[test\]\s*fn ' + re.escape(name) + r'\(', source), marker
        for path in paths:
            assert (ROOT / path).exists(), f'missing input: {path}'
        assert not any(path in ('verification/results.json', 'docs/VERIFICATION_RESULTS.md') for path in paths)
    assert {c['command'][c['command'].index('-p') + 1] for c in registry['checks'] if c.get('category', 'portable') == 'portable'} == set(CLOSURES)


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = tomllib.loads((ROOT / 'verification/checks.toml').read_text())

    def test_registered_harnesses_and_explicit_closures(self):
        validate(self.registry)

    def test_aes_initial_checks_pin_harnesses_and_counts(self):
        checks = {c['id']: c for c in self.registry['checks'] if c['component'] == 'aes'}
        expected = {'vectors': 6, 'rounds-and-faults': 17, 'msrv-vectors': 6,
                    'ownership': 11, 'optimized-vectors': 6, 'no-std-thumb': 0,
                    'asan-vectors': 6, 'miri-ownership': 1, 'asan-faults': 17,
                    'miri-public': 1, 'differential': 1, 'field-layout-proof': 0,
                    'api-msrv': 0, 'api-current': 0, 'mutation-controls': 0,
                    'owner-dispatch': 0, 'operation-cleanup': 0, 'owner-contract': 0,
                    'downstream': 0, 'downstream-matrix': 0, 'timing-screen': 0,
                    'dataflow-review': 0, 'aarch64-dataflow-review': 0, 'aarch64-linked-helpers-review': 0, 'provider-native': 16, 'provider-msrv': 16,
                    'provider-asan': 16, 'provider-miri': 16, 'provider-api-current': 0,
                    'provider-api-msrv': 0, 'provider-no-std': 0, 'provider-docs': 1,
                    'wide-vectors': 8, 'wide-msrv-vectors': 8, 'wide-optimized-vectors': 8,
                    'wide-asan-vectors': 8, 'wide-miri-ownership': 2,
                    'wide-api-msrv': 0, 'wide-api-current': 0,
                    'wide-kat': 4, 'wide-msrv-kat': 4, 'wide-optimized-kat': 4,
                    'wide-asan-kat': 4, 'wide-differential': 2, 'wide-operation-cleanup': 0,
                    'wide-timing-screen': 0, 'packaged-portable': 0,
                    'avs-msrv-direct': 12, 'avs-msrv-facade': 12,
                    'avs-current-direct': 12, 'avs-current-facade': 12,
                    'packaged-diff-msrv-direct': 8, 'packaged-diff-msrv-facade': 8,
                    'packaged-diff-current-direct': 8, 'packaged-diff-current-facade': 8,
                    'packaged-fixed-random-msrv': 4, 'packaged-fixed-random-current': 4,
                    'packaged-fixed-random-arm-msrv': 4, 'packaged-fixed-random-arm-current': 4,
                    'packaged-arm-native-msrv': 0, 'packaged-arm-native-current': 0,
                    'packaged-linked-msrv': 0, 'packaged-linked-current': 0,
                    'packaged-lifecycle-msrv': 0, 'packaged-lifecycle-current': 0}
        for endpoint in ('msrv', 'current'):
            expected[f'accelerated-arm-startup-{endpoint}'] = 0
            expected[f'accelerated-arm-hosted-startup-{endpoint}'] = 0
            expected[f'accelerated-x86-startup-{endpoint}'] = 0
            expected[f'accelerated-public-linked-{endpoint}'] = 0
            expected[f'accelerated-secret-linked-{endpoint}'] = 0
            expected[f'accelerated-ephemeral-linked-{endpoint}'] = 0
            expected[f'accelerated-ephemeral-public-linked-{endpoint}'] = 0
            expected[f'accelerated-lifecycle-linked-{endpoint}'] = 0
            for admission in ('static', 'hosted'):
                expected[f'accelerated-arm-cleanup-{admission}-{endpoint}'] = 0
                expected[f'accelerated-arm-constructors-{admission}-{endpoint}'] = 0
                expected[f'accelerated-arm-cached-{admission}-{endpoint}'] = 0
                expected[f'accelerated-arm-ephemeral-{admission}-{endpoint}'] = 0
            for mode, admission in (('native', 'static'), ('arm-qemu', 'static'), ('arm-qemu', 'hosted')):
                expected[f'accelerated-linked-{mode}-{admission}-{endpoint}'] = 0
            for route in ('direct', 'facade'):
                for admission, mode, suite in (('static', 'native', 'avs'),
                                                ('static', 'native', 'differential'),
                                                ('static', 'arm-qemu', 'avs'),
                                                ('hosted', 'arm-qemu', 'avs')):
                    expected[f'accelerated-{suite}-{admission}-{mode}-{endpoint}-{route}'] = 8 if suite == 'differential' else 12
            expected[f'execution-api-{endpoint}'] = 0
            for mode in ('native', 'arm-qemu'):
                expected[f'hosted-{mode}-{endpoint}'] = 6
                expected[f'dit-{mode}-{endpoint}'] = 11 if mode == 'arm-qemu' else 4
            for mode in ('native', 'baseline', 'arm-qemu'):
                expected[f'static-{mode}-{endpoint}'] = 7 if mode == 'baseline' else 26
            for arch in ('x86', 'arm-qemu'):
                expected[f'kernel-{arch}-{endpoint}'] = 5
                expected[f'expansion-{arch}-{endpoint}'] = 10
            for profile, count in (('minimal', 32), ('all', 98)):
                expected[f'feature-{endpoint}-{profile}-test'] = count
                expected[f'feature-{endpoint}-{profile}-doc'] = 0
        for route in ('direct', 'facade'):
            expected[f'accelerated-sanitizers-{route}'] = 26
            for compiler in ('msrv', 'current'):
                expected[f'accelerated-no-std-{route}-{compiler}'] = 0
                expected[f'performance-fixture-{route}-{compiler}'] = 4
                expected[f'accelerated-timing-fixture-{route}-{compiler}'] = 4
                expected[f'timing-controls-fixture-{route}-{compiler}'] = 8
                expected[f'timing-dispatch-fixture-{route}-{compiler}'] = 10
                expected[f'timing-batch-fixture-{route}-{compiler}'] = 10
                expected[f'timing-crossover-fixture-{route}-{compiler}'] = 13
        self.assertEqual(set(checks), set(expected))
        for name, count in expected.items():
            check = checks[name]
            for field in ('component', 'id', 'category'):
                self.assertRegex(check[field], r'^[a-z0-9_-]+$')
            input_group = ('aes-kernel-candidate' if name.startswith('kernel-') else
                           'aes-packaged' if name.startswith(('packaged-', 'avs-')) else 'aes-build')
            self.assertIn(input_group, check['inputs'])
            self.assertNotIn('--workspace', check['command'])
            if check['command'][0] == 'cargo':
                command = check['command']
                if name.startswith('feature-'):
                    _, endpoint, profile, action = name.split('-')
                    version = '1.90.0' if endpoint == 'msrv' else '1.99.1'
                    flag = '--no-default-features' if profile == 'minimal' else '--all-features'
                    self.assertEqual(command, ['cargo', '+'+version, action, '--locked', '--offline',
                                             '-p', 'brynja-crypto', '-p', 'brynja', flag]
                                     + (['--no-deps'] if action == 'doc' else []))
                    self.assertIn('aes-feature-integration', check['inputs'])
                    self.assertEqual(self.registry['groups']['aes-feature-integration']['paths'],
                                     ['Cargo.toml', 'Cargo.lock', 'crates'])
                    self.assertIn('LD_LIBRARY_PATH', check['reject_environment'])
                    if action == 'doc':
                        self.assertEqual(check['success']['contains'], ['Generated'])
                    self.assertEqual(check['success'].get('allow_ignored', False),
                                     action == 'test' and profile == 'all')
                else:
                    self.assertIn('--features', command)
                    features = 'hazmat-aes-block,external-key-provider' if name.startswith('provider-') else 'hazmat-aes-block'
                    self.assertEqual(command[command.index('--features') + 1], features)
            if count:
                self.assertEqual(check['success']['exact_tests'], count)
                self.assertEqual(check['success']['minimum_tests'], count)
            self.assertIn('RUSTC_WRAPPER', check['reject_environment'])
        self.assertEqual(checks['rounds-and-faults']['command'][-2:], ['--lib', 'aes::'])
        self.assertEqual(checks['ownership']['command'][-2:], ['--doc', 'aes::'])
        for name in ('wide-vectors', 'wide-msrv-vectors', 'wide-optimized-vectors',
                     'wide-asan-vectors', 'wide-miri-ownership'):
            command = checks[name]['command']
            self.assertEqual(command[command.index('--test') + 1], 'aes_wide')
        for name, version in (('wide-api-msrv', '1.90.0'), ('wide-api-current', '1.99.1')):
            self.assertEqual(checks[name]['command'], ['python3', 'scripts/aes/check-aes-wide-api.py', version])
            self.assertEqual(checks[name]['success']['unique_lines'], [f'AES_WIDE_API_PASS: {version} 76 paired probes'])
        self.assertIn('crates/brynja-crypto/tests/aes_wide.rs', self.registry['groups']['aes-build']['paths'])
        for name in ('wide-kat', 'wide-msrv-kat', 'wide-optimized-kat', 'wide-asan-kat'):
            command = checks[name]['command']
            self.assertEqual(command[command.index('--test') + 1], 'aes_wide_kat')
            self.assertEqual(command[-2:], ['--', '--nocapture'])
            self.assertEqual(checks[name]['success']['unique_lines'],
                             ['AES192_KAT_RECORDS: 700', 'AES256_KAT_RECORDS: 810'])
        oracle = checks['wide-differential']
        for name, suite in (('wide-differential', 'wide'), ('differential', '128')):
            registered = checks[name]
            self.assertEqual(registered['command'], ['python3', 'scripts/aes/check-aes-differential.py', suite])
            self.assertIn('aes-differential-runner', registered['inputs'])
            self.assertIn('BRYNJA_OPENSSL', registered['reject_environment'])
            for variable in ('LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'OPENSSL_ia32cap'):
                self.assertIn(variable, registered['reject_environment'])
            self.assertIn('Independent oracle SHA-256:', registered['success']['contains'])
            self.assertIn('AES differential executable identity: unchanged; shared libraries not measured', registered['success']['unique_lines'])
        self.assertEqual(oracle['success']['unique_lines'],
                         ['AES differential executable identity: unchanged; shared libraries not measured'] +
                         [f'AES{bits}_{cache}OPENSSL_COMPARISONS: 4096' for bits in (192, 256) for cache in ('', 'CACHED_')])
        self.assertIn('aes-oracle', oracle['inputs'])
        self.assertEqual(checks['miri-ownership']['command'][-3:],
                         ['output_outlives_key_and_explicit_clear_preserves_canaries', '--', '--exact'])
        for name in ('vectors','msrv-vectors','optimized-vectors','asan-vectors'):
            command = checks[name]['command']
            self.assertEqual(command[command.index('--test') + 1], 'aes128')
        sanitizer = checks['asan-vectors']
        self.assertEqual(sanitizer['command'][:3], ['cargo', '+nightly-2026-09-11', 'test'])
        self.assertEqual(sanitizer['environment']['RUSTFLAGS'], '-Zsanitizer=address')
        self.assertEqual(sanitizer['environment']['ASAN_OPTIONS'], 'detect_leaks=1:halt_on_error=1:exitcode=1')
        self.assertEqual(sanitizer['environment']['LSAN_OPTIONS'], 'exitcode=23')
        self.assertEqual(sanitizer['environment']['CARGO_ENCODED_RUSTFLAGS'], '')
        self.assertIn('asan-tools', sanitizer['inputs'])
        miri = checks['miri-ownership']
        self.assertEqual(miri['command'][:4], ['cargo', '+nightly-2026-09-11', 'miri', 'test'])
        self.assertEqual(miri['environment']['MIRIFLAGS'], '-Zmiri-report-progress=10000000')
        self.assertIn('miri-tools', miri['inputs'])
        for check in (sanitizer, miri):
            self.assertEqual(check['platform'], 'linux-x86_64')
            self.assertEqual(check['environment']['RUSTUP_AUTO_INSTALL'], '0')

        self.assertEqual(checks['asan-faults']['environment'], sanitizer['environment'])
        self.assertEqual(checks['asan-faults']['command'][-4:],
                         ['--lib', '--target', 'x86_64-unknown-linux-gnu', 'aes::'])
        self.assertEqual(checks['miri-public']['environment'], miri['environment'])
        self.assertEqual(checks['miri-public']['command'][-3:],
                         ['public_ciphertext_commit_preserves_inputs_and_canaries', '--', '--exact'])
        oracle = checks['differential']
        self.assertEqual(oracle['command'], ['python3', 'scripts/aes/check-aes-differential.py', '128'])
        self.assertEqual(oracle['success']['unique_lines'], ['AES differential executable identity: unchanged; shared libraries not measured', 'AES_OPENSSL_COMPARISONS: 4096', 'AES_CACHED_OPENSSL_COMPARISONS: 4096'])
        self.assertIn('aes-oracle', oracle['inputs'])
        self.assertEqual(self.registry['groups']['aes-oracle']['tools'], [{'program': 'openssl'}])

    def test_aes_downstream_binding_and_dependency_closure(self):
        check = next(c for c in self.registry['checks'] if c['component'] == 'aes' and c['id'] == 'downstream')
        consumer = aes_consumer_tests.consumer
        self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-consumer.py'])
        self.assertEqual(check['success']['contains'], ['AES downstream: PASS;'])
        self.assertEqual(check['success']['unique_lines'], [consumer.MARKER] + [
            f'AES_DOWNSTREAM_HOST: {compiler} {route} {profile} 18 exact tests'
            for compiler in consumer.TOOLCHAINS for route in consumer.ROUTES for profile in ('debug', 'release')
        ] + [f'AES_DOWNSTREAM_TARGET: {compiler} {route} thumbv7em-none-eabi compile-only'
             for compiler in consumer.TOOLCHAINS for route in consumer.ROUTES] + consumer.FEATURE_MARKERS)
        self.assertTrue({'aes-build', 'aes-consumer', 'compiler', 'hkdf-msrv'} <= set(check['inputs']))
        paths = self.registry['groups']['aes-consumer']['paths']
        for name in consumer.FACADE:
            self.assertIn('crates/' + name, paths)
        for name in consumer.FILES:
            self.assertIn('assurance/aes-public-api/' + name, paths)
        for name in ('scripts/aes/check-aes-consumer.py', 'scripts/aes/test-aes-consumer.py',
                     'scripts/hmac/hmac_verifiers.py', 'scripts/repository/facade_cargo_environment.py'):
            self.assertIn(name, paths)

    def test_aes_consumer_matrix_exact_compilers_and_population(self):
        consumer = aes_consumer_tests.consumer
        check = next(c for c in self.registry['checks'] if c['component'] == 'aes' and c['id'] == 'downstream-matrix')
        self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-consumer.py', '--matrix'])
        self.assertIn('hkdf-public-api-matrix', check['inputs'])
        tools = self.registry['groups']['hkdf-public-api-matrix']['tools']
        self.assertEqual({(t['program'], t['toolchain']) for t in tools},
                         {(program, compiler) for compiler in consumer.MATRIX for program in ('cargo', 'rustc')})
        self.assertEqual(check['success']['unique_lines'], [consumer.MATRIX_MARKER] + [
            f'AES_DOWNSTREAM_HOST: {compiler} {route} {profile} 18 exact tests'
            for compiler in consumer.MATRIX for route in consumer.ROUTES for profile in ('debug', 'release')
        ] + [f'AES_DOWNSTREAM_TARGET: {compiler} {route} thumbv7em-none-eabi compile-only'
             for compiler in consumer.TOOLCHAINS for route in consumer.ROUTES] + consumer.FEATURE_MARKERS)

    def test_aes_timing_scope_and_full_input_closure(self):
        check = next(c for c in self.registry['checks'] if c['component'] == 'aes' and c['id'] == 'timing-screen')
        self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-timing.py'])
        self.assertEqual(check['platform'], 'linux-x86_64')
        self.assertIn(aes_timing_tests.timing.MARKER, check['success']['unique_lines'])
        self.assertTrue({'aes-build', 'aes-timing', 'aes-oracle', 'compiler', 'hash-core'} <= set(check['inputs']))
        paths = self.registry['groups']['aes-timing']['paths']
        for path in ('assurance/aes-timing/Cargo.toml', 'assurance/aes-timing/Cargo.lock',
                     'assurance/aes-timing/src', 'scripts/aes/check-aes-timing.py',
                     'scripts/aes/test-aes-timing.py', 'scripts/hmac/hmac_timing.py',
                     'scripts/hmac/hmac_verifiers.py', 'scripts/repository/facade_cargo_environment.py'):
            self.assertIn(path, paths)

    def test_aes_wide_timing_scope_and_full_input_closure(self):
        check = next(c for c in self.registry['checks'] if c['component'] == 'aes' and c['id'] == 'wide-timing-screen')
        self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-wide-timing.py'])
        self.assertEqual(check['platform'], 'linux-x86_64')
        self.assertEqual(check['success']['unique_lines'], ['Independent AES wide timing preflight: PASS',
                         aes_wide_timing_tests.timing.MARKER,
                         'Observation only; not constant-time, cache, cross-target or independent qualification'])
        self.assertTrue({'aes-build', 'aes-timing', 'aes-wide-timing', 'aes-oracle', 'compiler', 'hash-core'} <= set(check['inputs']))
        self.assertEqual(set(self.registry['groups']['aes-wide-timing']['paths']), {
            'scripts/aes/check-aes-wide-timing.py', 'scripts/aes/test-aes-wide-timing.py'})
        self.assertIn('assurance/aes-timing/src', self.registry['groups']['aes-timing']['paths'])
        self.assertIn('PYTHONOPTIMIZE', check['reject_environment'])
        self.assertGreaterEqual(check['log_bytes'], 4 * 1024 * 1024)

    def test_aes_proof_and_diagnostic_bindings(self):
        checks = {c['id']: c for c in self.registry['checks'] if c['component'] == 'aes'}
        proof = checks['field-layout-proof']
        self.assertEqual(proof['command'], ['python3', 'scripts/aes/check-aes-kani.py'])
        self.assertEqual(proof['success']['unique_lines'], [aes_runner_tests.kani.MARKER])
        self.assertTrue({'kani-tools', 'kani-setup', 'aes-proof'} <= set(proof['inputs']))
        for name, version, tool in [('api-msrv', '1.90.0', 'hkdf-msrv'), ('api-current', '1.99.1', 'compiler')]:
            check = checks[name]
            self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-api.py', version])
            self.assertEqual(check['success']['unique_lines'], [f'AES_API_PASS: {version} 58 paired probes'])
            self.assertTrue({tool, 'aes-build', 'aes-runner'} <= set(check['inputs']))
        for group in ('aes-proof', 'aes-runner'):
            paths = self.registry['groups'][group]['paths']
            for path in ('scripts/aes/test-aes-runners.py', 'scripts/hmac/hmac_verifiers.py',
                         'scripts/repository/facade_cargo_environment.py'):
                self.assertIn(path, paths)
            self.assertTrue(all((ROOT / path).exists() for path in paths))

    def test_aes_nist_fixture_integrity_and_package_inclusion(self):
        directory = ROOT / 'crates/brynja-crypto/tests/fixtures/aes128'
        expected = {
            'ECBGFSbox128.rsp': '8fd29513660c25497cd7a491792b8d16bb209d1a176fa5294ec65d1e71db9b20',
            'ECBKeySbox128.rsp': '4e1f2d023fd7f1c23e9296c0ced224021c0dc83d6259099869e578daa54bbdec',
            'ECBVarKey128.rsp': 'f2af24115a5e5e3b1e050b9652ca49d8027632f0c663fb1db89ba22bd3878b1f',
            'ECBVarTxt128.rsp': '0f293b0d0b5958e67403b838f771f9bb78ed413bbce1ec62229331ca0a19b244',
        }
        self.assertEqual({p.name for p in directory.glob('*.rsp')}, set(expected))
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((directory / name).read_bytes()).hexdigest(), digest)
        manifest = tomllib.loads((ROOT / 'crates/brynja-crypto/Cargo.toml').read_text())
        self.assertIn('tests/fixtures/aes128/*', manifest['package']['include'])
        self.assertIn('crates/brynja-crypto/tests/fixtures/aes128',
                      self.registry['groups']['aes-build']['paths'])

    def test_wide_aes_fixtures_and_package_inclusion(self):
        expected = {
            (192, 'ECBGFSbox192.rsp'): 'bee6349ecc3ab031db9b6effc3632f54ddd49287d27257693261972c35abb1db',
            (192, 'ECBKeySbox192.rsp'): '0e08371b787b8e1663f92c8941f4cb60d9afc558fd1f25c4b0e29e43772cfc38',
            (192, 'ECBVarKey192.rsp'): '4d6a3d6f8e4e5d6745f37b0c41191e25f029c32810e69288919d7e85a081944a',
            (192, 'ECBVarTxt192.rsp'): 'a41f30d494e25a2a6618d4dfd0ca0b33fe563fe1efeb8529134ab602ac2d9a28',
            (256, 'ECBGFSbox256.rsp'): '6669478d69cd45d4f64549bb3c78389a0fb01eae149d804a8cccc9713ea0d511',
            (256, 'ECBKeySbox256.rsp'): '323077de259a06dcb2abf389d4e60cd3399d8608e6253504b103a4ce68b08171',
            (256, 'ECBVarKey256.rsp'): 'ae2de0c7f11b8d52867db67a17521e8ef9eaa047febe22339ececb2d02c15329',
            (256, 'ECBVarTxt256.rsp'): '6541ad108a78256d6ddefe34283c3037112f893626daf7acfab9cca278196c1c',
        }
        manifest = tomllib.loads((ROOT / 'crates/brynja-crypto/Cargo.toml').read_text())
        for bits in (192, 256):
            relative = f'crates/brynja-crypto/tests/fixtures/aes{bits}'
            directory = ROOT / relative
            self.assertEqual({p.name for p in directory.iterdir()}, {'README.md'} | {n for (b, n) in expected if b == bits})
            self.assertIn(f'tests/fixtures/aes{bits}/*', manifest['package']['include'])
            self.assertIn(relative, self.registry['groups']['aes-build']['paths'])
        for (bits, name), digest in expected.items():
            path = ROOT / f'crates/brynja-crypto/tests/fixtures/aes{bits}' / name
            self.assertFalse(path.is_symlink())
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_aes_mutation_and_codegen_scope(self):
        checks = {c['id']: c for c in self.registry['checks'] if c['component'] == 'aes'}
        mutation = checks['mutation-controls']
        self.assertEqual(mutation['command'], ['python3', 'scripts/aes/check-aes-mutations.py'])
        self.assertEqual(mutation['success']['unique_lines'], [aes_runner_tests.mutation.MARKER] +
                         ['AES_MUTATION_REJECTED: ' + m[0] for m in aes_runner_tests.mutation.MUTATIONS] +
                         [aes_runner_tests.mutation.SCRATCH_MARKER])
        self.assertTrue({'aes-mutations', 'compiler', 'hash-core'} <= set(mutation['inputs']))
        owner = checks['owner-dispatch']
        self.assertEqual(owner['command'], ['python3', 'scripts/aes/check-aes-owner-cleanup.py'])
        self.assertEqual(owner['platform'], 'linux-x86_64')
        self.assertTrue({'aes-owner-codegen', 'compiler', 'hkdf-msrv'} <= set(owner['inputs']))
        self.assertEqual(owner['success']['unique_lines'], [aes_runner_tests.owner.MARKER] +
                         [f'AES owner dispatch: PASS; Rust {compiler}; x86_64; panic={panic}; 7 probes; 12 rejected IR mutations'
                          for compiler in ('1.90.0', '1.99.1') for panic in ('abort', 'unwind')])
        paths = self.registry['groups']['aes-owner-codegen']['paths']
        for helper in ('scripts/hkdf/hkdf_owner_codegen.py', 'scripts/hmac/hmac_engine_codegen.py',
                       'scripts/hmac/hmac_verifiers.py', 'scripts/repository/facade_cargo_environment.py'):
            self.assertIn(helper, paths)

    def test_aes_dataflow_review_scope(self):
        check = next(c for c in self.registry['checks'] if c['component'] == 'aes' and c['id'] == 'dataflow-review')
        self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-dataflow.py'])
        self.assertEqual(check['platform'], 'linux-x86_64')
        self.assertTrue({'aes-build', 'aes-dataflow', 'compiler', 'hkdf-msrv', 'hash-core'} <= set(check['inputs']))
        self.assertEqual(check['success']['unique_lines'], [aes_dataflow_tests.flow.MARKER] +
                         [f'AES dataflow: PASS; Rust {compiler}; panic={panic}; 11 helpers; {count} inverse machine instructions'
                          for compiler, count in (('1.90.0', 740), ('1.99.1', 749)) for panic in ('abort', 'unwind')] +
                         [f'AES machine review: PASS; Rust {compiler}; panic={panic}; 11 reviewed instruction streams'
                          for compiler in ('1.90.0', '1.99.1') for panic in ('abort', 'unwind')])
        self.assertEqual(set(self.registry['groups']['aes-dataflow']['paths']), {
            'scripts/aes/check-aes-dataflow.py', 'scripts/aes/test-aes-dataflow.py',
            'scripts/aes/aes_machine_review.py', 'scripts/aes/machine-review.json',
            'docs/assurance/aes128-development.md', 'docs/assurance/aes-wide-development.md',
            'scripts/hmac/hmac_engine_codegen.py', 'scripts/hmac/hmac_verifiers.py',
            'scripts/repository/facade_cargo_environment.py'})
        self.assertIn('PYTHONOPTIMIZE', check['reject_environment'])

    def test_aes_operation_cleanup_scope(self):
        checks = [c for c in self.registry['checks'] if c['component'] == 'aes' and c['id'] == 'operation-cleanup']
        self.assertEqual(len(checks), 1)
        check = checks[0]
        self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-operation-cleanup.py'])
        self.assertEqual(check['platform'], 'linux-x86_64')
        self.assertTrue({'aes-operation-codegen', 'aes-build', 'compiler', 'hkdf-msrv', 'hash-core'} <= set(check['inputs']))
        self.assertEqual(check['success']['unique_lines'], [aes_runner_tests.operation.MARKER] +
                         [f'AES operation cleanup: PASS; Rust {compiler}; x86_64; panic={panic}; 7 scratch bodies; 3 explicit clears; 75 rejected IR mutations'
                          for compiler in ('1.90.0', '1.99.1') for panic in ('abort', 'unwind')])
        paths = self.registry['groups']['aes-operation-codegen']['paths']
        for helper in ('scripts/aes/check-aes-operation-cleanup.py', 'scripts/aes/test-aes-runners.py',
                       'scripts/hmac/hmac_engine_codegen.py', 'scripts/hmac/hmac_engine_scratch.py',
                       'scripts/hmac/hmac_verifiers.py', 'scripts/repository/facade_cargo_environment.py'):
            self.assertIn(helper, paths)

    def test_aes_wide_operation_cleanup_scope(self):
        checks = [c for c in self.registry['checks'] if c['component'] == 'aes' and c['id'] == 'wide-operation-cleanup']
        self.assertEqual(len(checks), 1)
        check = checks[0]
        self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-wide-operation-cleanup.py'])
        self.assertEqual(check['platform'], 'linux-x86_64')
        self.assertEqual(check['category'], 'compiler')
        self.assertTrue({'aes-wide-operation-codegen', 'aes-build', 'compiler', 'hkdf-msrv', 'hash-core'} <= set(check['inputs']))
        self.assertEqual(check['success']['unique_lines'], [wide_operation_tests.wide.MARKER] +
                         [f'AES wide operation cleanup: PASS; Rust {compiler}; x86_64; panic={panic}; 14 scratch bodies; 4 explicit clears; 130 rejected IR mutations'
                          for compiler in ('1.90.0', '1.99.1') for panic in ('abort', 'unwind')])
        self.assertEqual(set(self.registry['groups']['aes-wide-operation-codegen']['paths']), {
            'scripts/aes/check-aes-wide-operation-cleanup.py', 'scripts/aes/test-aes-wide-operation-cleanup.py',
            'scripts/aes/check-aes-operation-cleanup.py', 'scripts/hmac/hmac_engine_codegen.py',
            'scripts/hmac/hmac_engine_scratch.py', 'scripts/hmac/hmac_verifiers.py',
            'scripts/repository/facade_cargo_environment.py'})

    def test_aes_development_owner_scope(self):
        selected = [c for c in self.registry['checks'] if c['component'] == 'aes' and c['id'] == 'owner-contract']
        self.assertEqual(len(selected), 1)
        check = selected[0]
        self.assertEqual(check['command'], ['python3', 'scripts/cryptography/test-aes-owner-contract.py'])
        self.assertEqual(check['success'], {'contains': ['Ran 24 tests in '], 'unique_lines': ['OK']})
        paths = self.registry['groups']['aes-owner-contract']['paths']
        for path in ('security/cryptographic-api-profile-policy.toml', 'verification/checks.toml',
                     'scripts/cryptography/aes_owner_contract.py', 'scripts/cryptography/rust_source_contract.py',
                     'scripts/cryptography/test-aes-owner-contract.py'):
            self.assertIn(path, paths)

    def test_hkdf_downstream_dynamic_checks_and_negative_controls(self):
        registry = copy.deepcopy(self.registry)
        for include in registry['includes']:
            registry['groups'].update(json.loads((ROOT / include).read_text())['groups'])
        hkdf_public_dynamic.validate(registry)
        hkdf_public_dynamic.negative_controls(registry)
        dynamic = [c for c in self.registry['checks']
                   if c['component'] in ('hkdf', 'legacy_hkdf') and c.get('category') in ('asan', 'miri')]
        self.assertEqual(len(dynamic), 13)

    def test_hkdf_optimized_checks_reuse_exact_existing_suites(self):
        selected = [c for c in self.registry['checks']
                    if c['component'] in ('hkdf', 'legacy_hkdf') and c.get('category') == 'optimized']
        self.assertEqual(len(selected), 4)
        self.assertEqual(self.registry['groups']['hkdf-optimized']['toml'],
                         {'Cargo.toml': ['profile.release']})
        for check in selected:
            original = next(c for c in self.registry['checks']
                            if c['component'] == check['component']
                            and c['id'] == check['id'].removeprefix('optimized-'))
            self.assertEqual([arg for arg in check['command'] if arg != '--release'], original['command'])
            self.assertEqual(check['command'].count('--release'), 1)
            self.assertEqual(set(check['inputs']), set(original['inputs']) | {'hkdf-optimized'})
            self.assertEqual(check['success'], original['success'])
            self.assertIn('CARGO_PROFILE_RELEASE_OPT_LEVEL', check['reject_environment'])
            self.assertIn('CARGO_PROFILE_RELEASE_LTO', check['reject_environment'])
            self.assertNotIn('--workspace', check['command'])
            self.assertNotIn('--all-features', check['command'])

    def test_hkdf_owner_compiler_checks_are_separate_and_scoped(self):
        for component, family, package in (
                ('hkdf', 'modern', 'brynja-crypto'),
                ('legacy_hkdf', 'legacy', 'brynja-legacy-hkdf')):
            check, = [c for c in self.registry['checks']
                      if c['component'] == component and c['id'] == 'owner-dispatch']
            self.assertEqual(check['command'],
                             ['python3', 'scripts/hkdf/check-hkdf-owner-cleanup.py', family])
            self.assertEqual(check['category'], 'compiler')
            self.assertTrue({'compiler', 'hkdf-msrv', 'hkdf-owner-codegen'} <= set(check['inputs']))
            paths = {p for group in check['inputs'] for p in self.registry['groups'][group].get('paths', [])}
            for dependency in CLOSURES[package] | {package}:
                self.assertIn(f'crates/{dependency}/src', paths)
            self.assertIn('assurance/hkdf-owner-cleanup/Cargo.lock', paths)
            self.assertEqual(len(check['success']['contains']), 5)
            for compiler in ('1.90.0', '1.99.1'):
                for panic in ('abort', 'unwind'):
                    self.assertTrue(any(f'Rust {compiler}; x86_64; panic={panic};' in signal
                                        for signal in check['success']['contains']))

    def test_hkdf_operation_compiler_checks_are_separate_and_scoped(self):
        for component, family, package, consumers, mutations in (
                ('hkdf', 'modern', 'brynja-crypto', 24, 180),
                ('legacy_hkdf', 'legacy', 'brynja-legacy-hkdf', 3, 25)):
            check, = [c for c in self.registry['checks']
                      if c['component'] == component and c['id'] == 'operation-scratch']
            self.assertEqual(check['command'],
                             ['python3', 'scripts/hkdf/check-hkdf-operation-cleanup.py', family])
            self.assertEqual(check['category'], 'compiler')
            self.assertTrue({'compiler', 'hkdf-msrv', 'hkdf-operation-codegen'} <= set(check['inputs']))
            paths = {p for group in check['inputs'] for p in self.registry['groups'][group].get('paths', [])}
            for dependency in CLOSURES[package] | {package}:
                self.assertIn(f'crates/{dependency}/src', paths)
            self.assertIn('scripts/hmac/hmac_engine_scratch.py', paths)
            if family == 'modern':
                self.assertIn('assurance/hkdf-operation-cleanup/Cargo.lock', paths)
                self.assertIn('assurance/hkdf-operation-cleanup/src', paths)
            else:
                self.assertIn('hkdf-optimized', check['inputs'])
            signals = check['success']['contains']
            self.assertEqual(len(signals), 5)
            for compiler in ('1.90.0', '1.99.1'):
                for panic in ('abort', 'unwind'):
                    self.assertIn(f'HKDF {family} operation scratch: PASS; Rust {compiler}; x86_64; '
                                  f'panic={panic}; {consumers} consumers; {mutations} rejected mutations', signals)

    def test_hkdf_timing_screens_are_diagnostics_with_exact_populations(self):
        for component, family, package, count in (
                ('hkdf', 'modern', 'brynja-crypto', 36),
                ('legacy_hkdf', 'legacy', 'brynja-legacy-hkdf', 5)):
            check, = [c for c in self.registry['checks']
                      if c['component'] == component and c['id'] == 'timing-screen']
            self.assertEqual(check['command'], ['python3', 'scripts/hkdf/check-hkdf-timing.py', family])
            self.assertEqual(check['category'], 'timing')
            self.assertEqual(check['platform'], 'linux-x86_64')
            paths = {p for group in check['inputs'] for p in self.registry['groups'][group].get('paths', [])}
            for dependency in CLOSURES[package] | {package}:
                self.assertIn(f'crates/{dependency}/src', paths)
            self.assertIn('assurance/hkdf-timing/Cargo.lock', paths)
            self.assertIn('scripts/hmac/hmac_timing.py', paths)
            self.assertIn('Independent HKDF timing preflight: PASS', check['success']['unique_lines'])
            self.assertIn(f'HKDF {family} timing screen: {count} campaigns; 512 pairs; 4 repetitions; zero alarms',
                          check['success']['unique_lines'])
            self.assertIn('not constant-time', check['establishes'])
            self.assertIn('No automatic retry', check['establishes'])

    def test_hkdf_dynamic_bindings_and_negative_controls(self):
        hkdf_dynamic.validate(self.registry, CLOSURES)
        hkdf_dynamic.negative_controls(self.registry, CLOSURES)

    def test_hkdf_private_encoder_keeps_wire_and_public_boundary_coverage(self):
        checks = {c['id']: c for c in self.registry['checks'] if c['component'] == 'hkdf'}
        prefix = ['cargo', '+1.99.1', 'test', '--locked', '--offline', '-p',
                  'brynja-crypto', '--no-default-features']
        for name, selector, count in (
                ('parameters', ['--lib', 'hkdf::parameters::tests::'], 6),
                ('label-aliasing', ['--doc', 'hkdf::parameters::Tls13Label'], 2)):
            check = checks[name]
            self.assertEqual(check['command'], prefix + selector)
            self.assertEqual(check['success']['minimum_tests'], count)
            self.assertEqual(check['success']['exact_tests'], count)
            self.assertIn(f'test result: ok. {count} passed; 0 failed; 0 ignored;',
                          check['success']['contains'])
            self.assertIn('hkdf-composition', check['inputs'])
        self.assertEqual(self.registry['groups']['hkdf-parameters']['paths'],
                         ['crates/brynja-crypto/src/hkdf/parameter_tests.rs'])

    def test_removed_hkdf_integration_harness_does_not_return(self):
        # Inspect the filesystem, not git's index: ignored/untracked leftovers
        # are also auto-discovered by Cargo and can break tests and Clippy.
        obsolete = ROOT / 'crates/brynja-crypto/tests/hkdf_parameters.rs'
        self.assertFalse(obsolete.exists() or obsolete.is_symlink(),
                         'Remove the obsolete external encoder harness; its six tests live in src/hkdf/parameter_tests.rs')

    def test_label_doctests_do_not_claim_diagnostic_specific_evidence(self):
        check = next(c for c in self.registry['checks']
                     if (c['component'], c['id']) == ('hkdf', 'label-aliasing'))
        self.assertIn('assert only', check['establishes'])
        self.assertIn('Stable rustdoc does not verify', check['establishes'])
        self.assertIn('unrelated compile errors', check['establishes'])

    def test_missing_transitive_source_and_harness_are_rejected(self):
        for group in ('hash-core', 'md5-api', 'hkdf-parameters'):
            changed = copy.deepcopy(self.registry)
            changed['groups'][group]['paths'] = []
            with self.assertRaises(AssertionError):
                validate(changed)

    def test_zero_population_or_wrong_marker_is_rejected(self):
        for field, value in (('minimum_tests', 0), ('contains', ['test not_a_test ... ok'])):
            changed = copy.deepcopy(self.registry)
            check = next(c for c in changed['checks'] if c.get('category', 'portable') == 'portable')
            check['success'][field] = value
            with self.assertRaises(AssertionError):
                validate(changed)

    def test_facade_fixture_versions_follow_actual_local_package(self):
        version = tomllib.loads((ROOT / 'crates/brynja/Cargo.toml').read_text())['package']['version']
        for path in (ROOT / 'assurance').glob('*/Cargo.toml'):
            doc = tomllib.loads(path.read_text())
            dependency = doc.get('dependencies', {}).get('brynja', {})
            if isinstance(dependency, dict) and dependency.get('path'):
                assert dependency.get('version', '=' + version) == '=' + version, str(path)


if __name__ == '__main__':
    unittest.main()
