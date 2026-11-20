#!/usr/bin/env python3
"""Regressions for partial emitted-site bookkeeping, not fault testing."""
from contextlib import redirect_stdout
from copy import deepcopy
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "fault_emitted_sites", Path(__file__).with_name("check-aes-fault-emitted-sites.py"))
E = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(E)


class EmittedSiteCandidates(unittest.TestCase):
    def setUp(self):
        self.data = E.SOURCE.load(E.ROOT / E.MAP)
        self.inventory = E.SOURCE.load(E.ROOT / self.data["source_inventory"])
        self.observation = E.SOURCE.load(E.ROOT / self.data["observation_record"])
        self.capture_observation = E.SOURCE.load(
            E.ROOT / self.data["capture_observation_record"])
        self.retained_observation = E.SOURCE.load(
            E.ROOT / self.data["retained_observation_record"])
        self.result_observation = E.SOURCE.load(
            E.ROOT / self.data["result_observation_record"])
        self.completion_observation = E.SOURCE.load(
            E.ROOT / self.data["completion_observation_record"])
        self.outer_completion_observation = E.SOURCE.load(
            E.ROOT / self.data["outer_completion_observation_record"])
        self.permit_observation = E.SOURCE.load(
            E.ROOT / self.data["permit_observation_record"])
        self.readbacks_observation = E.SOURCE.load(
            E.ROOT / self.data["readbacks_observation_record"])
        self.secret_destination_observation = E.SOURCE.load(
            E.ROOT / self.data["secret_destination_observation_record"])
        self.secret_result_observation = E.SOURCE.load(
            E.ROOT / self.data["secret_result_observation_record"])
        self.secret_caller_observation = E.SOURCE.load(
            E.ROOT / self.data["secret_caller_observation_record"])

    def validate(self, data, inventory, observation, capture, retained):
        return E.validate(data, inventory, observation, capture, retained,
                          self.result_observation, self.completion_observation,
                          self.outer_completion_observation, self.permit_observation,
                          self.readbacks_observation,
                          self.secret_destination_observation,
                          self.secret_result_observation,
                          self.secret_caller_observation)

    def reject(self, data):
        with self.assertRaises(ValueError):
            self.validate(data, self.inventory, self.observation,
                          self.capture_observation, self.retained_observation)

    def test_pinned_partial_map_is_consistent(self):
        self.assertEqual(E.check(), (2, 1158, 12, 9))
        self.assertEqual(self.data["fault_results"], [])
        self.assertEqual(self.data["dc1_pairings"], [])
        self.assertEqual(self.inventory["artifact_mappings"], [])

    def test_no_qualification_or_fault_result_promotion(self):
        for name, replacement in (
            ("status", "qualified"), ("qualification", "qualified"),
            ("fault_results", ["passed"]), ("dc1_pairings", ["passed"]),
            ("family", "key-capture"), ("class", "C1"),
            ("schema", True),
        ):
            with self.subTest(field=name):
                data = deepcopy(self.data)
                data[name] = replacement
                self.reject(data)

    def test_artifacts_must_match_pinned_observations(self):
        for name, replacement in (
            ("binary_sha256", "0" * 64), ("toolchain", "other"),
            ("arch", "aarch64"), ("caller_symbol", "other"),
            ("call_offsets", [0, 1]), ("copy_leaf_symbol", "other"),
            ("word_load_offset", 0), ("word_store_offset", 0),
            ("width_bytes", [16, 24]), ("paths", ["public"]),
            ("word_offsets_by_width", {"16": [0], "24": [0, 8, 16],
                                       "32": [0, 8, 16, 24]}),
            ("status", "fault-passed"),
        ):
            with self.subTest(field=name):
                data = deepcopy(self.data)
                data["artifacts"][0][name] = replacement
                self.reject(data)
        data = deepcopy(self.data)
        data["artifacts"][1] = deepcopy(data["artifacts"][0])
        self.reject(data)
        data = deepcopy(self.data)
        data["artifacts"].pop()
        self.reject(data)

    def test_source_and_observation_cannot_silently_shrink(self):
        inventory = deepcopy(self.inventory)
        inventory["sites"] = [site for site in inventory["sites"]
                              if site["id"] != "local-key-copy"]
        with self.assertRaises(ValueError):
            self.validate(self.data, inventory, self.observation,
                       self.capture_observation, self.retained_observation)
        observation = deepcopy(self.observation)
        observation["observations"][0]["baseline_cases"].pop()
        with self.assertRaises(ValueError):
            self.validate(self.data, self.inventory, observation,
                       self.capture_observation, self.retained_observation)
        observation = deepcopy(self.observation)
        observation["observations"][0]["copy_leaf"]["events"]["word_load"] += 1
        with self.assertRaises(ValueError):
            self.validate(self.data, self.inventory, observation,
                       self.capture_observation, self.retained_observation)

    def test_capture_families_are_distinct_and_pinned(self):
        for field, replacement in (
            ("family", "local-key-copy"), ("scope", "input"),
            ("phase", "use"), ("owner", ["cached"]),
            ("class", "C1"), ("expected_outcome", "bypass-obligation"),
        ):
            data = deepcopy(self.data)
            data["capture_families"][0][field] = replacement
            self.reject(data)
        data = deepcopy(self.data)
        data["capture_artifacts"][0]["binary_sha256"] = "0" * 64
        self.reject(data)
        data = deepcopy(self.data)
        data["capture_artifacts"][0]["status"] = "fault-passed"
        self.reject(data)
        capture = deepcopy(self.capture_observation)
        capture["artifacts"][0]["capture"]["events"]["first_call"] += 1
        with self.assertRaises(ValueError):
            self.validate(self.data, self.inventory, self.observation,
                       capture, self.retained_observation)
        capture = deepcopy(self.capture_observation)
        capture["case_matrix"]["count_per_artifact"] -= 1
        with self.assertRaises(ValueError):
            self.validate(self.data, self.inventory, self.observation,
                       capture, self.retained_observation)

    def test_retained_call_map_cannot_be_promoted_or_shrunk(self):
        for name, replacement in (
            ("family", "block-capture"), ("class", "C1"),
            ("phase", "use"), ("owner", ["cached"]),
            ("expected_outcome", "bypass-obligation"),
        ):
            data = deepcopy(self.data)
            data["retained_family"][name] = replacement
            self.reject(data)
        data = deepcopy(self.data)
        data["retained_artifacts"][0]["status"] = "fault-passed"
        self.reject(data)
        retained = deepcopy(self.retained_observation)
        retained["artifacts"][0]["call_offsets"] = [88]
        with self.assertRaises(ValueError):
            self.validate(self.data, self.inventory, self.observation,
                       self.capture_observation, retained)
        retained = deepcopy(self.retained_observation)
        retained["artifacts"][0]["baseline_cases"].pop()
        with self.assertRaises(ValueError):
            self.validate(self.data, self.inventory, self.observation,
                          self.capture_observation, retained)

    def test_result_boundaries_remain_open_and_pinned(self):
        for name, replacement in (("class", "C1"), ("phase", "release"),
                                  ("expected_outcome", "passed")):
            data = deepcopy(self.data)
            data["result_families"][0][name] = replacement
            self.reject(data)
        data = deepcopy(self.data)
        data["result_artifacts"][0]["status"] = "fault-passed"
        self.reject(data)
        for field, value in (("primary_return_offset", 0),
                             ("secondary_return_offset", 0),
                             ("baseline_cases", [])):
            result = deepcopy(self.result_observation)
            result["artifacts"][0][field] = value
            with self.assertRaises(ValueError):
                E.validate(self.data, self.inventory, self.observation,
                           self.capture_observation, self.retained_observation, result,
                           self.completion_observation,
                           self.outer_completion_observation, self.permit_observation,
                           self.readbacks_observation,
                           self.secret_destination_observation,
                           self.secret_result_observation,
                           self.secret_caller_observation)

    def test_inner_completion_is_not_promoted_to_full_lifecycle(self):
        for name, replacement in (("classes", ["L1"]),
                                  ("expected_outcome", "passed"),
                                  ("phase", "release")):
            data = deepcopy(self.data)
            data["completion_family"][name] = replacement
            self.reject(data)
        data = deepcopy(self.data)
        data["completion_artifacts"][0]["status"] = "fault-passed"
        self.reject(data)
        for field, replacement in (("store_offset", 0),
                                   ("return_offset", 0),
                                   ("baseline_cases", [])):
            completion = deepcopy(self.completion_observation)
            completion["artifacts"][0][field] = replacement
            with self.assertRaises(ValueError):
                E.validate(self.data, self.inventory, self.observation,
                           self.capture_observation, self.retained_observation,
                           self.result_observation, completion,
                           self.outer_completion_observation, self.permit_observation,
                           self.readbacks_observation,
                           self.secret_destination_observation,
                           self.secret_result_observation,
                           self.secret_caller_observation)

    def test_outer_completion_handoff_stays_baseline_only(self):
        data = deepcopy(self.data)
        data["outer_completion_artifacts"][0]["status"] = "fault-passed"
        self.reject(data)
        for field, replacement in (("outer_inner_call_offset", 0),
                                   ("outer_store_offset", 0),
                                   ("baseline_cases", [])):
            outer = deepcopy(self.outer_completion_observation)
            outer["artifacts"][0][field] = replacement
            with self.assertRaises(ValueError):
                E.validate(self.data, self.inventory, self.observation,
                           self.capture_observation, self.retained_observation,
                           self.result_observation, self.completion_observation, outer,
                           self.permit_observation, self.readbacks_observation,
                           self.secret_destination_observation,
                           self.secret_result_observation,
                           self.secret_caller_observation)

    def test_permit_map_is_not_a_bypass_pass(self):
        for name, replacement in (("classes", ["L1"]),
                                  ("phase", "use"),
                                  ("expected_outcome", "passed")):
            data = deepcopy(self.data)
            data["permit_family"][name] = replacement
            self.reject(data)
        data = deepcopy(self.data)
        data["permit_artifacts"][0]["status"] = "fault-passed"
        self.reject(data)
        for field, replacement in (("deny_store_offset", 0),
                                   ("guarded_call_offset", 0),
                                   ("baseline_cases", [])):
            permit = deepcopy(self.permit_observation)
            permit["artifacts"][0][field] = replacement
            with self.assertRaises(ValueError):
                E.validate(self.data, self.inventory, self.observation,
                           self.capture_observation, self.retained_observation,
                           self.result_observation, self.completion_observation,
                           self.outer_completion_observation, permit,
                           self.readbacks_observation,
                           self.secret_destination_observation,
                           self.secret_result_observation,
                           self.secret_caller_observation)

    def test_readbacks_map_does_not_claim_actual_secret_destination(self):
        for name, replacement in (("classes", ["L1"]),
                                  ("phase", "use"),
                                  ("expected_outcome", "passed")):
            data = deepcopy(self.data)
            data["readbacks_family"][name] = replacement
            self.reject(data)
        data = deepcopy(self.data)
        data["readbacks_artifacts"][0]["status"] = "fault-passed"
        self.reject(data)
        for field, replacement in (("call_offsets", []),
                                   ("selector_offsets", []),
                                   ("baseline_cases", [])):
            readbacks = deepcopy(self.readbacks_observation)
            readbacks["artifacts"][0][field] = replacement
            with self.assertRaises(ValueError):
                E.validate(self.data, self.inventory, self.observation,
                           self.capture_observation, self.retained_observation,
                           self.result_observation, self.completion_observation,
                           self.outer_completion_observation, self.permit_observation,
                           readbacks, self.secret_destination_observation,
                           self.secret_result_observation,
                           self.secret_caller_observation)

    def test_actual_secret_destination_stays_baseline_only(self):
        for name, replacement in (("classes", ["L1"]),
                                  ("phase", "use"),
                                  ("expected_outcome", "passed")):
            data = deepcopy(self.data)
            data["secret_destination_family"][name] = replacement
            self.reject(data)
        data = deepcopy(self.data)
        data["secret_destination_artifacts"][0]["status"] = "fault-passed"
        self.reject(data)
        for field, replacement in (("validate_check_offsets", []),
                                   ("owners", {}), ("baseline_cases", [])):
            secret = deepcopy(self.secret_destination_observation)
            secret["artifacts"][0][field] = replacement
            with self.assertRaises(ValueError):
                E.validate(self.data, self.inventory, self.observation,
                           self.capture_observation, self.retained_observation,
                           self.result_observation, self.completion_observation,
                           self.outer_completion_observation,
                           self.permit_observation, self.readbacks_observation,
                           secret, self.secret_result_observation,
                           self.secret_caller_observation)

    def test_secret_result_construction_stays_baseline_only(self):
        data = deepcopy(self.data)
        data["secret_result_artifacts"][0]["status"] = "fault-passed"
        self.reject(data)
        for field, replacement in (("complete_address", 0),
                                   ("complete_symbol", "other::complete"),
                                   ("owners", {}), ("baseline_cases", []),
                                   ("qualification", "qualified")):
            result = deepcopy(self.secret_result_observation)
            result["artifacts"][0][field] = replacement
            with self.assertRaises(ValueError):
                E.validate(self.data, self.inventory, self.observation,
                           self.capture_observation, self.retained_observation,
                           self.result_observation, self.completion_observation,
                           self.outer_completion_observation,
                           self.permit_observation, self.readbacks_observation,
                           self.secret_destination_observation, result,
                           self.secret_caller_observation)

    def test_secret_fixture_caller_return_stays_baseline_only(self):
        data = deepcopy(self.data)
        data["secret_caller_artifacts"][0]["status"] = "fault-passed"
        self.reject(data)
        for field, replacement in (("callers", {}),
                                   ("baseline_cases", []),
                                   ("qualification", "qualified")):
            caller = deepcopy(self.secret_caller_observation)
            caller["artifacts"][0][field] = replacement
            with self.assertRaises(ValueError):
                E.validate(self.data, self.inventory, self.observation,
                           self.capture_observation, self.retained_observation,
                           self.result_observation, self.completion_observation,
                           self.outer_completion_observation,
                           self.permit_observation, self.readbacks_observation,
                           self.secret_destination_observation,
                           self.secret_result_observation, caller)

    def test_generated_context_labels_are_stable_and_unique(self):
        labels = [label for artifact in self.data["artifacts"]
                  for label in E.labels(artifact)]
        self.assertEqual(len(labels), 252)
        self.assertEqual(len(labels), len(set(labels)))
        self.assertTrue(labels[0].endswith("/aes128/public/primary/call"))
        self.assertTrue(labels[-1].endswith("/aes256/decrypt/complemented/word24/store"))
        capture_labels = [label for artifact in self.data["capture_artifacts"]
                          for family in self.data["capture_families"]
                          for label in E.capture_labels(artifact, family)]
        self.assertEqual(len(capture_labels), 288)
        self.assertEqual(len(capture_labels), len(set(capture_labels)))
        self.assertTrue(capture_labels[0].endswith("/aes128/cached/public/primary/capture-call"))
        self.assertTrue(capture_labels[-1].endswith(
            "/aes256/operation-local/decrypt/complemented/copy-return"))
        retained_labels = [label for artifact in self.data["retained_artifacts"]
                           for label in E.retained_labels(artifact)]
        self.assertEqual(len(retained_labels), 72)
        self.assertEqual(len(retained_labels), len(set(retained_labels)))
        self.assertTrue(retained_labels[0].endswith(
            "/aes128/cached/public/pre-validation-call"))
        self.assertTrue(retained_labels[-1].endswith(
            "/aes256/operation-local/decrypt/post-validation-call"))
        result_labels = [label for artifact in self.data["result_artifacts"]
                         for family in self.data["result_families"]
                         for label in E.result_labels(artifact, family)]
        self.assertEqual(len(result_labels), 72)
        self.assertEqual(len(result_labels), len(set(result_labels)))
        self.assertTrue(result_labels[0].endswith(
            "/aes128/cached/public/transform-return"))
        self.assertTrue(result_labels[-1].endswith(
            "/aes256/operation-local/decrypt/transform-return"))
        completion_labels = [label for artifact in self.data["completion_artifacts"]
                             for label in E.completion_labels(artifact)]
        self.assertEqual(len(completion_labels), 36)
        self.assertEqual(len(completion_labels), len(set(completion_labels)))
        self.assertTrue(completion_labels[0].endswith(
            "/aes128/cached/public/inner-store"))
        self.assertTrue(completion_labels[-1].endswith(
            "/aes256/operation-local/decrypt/inner-store"))
        outer_labels = [label for artifact in self.data["outer_completion_artifacts"]
                        for label in E.outer_completion_labels(artifact)]
        self.assertEqual(len(outer_labels), 18)
        self.assertEqual(len(outer_labels), len(set(outer_labels)))
        self.assertTrue(outer_labels[0].endswith(
            "/aes128/operation-local/public/outer-store"))
        self.assertTrue(outer_labels[-1].endswith(
            "/aes256/operation-local/decrypt/outer-store"))
        permit_labels = [label for artifact in self.data["permit_artifacts"]
                         for label in E.permit_labels(artifact)]
        self.assertEqual(len(permit_labels), 108)
        self.assertEqual(len(permit_labels), len(set(permit_labels)))
        self.assertTrue(permit_labels[0].endswith(
            "/aes128/cached/public/entry"))
        self.assertTrue(permit_labels[-1].endswith(
            "/aes256/operation-local/decrypt/healthy-return"))
        readback_labels = [label for artifact in self.data["readbacks_artifacts"]
                           for label in E.readback_labels(artifact)]
        self.assertEqual(len(readback_labels), 72)
        self.assertEqual(len(readback_labels), len(set(readback_labels)))
        self.assertTrue(readback_labels[0].endswith(
            "/aes128/cached/public/guarded-forward"))
        self.assertTrue(readback_labels[-1].endswith(
            "/aes256/operation-local/decrypt/guarded-reverse"))
        secret_labels = [label for artifact in self.data["secret_destination_artifacts"]
                         for label in E.secret_destination_labels(artifact)]
        actual_labels = [label for artifact in self.data["secret_destination_artifacts"]
                         for label in E.actual_secret_readback_labels(artifact)]
        self.assertEqual(len(secret_labels), 72)
        self.assertEqual(len(actual_labels), 48)
        self.assertEqual(len(set(secret_labels + actual_labels)), 120)
        result_labels = [label for artifact in self.data["secret_result_artifacts"]
                         for label in E.secret_result_labels(artifact)]
        self.assertEqual(len(result_labels), 72)
        self.assertEqual(len(set(secret_labels + actual_labels + result_labels)), 192)
        self.assertTrue(result_labels[0].endswith(
            "/aes128/cached/encrypt/lifecycle-complete-call"))
        self.assertTrue(result_labels[-1].endswith(
            "/aes256/operation-local/decrypt/result-length-store"))
        caller_labels = [label for artifact in self.data["secret_caller_artifacts"]
                         for label in E.secret_caller_labels(artifact)]
        self.assertEqual(len(caller_labels), 48)
        self.assertEqual(len(set(secret_labels + actual_labels + result_labels +
                                 caller_labels)), 240)
        self.assertTrue(caller_labels[0].endswith("/aes128/cached/encrypt/fixture-call"))
        self.assertTrue(caller_labels[-1].endswith(
            "/aes256/operation-local/decrypt/fixture-return"))

    def test_unknown_fields_do_not_bypass_validation(self):
        for location in (self.data, self.data["artifacts"][0]):
            location["passed"] = True
            self.reject(self.data)
            del location["passed"]

    def test_pinned_record_hash_and_paths_fail_closed(self):
        data = deepcopy(self.data)
        data["observation_sha256"] = "0" * 64
        with patch.object(E.SOURCE, "load", side_effect=[data, self.inventory]):
            with self.assertRaises(ValueError):
                E.check()
        data = deepcopy(self.data)
        data["capture_observation_sha256"] = "0" * 64
        with patch.object(E.SOURCE, "load", side_effect=[data, self.inventory,
                                                         self.observation]):
            with self.assertRaises(ValueError):
                E.check()
        data = deepcopy(self.data)
        data["retained_observation_sha256"] = "0" * 64
        with patch.object(E.SOURCE, "load", side_effect=[data, self.inventory,
                                                         self.observation,
                                                         self.capture_observation]):
            with self.assertRaises(ValueError):
                E.check()
        data = deepcopy(self.data)
        data["result_observation_sha256"] = "0" * 64
        with patch.object(E.SOURCE, "load", side_effect=[data, self.inventory,
                                                         self.observation,
                                                         self.capture_observation,
                                                         self.retained_observation]):
            with self.assertRaises(ValueError):
                E.check()
        data = deepcopy(self.data)
        data["completion_observation_sha256"] = "0" * 64
        with patch.object(E.SOURCE, "load", side_effect=[data, self.inventory,
                                                         self.observation,
                                                         self.capture_observation,
                                                         self.retained_observation,
                                                         self.result_observation]):
            with self.assertRaises(ValueError):
                E.check()
        data = deepcopy(self.data)
        data["outer_completion_observation_sha256"] = "0" * 64
        with patch.object(E.SOURCE, "load", side_effect=[data, self.inventory,
                                                         self.observation,
                                                         self.capture_observation,
                                                         self.retained_observation,
                                                         self.result_observation,
                                                         self.completion_observation]):
            with self.assertRaises(ValueError):
                E.check()
        data = deepcopy(self.data)
        data["permit_observation_sha256"] = "0" * 64
        with patch.object(E.SOURCE, "load", side_effect=[data, self.inventory,
                                                         self.observation,
                                                         self.capture_observation,
                                                         self.retained_observation,
                                                         self.result_observation,
                                                         self.completion_observation,
                                                         self.outer_completion_observation]):
            with self.assertRaises(ValueError):
                E.check()
        data = deepcopy(self.data)
        data["readbacks_observation_sha256"] = "0" * 64
        with patch.object(E.SOURCE, "load", side_effect=[data, self.inventory,
                                                         self.observation,
                                                         self.capture_observation,
                                                         self.retained_observation,
                                                         self.result_observation,
                                                         self.completion_observation,
                                                         self.outer_completion_observation,
                                                         self.permit_observation]):
            with self.assertRaises(ValueError):
                E.check()
        data = deepcopy(self.data)
        data["secret_destination_observation_sha256"] = "0" * 64
        with patch.object(E.SOURCE, "load", side_effect=[data, self.inventory,
                                                         self.observation,
                                                         self.capture_observation,
                                                         self.retained_observation,
                                                         self.result_observation,
                                                         self.completion_observation,
                                                         self.outer_completion_observation,
                                                         self.permit_observation,
                                                         self.readbacks_observation]):
            with self.assertRaises(ValueError):
                E.check()
        data = deepcopy(self.data)
        data["secret_result_observation_sha256"] = "0" * 64
        with patch.object(E.SOURCE, "load", side_effect=[data, self.inventory,
                                                         self.observation,
                                                         self.capture_observation,
                                                         self.retained_observation,
                                                         self.result_observation,
                                                         self.completion_observation,
                                                         self.outer_completion_observation,
                                                         self.permit_observation,
                                                         self.readbacks_observation,
                                                         self.secret_destination_observation]):
            with self.assertRaises(ValueError):
                E.check()
        data = deepcopy(self.data)
        data["secret_caller_observation_sha256"] = "0" * 64
        with patch.object(E.SOURCE, "load", side_effect=[data, self.inventory,
                                                         self.observation,
                                                         self.capture_observation,
                                                         self.retained_observation,
                                                         self.result_observation,
                                                         self.completion_observation,
                                                         self.outer_completion_observation,
                                                         self.permit_observation,
                                                         self.readbacks_observation,
                                                         self.secret_destination_observation,
                                                         self.secret_result_observation]):
            with self.assertRaises(ValueError):
                E.check()
        data = deepcopy(self.data)
        data["source_inventory"] = "../outside.json"
        with patch.object(E.SOURCE, "load", return_value=data):
            with self.assertRaises(ValueError):
                E.check()

    def test_cli_is_explicitly_non_qualifying(self):
        output = io.StringIO()
        with patch.object(E.sys, "argv", ["check-aes-fault-emitted-sites.py"]), \
                redirect_stdout(output):
            self.assertEqual(E.main(), 0)
        self.assertIn("No fault results", output.getvalue())
        self.assertIn("qualified builds", output.getvalue())


if __name__ == "__main__":
    unittest.main()
