#!/usr/bin/env python3
"""Coverage-drift tests for the open fault-stage ledger."""
import copy
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "stage_expansion", Path(__file__).with_name("check-aes-fault-stage-expansion.py"))
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


class StageExpansionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = S.SITES.load(S.SITES.file_at(S.ROOT, S.SITES.INVENTORY))
        cls.ledger = S.SITES.load(S.SITES.file_at(S.ROOT, S.LEDGER))

    def test_all_source_and_bypass_families_remain_open(self):
        families, stages, bypasses, bypass_stages = S.validate(self.ledger, self.inventory)
        self.assertEqual((families, bypasses, bypass_stages), (22, 9, 39))
        self.assertEqual(stages, 112)

    def test_missing_or_duplicate_family_rejected(self):
        for change in (lambda rows: rows.pop(),
                       lambda rows: rows.append(copy.deepcopy(rows[0]))):
            ledger = copy.deepcopy(self.ledger)
            change(ledger["families"])
            with self.assertRaises(ValueError):
                S.validate(ledger, self.inventory)

    def test_empty_or_duplicate_stage_rejected(self):
        for stages in ([], ["same", "same"]):
            ledger = copy.deepcopy(self.ledger)
            ledger["families"][0]["stages"] = stages
            with self.assertRaises(ValueError):
                S.validate(ledger, self.inventory)

    def test_no_unreviewed_qualification_fields(self):
        for field, value in (("qualification", "passed"),
                             ("exact_emitted_sites", ["invented"]),
                             ("dc1_temporal_pairings", ["invented"])):
            ledger = copy.deepcopy(self.ledger)
            ledger[field] = value
            with self.assertRaises(ValueError):
                S.validate(ledger, self.inventory)

    def test_bypass_stage_drift_rejected(self):
        for change in (lambda rows: rows.pop(),
                       lambda rows: rows[0]["stages"].append("invented-stage"),
                       lambda rows: rows[0].update(status="passed")):
            ledger = copy.deepcopy(self.ledger)
            change(ledger["bypass_stage_inventory"])
            with self.assertRaises(ValueError):
                S.validate(ledger, self.inventory)


if __name__ == "__main__":
    unittest.main()
