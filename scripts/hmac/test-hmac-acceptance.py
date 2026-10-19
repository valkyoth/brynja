#!/usr/bin/env python3
"""The acceptance driver must distinguish executed tests from unrelated errors."""
import json
from types import SimpleNamespace
import unittest

from hmac_acceptance import ALGORITHMS, diagnostic_rejection, negative_cases
from hmac_faults import accepted, rejected, replace_once


def output(code=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)


def error(code):
    return json.dumps({"reason": "compiler-message", "message": {
        "level": "error", "code": {"code": code}}}) + "\n"


class AcceptanceTests(unittest.TestCase):
    def test_complete_negative_population(self):
        cases = list(negative_cases())
        self.assertEqual(len(cases), 67)
        self.assertEqual(len({name for name, _, _ in cases}), 67)
        for algorithm in ALGORITHMS:
            for bound in ("Send", "Sync", "Copy", "Clone", "core::fmt::Debug"):
                self.assertIn(f"{algorithm}/{bound}", [name for name, _, _ in cases])

    def test_diagnostic_only(self):
        diagnostic_rejection(output(101, error("E0277")), "E0277")
        for value in (output(0, error("E0277")), output(101, "E0277"),
                      output(101, "", error("E0277")), output(101, error("E0432")),
                      output(101, error("E0277") + error("E0432")),
                      output(101, error(None)), output(-9, error("E0277"))):
            with self.subTest(value=value), self.assertRaises(ValueError):
                diagnostic_rejection(value, "E0277")

    def test_positive_population(self):
        marker = "test result: ok. 5 passed; 0 failed; 0 ignored;"
        accepted(output(0, marker), 5)
        for value in (output(101, marker), output(0), output(0, marker.replace("5 passed", "4 passed")),
                      output(0, marker.replace("0 ignored", "1 ignored"))):
            with self.subTest(value=value), self.assertRaises(ValueError):
                accepted(value, 5)

    def test_mutant_must_execute(self):
        marker = "test result: FAILED. 0 passed; 1 failed; 0 ignored;"
        rejected(output(101, marker))
        for value in (output(0, marker), output(-6, marker), output(101, error("E0425")),
                      output(101, marker.replace("1 failed", "2 failed")),
                      output(101, marker.replace("0 ignored", "1 ignored"))):
            with self.subTest(value=value), self.assertRaises(ValueError):
                rejected(value)

    def test_exact_mutation_anchor(self):
        self.assertEqual(replace_once("x original y", "original", "mutant"), "x mutant y")
        for text in ("missing", "original original"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                replace_once(text, "original", "mutant")


if __name__ == "__main__":
    unittest.main()
