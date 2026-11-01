#!/usr/bin/env python3
"""Reject missing evidence and obvious timing signals in the HKDF screen."""
import unittest

import hkdf_timing as timing


def vectors(family):
    return "\n".join([
        f"VECTOR {identity} {mode} {cls} " + timing.answer(
            identity, width, mode, bytes([0xff if cls else 0]) * 200).hex()
        for identity, width, mode in timing.population(family) for cls in (0, 1)
    ] + ["HKDF_TIMING_END preflight"])


def samples(family):
    return "\n".join([
        f"SAMPLE {identity} {mode} {sample} 1000 1000"
        for identity, _, mode in timing.population(family) for sample in range(timing.SAMPLES)
    ] + ["HKDF_TIMING_END measure"])


class TimingTests(unittest.TestCase):
    def test_exact_populations(self):
        for family, count in (("modern", 36), ("legacy", 5)):
            timing.preflight(vectors(family), family)
            rows = timing.parse(samples(family), family)
            self.assertEqual(len(rows), count)
            self.assertFalse(any(row["signal"] for row in rows))

    def test_rfc5869_oracle(self):
        # RFC 5869 A.1 independently pins the recurrence used by the preflight.
        import hmac
        prk = hmac.digest(bytes(range(13)), b"\x0b" * 22, "sha256")
        self.assertEqual(prk.hex(), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        self.assertEqual(timing.expand("sha256", prk, bytes(range(0xf0, 0xfa)), 42).hex(),
                         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

    def test_preflight_rejects_corruption_and_missing_classes(self):
        text = vectors("modern")
        first = text.splitlines()[0]
        for mutant in (text.replace("VECTOR sha224", "VECTOR sha256", 1),
                       text.split("\n", 1)[1], text + "\nextra",
                       text.replace(first, first[:-2] + "zz", 1),
                       text.replace(" 0 ", " 1 ", 1), text.replace("preflight", "measure")):
            with self.assertRaises(ValueError):
                timing.preflight(mutant, "modern")

    def test_missing_duplicate_and_reordered_samples(self):
        text = samples("legacy")
        lines = text.splitlines()
        for mutant in ("\n".join(lines[1:]), text + "\n" + lines[-1],
                       "\n".join([lines[1], lines[0], *lines[2:]]),
                       text.replace("SAMPLE sha1", "SAMPLE sha256", 1)):
            with self.assertRaises(ValueError):
                timing.parse(mutant, "legacy")

    def test_invalid_measurements(self):
        text = samples("legacy")
        for value in ("0", "-1", "nan", "inf", "1.5", "True", "1" * 40):
            with self.assertRaises(ValueError):
                timing.parse(text.replace("1000", value, 1), "legacy")

    def test_constant_difference_is_an_alarm(self):
        rows = timing.parse(samples("legacy").replace("1000 1000", "1100 1000"), "legacy")
        self.assertTrue(all(row["signal"] and row["paired_t_abs"] is None for row in rows))

    def test_variable_large_difference_is_an_alarm(self):
        pairs = [(1200 + i % 3, 1000) for i in range(timing.SAMPLES)]
        self.assertTrue(timing.screen(pairs)["signal"])

    def test_unknown_family_is_rejected(self):
        with self.assertRaises(ValueError):
            timing.population("all")


if __name__ == "__main__":
    unittest.main()
