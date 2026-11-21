"""Negative controls for the GHASH diagnostic (does not repeat timings)."""
import runpy
import unittest
import json
from pathlib import Path

MOD = runpy.run_path(str(Path(__file__).with_name("check-portable-host.py")))


class HostChecks(unittest.TestCase):
    def test_retained_observations(self):
        # Frozen summary digests bind the observed compiler, binary and raw
        # sample hashes. Replay is not a new execution of the measured build.
        frozen = {
            "1.90.0": "9a19c38f1eb1a57f3262b975c9d127a6f067f33c2eae97dee67dc9c700869d81",
            "1.100.0": "c3bf5a424edba5c7cfa35133ef7c94e2bdd39b52680cc0b2b1cf1ae550c42285",
        }
        directory = MOD["ROOT"] / "assurance/ghash-observations/first-x86_64"
        for compiler, expected in frozen.items():
            summary = (directory / f"{compiler}.json").read_bytes()
            self.assertEqual(MOD["digest"](summary), expected)
            record = json.loads(summary)
            raw = (directory / f"{compiler}.txt").read_bytes()
            self.assertEqual(MOD["digest"](raw), record["raw_sha256"])
            results = MOD["summarize"](raw)
            self.assertEqual(results.keys(), record["results"].keys())
            for mode, actual in results.items():
                reference = record["results"][mode]
                self.assertEqual(actual["alarm"], reference["alarm"])
                for metric in ("paired_t", "mean_difference_ns"):
                    self.assertAlmostEqual(actual[metric], reference[metric], places=10)

    def test_timing_controls(self):
        parse = MOD["summarize"]
        raw = b"".join(f"{mode} 10 10\n".encode() * MOD["N"] for mode in MOD["MODES"])
        self.assertFalse(any(row["alarm"] for row in parse(raw).values()))
        changed = parse(raw.replace(b"subkey 10 10", b"subkey 10 12"))
        self.assertTrue(changed["subkey"]["alarm"])
        self.assertIsNone(changed["subkey"]["paired_t"])
        noisy = raw.replace(b"block 10 10\nblock 10 10", b"block 20 10\nblock 21 10")
        self.assertGreater(parse(noisy)["block"]["paired_t"], 4.5)
        for bad in (raw[1:], raw + b"block 1 1\n", raw.replace(b"10", b"0", 1),
                    raw.replace(b"identical", b"subkey", 1)):
            with self.assertRaises(ValueError):
                parse(bad)

    def test_assembly_identity(self):
        pins = MOD["CROSS_REVIEWED"]
        self.assertEqual(set(pins), {(compiler, target) for compiler in ("1.90.0", "1.100.0")
                                     for target in ("thumbv7em-none-eabi", "riscv32imac-unknown-none-elf",
                                                    "aarch64-linux-android")})
        self.assertNotEqual(pins["1.90.0", "thumbv7em-none-eabi"], pins["1.100.0", "thumbv7em-none-eabi"])
        body = MOD["update_body"]
        sample = "fakeGhash6update1:\n decl %ebp\n jne .LBB3_10\n .size fakeGhash6update1, 10"
        baseline = body(sample)
        for old, new in (("jne", "je"), ("%ebp", "%eax"), ("_10", "_11")):
            self.assertNotEqual(baseline, body(sample.replace(old, new)))
        for bad in ("", sample + "\n" + sample, sample.replace(".size", ".bogus")):
            with self.assertRaises(ValueError):
                body(bad)


if __name__ == "__main__":
    unittest.main()
