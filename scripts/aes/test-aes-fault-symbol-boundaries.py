#!/usr/bin/env python3
"""Fail-closed tests for pinned named-body boundary discovery."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "symbol_boundaries", Path(__file__).with_name("check-aes-fault-symbol-boundaries.py"))
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


def fake_table():
    lines = []
    index = 0
    for symbols in S.FAMILIES.values():
        for name in symbols:
            index += 1
            rendered = f"<{name.rsplit('::', 1)[0]}>::{name.rsplit('::', 1)[1]}"
            lines.append(f"{0x1000 + index * 0x100:016x} 0000000000000040 t {rendered}")
    return "\n".join(lines)


class SymbolBoundariesTests(unittest.TestCase):
    def test_all_named_bodies_required(self):
        table = fake_table()
        result = S.symbol_table(table)
        self.assertEqual(len(result), sum(map(len, S.FAMILIES.values())))
        with self.assertRaises(ValueError):
            S.symbol_table("\n".join(table.splitlines()[:-1]))

    def test_duplicate_or_non_text_body_rejected(self):
        table = fake_table()
        with self.assertRaises(ValueError):
            S.symbol_table(table + "\n" + table.splitlines()[0])
        with self.assertRaises(ValueError):
            S.symbol_table(table.replace(" t ", " d ", 1))

    def test_unreviewed_binary_rejected_before_nm(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "unknown.elf"
            path.write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00")
            with patch.object(S.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "unreviewed test ELF"):
                    S.observe(path)
                run.assert_not_called()

    def test_record_rejects_forged_boundary(self):
        import json
        rows = json.loads(S.RECORD.read_text(encoding="utf-8"))["artifacts"]
        S.check_record(rows)
        changed = copy.deepcopy(rows)
        changed[0]["bodies"]["secondary-rounds"][0]["address"] += 1
        with self.assertRaises(ValueError):
            S.check_record(changed)


if __name__ == "__main__":
    unittest.main()
