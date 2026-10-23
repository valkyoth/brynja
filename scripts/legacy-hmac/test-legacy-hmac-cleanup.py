#!/usr/bin/env python3
"""Real compiler artifacts plus source-compiled cleanup regressions."""
import importlib.util
from pathlib import Path
import re
import shutil
import unittest

spec = importlib.util.spec_from_file_location(
    "legacy_cleanup_driver", Path(__file__).with_name("check-legacy-hmac-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
codegen = driver.codegen


class CleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.artifacts = driver.collect(cls.root / "baseline", "1.99.1",
                                       "x86_64-unknown-linux-gnu", "unwind")

    def rejects(self, llvm):
        with self.assertRaises(ValueError):
            codegen.check(self.artifacts[0], llvm, self.artifacts[2], "unwind")

    def test_population_identity_and_panic_profile(self):
        llvm = self.artifacts[1]
        self.rejects(llvm.replace("10scratch_20", "10scratch_21"))
        self.rejects(llvm + llvm)
        self.rejects(llvm.replace("11brynja_core13secret_memory18clear_owned_region",
                                 "11brynja_core13secret_memory18other_owned_region"))
        for panic in ("abort", "unknown"):
            with self.assertRaises(ValueError):
                codegen.check(*self.artifacts, panic)
        for artifacts in (("", llvm, self.artifacts[2]), (self.artifacts[0], llvm, "")):
            with self.assertRaises(ValueError):
                codegen.check(*artifacts, "unwind")

    def test_each_clear_extent_and_pointer(self):
        lines = self.artifacts[1].splitlines()
        count = 0
        for index, line in enumerate(lines):
            if not line.startswith("declare ") and re.search(codegen.CLEAR, line):
                for changed in (line.replace("%owner,", "%input,"),
                                re.sub(r"i64 noundef (1|20|64)\)", "i64 noundef 0)", line)):
                    self.assertNotEqual(changed, line)
                    self.rejects("\n".join([*lines[:index], changed, *lines[index + 1:]]))
                    count += 1
        self.assertEqual(count, 20)

    def test_early_return_does_not_borrow_another_branch_clear(self):
        llvm = self.artifacts[1]
        for body in codegen.functions(llvm).values():
            changed = body.replace("start:", "start:\n  ret i8 -1\nunused:", 1)
            self.rejects(llvm.replace(body, changed, 1))

    def test_unwind_lifetime_and_post_clear_write(self):
        llvm = self.artifacts[1]
        body = codegen.functions(llvm)["scratch_unwind"]
        changed = body.replace("unwind label %cleanup", "unwind label %escape", 1)
        self.assertNotEqual(body, changed)
        changed += "\nescape:\n  resume { ptr, i32 } zeroinitializer\n"
        self.rejects(llvm.replace(body, changed, 1))
        for instruction in ("store i8 42, ptr %owner", "call void @unknown(ptr %owner)"):
            changed = re.sub(r"(\n\s*ret i8)", "\n  " + instruction + "\n\\1", body)
            self.assertNotEqual(body, changed)
            self.rejects(llvm.replace(body, changed, 1))
        body = codegen.functions(llvm)["scratch_64"]
        changed = body.replace("start:", "start:\n  call void @llvm.lifetime.end.p0(ptr %owner)", 1)
        self.rejects(llvm.replace(body, changed, 1))
        self.rejects(llvm.replace("unwind label %cleanup", "unwind label %absent", 1))

    def test_compiled_actual_drop_mutations(self):
        source = driver.FIXTURE.parent
        original = (driver.ROOT / "crates/brynja-legacy-hmac/src/scratch.rs").read_text()
        anchor = "let _ = brynja_core::clear_owned_region(&mut self.0);"
        self.assertEqual(original.count(anchor), 1)
        for number, replacement in enumerate(("let _ = &mut self.0;",
                                              "let _ = brynja_core::clear_owned_region(&mut self.0[..N / 2]);")):
            work = self.root / f"mutant-{number}"
            (work / "src").mkdir(parents=True)
            (work / "Cargo.toml").write_text((source / "Cargo.toml").read_text().replace(
                "../../crates/", str(driver.ROOT / "crates") + "/"))
            shutil.copyfile(source / "Cargo.lock", work / "Cargo.lock")
            (work / "src/lib.rs").write_text((source / "src/lib.rs").read_text().replace(
                "../../../crates/brynja-legacy-hmac/src/scratch.rs", "scratch.rs"))
            scratch = work / "src/scratch.rs"
            scratch.write_text(original)
            baseline = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", work / "Cargo.toml")
            codegen.check(*baseline, "unwind")
            scratch.write_text(original.replace(anchor, replacement))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", work / "Cargo.toml")
            with self.assertRaises(ValueError):
                codegen.check(*artifacts, "unwind")


if __name__ == "__main__":
    unittest.main()
