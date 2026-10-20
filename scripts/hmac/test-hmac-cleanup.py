#!/usr/bin/env python3
"""Exercise real emitted artifacts and compiled scratch-cleanup regressions."""
import importlib.util
from pathlib import Path
import re
import shutil
import unittest

spec = importlib.util.spec_from_file_location(
    "hmac_cleanup_driver", Path(__file__).with_name("check-hmac-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
codegen = driver.codegen


class CleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.verifier.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.artifacts = driver.collect(cls.root / "baseline", "1.99.1",
                                       "x86_64-unknown-linux-gnu", "unwind")

    def rejects(self, llvm):
        with self.assertRaises(ValueError):
            codegen.check(self.artifacts[0], llvm, self.artifacts[2], "unwind")

    def test_exact_population_and_wrong_identity(self):
        llvm = self.artifacts[1]
        self.rejects(llvm.replace("10scratch_64", "10scratch_65"))
        self.rejects(llvm + llvm)
        self.rejects(llvm.replace("11brynja_core13secret_memory18clear_owned_region",
                                 "11brynja_core13secret_memory18other_owned_region"))

    def test_all_clear_extents_and_pointer_identity(self):
        llvm = self.artifacts[1]
        lines = llvm.splitlines()
        count = 0
        for index, line in enumerate(lines):
            if not line.startswith("declare ") and re.search(codegen.CLEAR, line):
                for mutant in (line.replace("%owner,", "%input,"),
                               re.sub(r"i64 noundef (1|64|144)\)", "i64 noundef 0)", line)):
                    self.assertNotEqual(line, mutant)
                    self.rejects("\n".join([*lines[:index], mutant, *lines[index + 1:]]))
                    count += 1
        self.assertEqual(count, 20)

    def test_clear_in_other_branch_cannot_cover_early_return(self):
        llvm = self.artifacts[1]
        functions = codegen.functions(llvm)
        for body in functions.values():
            changed = body.replace("start:", "start:\n  ret i8 -1\nunused:", 1)
            self.rejects(llvm.replace(body, changed, 1))

    def test_unwind_bypass_and_post_clear_write(self):
        llvm = self.artifacts[1]
        body = codegen.functions(llvm)["scratch_unwind"]
        bypass = body.replace("unwind label %cleanup", "unwind label %escape", 1)
        bypass += "\nescape:\n  resume { ptr, i32 } zeroinitializer\n"
        self.rejects(llvm.replace(body, bypass, 1))
        changed = re.sub(r"(\n\s*ret i8)", "\n  store i8 42, ptr %owner\n\\1", body)
        self.assertNotEqual(body, changed)
        self.rejects(llvm.replace(body, changed, 1))
        changed = re.sub(r"(\n\s*ret i8)", "\n  call void @unknown(ptr %owner)\n\\1", body)
        self.rejects(llvm.replace(body, changed, 1))

    def test_lifetime_missing_edges_and_panic_profile(self):
        llvm = self.artifacts[1]
        body = codegen.functions(llvm)["scratch_64"]
        changed = body.replace("start:", "start:\n  call void @llvm.lifetime.end.p0(ptr %owner)", 1)
        self.rejects(llvm.replace(body, changed, 1))
        self.rejects(llvm.replace("unwind label %cleanup", "unwind label %absent", 1))
        with self.assertRaises(ValueError):
            codegen.check(*self.artifacts, "abort")
        with self.assertRaises(ValueError):
            codegen.check(*self.artifacts, "invented")
        with self.assertRaises(ValueError):
            codegen.check("", llvm, self.artifacts[2], "unwind")
        with self.assertRaises(ValueError):
            codegen.check(self.artifacts[0], llvm, "", "unwind")

    def test_real_compiled_scratch_mutants(self):
        source = driver.ROOT / "assurance/hmac-cleanup"
        runtime = (driver.ROOT / "crates/brynja-mac-hmac/src/scratch.rs").read_text()
        anchor = "let _ = clear_owned_region(&mut self.0);"
        self.assertEqual(runtime.count(anchor), 1)
        for number, replacement in enumerate((
                "let _ = &mut self.0;",
                "let _ = clear_owned_region(&mut self.0[..N / 2]);")):
            with self.subTest(mutant=number):
                work = self.root / f"mutant-{number}"
                (work / "src").mkdir(parents=True)
                manifest = (source / "Cargo.toml").read_text()
                for name in ("brynja-core", "brynja-mac-hmac"):
                    manifest = manifest.replace("../../crates/" + name,
                                                str(driver.ROOT / "crates" / name))
                (work / "Cargo.toml").write_text(manifest)
                shutil.copyfile(source / "Cargo.lock", work / "Cargo.lock")
                probe = (source / "src/lib.rs").read_text().replace(
                    "../../../crates/brynja-mac-hmac/src/scratch.rs", "scratch.rs")
                (work / "src/lib.rs").write_text(probe)
                (work / "src/scratch.rs").write_text(runtime)
                baseline = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu",
                                       "unwind", work / "Cargo.toml")
                codegen.check(*baseline, "unwind")
                (work / "src/scratch.rs").write_text(runtime.replace(anchor, replacement))
                # Compilation must succeed. A compiler failure is not a killed mutant.
                artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu",
                                        "unwind", work / "Cargo.toml")
                with self.assertRaises(ValueError):
                    codegen.check(*artifacts, "unwind")


if __name__ == "__main__":
    unittest.main()
