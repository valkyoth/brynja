#!/usr/bin/env python3
"""Package-external execution and compiled regression rejection, never publication."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/sha3"))
spec = importlib.util.spec_from_file_location("execution_packages", ROOT / "scripts/sha3/check-sha3-execution.py")
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
shared.PACKAGES = (*shared.PACKAGES, "brynja-hash-parallel", "brynja-hash-parallel-std")


def check(args, cwd, environment, *, failing=False):
    result = subprocess.run(args, cwd=cwd, env=environment, text=True, capture_output=True, timeout=300)
    if failing:
        if not result.returncode or "test result: FAILED" not in result.stdout or "error[E" in result.stderr:
            raise ValueError("compiled mutation did not fail an executing test:\n" + result.stdout + result.stderr)
    elif result.returncode:
        raise ValueError("package-external execution failed:\n" + result.stdout + result.stderr)
    return result


def main():
    with tempfile.TemporaryDirectory(prefix="brynja-parallel-package-") as directory:
        destination = Path(directory)
        environment = dict(os.environ, CARGO_TARGET_DIR=str(destination / "target"))
        _, roots = shared.package(destination, environment)
        patches = "\n[patch.crates-io]\n" + "\n".join(
            f'{name} = {{ path = "{path.as_posix()}" }}' for name, path in roots.items()) + "\n"
        for name in ("brynja-hash-parallel", "brynja-hash-parallel-std"):
            manifest = roots[name] / "Cargo.toml"
            manifest.write_text(manifest.read_text() + "\n[workspace]\n" + patches)
            for profile in ([], ["--release"]):
                check(["cargo", "test", "--offline", "--features", "runtime-execution", *profile], roots[name], environment)
        boundary = roots["brynja-hash-parallel"] / "src/execution/mod.rs"
        original_boundary = boundary.read_text()
        for body, code in (
            ("fn forge(root: &mut super::Collector<'static, 'static, '_>) { "
             "let _ = super::stream::CompleteInput { root }; }", "E0451"),
            ("fn bypass(root: &mut super::Collector<'static, 'static, '_>) { "
             "let _ = root.finish(0, true); }", "E0624"),
            ("fn bypass(root: &mut super::Collector<'static, 'static, '_>) { "
             "let _ = root.finish_inner(0, true, true); }", "E0624"),
            ("fn reuse(input: super::stream::CompleteInput<'_, '_>) { "
             "let _ = input.into_root(); let _ = input.into_root(); }", "E0382"),
        ):
            try:
                boundary.write_text(original_boundary + "\n#[cfg(test)] mod completion_boundary_probe { " + body + " }\n")
                for profile in ([], ["--release"]):
                    result = subprocess.run(
                        ["cargo", "test", "--offline", "--features", "runtime-execution", *profile, "--lib", "--no-run"],
                        cwd=roots["brynja-hash-parallel"], env=environment,
                        text=True, capture_output=True, timeout=300)
                    if not result.returncode or f"error[{code}]" not in result.stderr:
                        raise ValueError("completion boundary did not reject " + code + ":\n" + result.stderr)
            finally:
                boundary.write_text(original_boundary)
        print("Streaming completion rejects eight compiled forgery/bypass/reuse probes", flush=True)
        cases = [
            ("brynja-hash-parallel", "src/execution/collector.rs",
             f"let _ = clear_owned_region(&mut self.{field});", "",
             ["--lib", "cancel_clears_all_four_root_metadata_regions"])
            for field in ("merged", "accelerated", "output_bits", "phase")
        ]
        cases += [
            ("brynja-hash-parallel", "src/execution/binding.rs",
             "streaming_complete && merged <= *limit", "merged <= *limit",
             ["--lib", "streaming_root_rejects_finalization_without_input_proof"]),
            ("brynja-hash-parallel", "src/execution/stream.rs",
             "self.used()? != 0 || self.root.merged_leaves() != expected",
             "self.root.merged_leaves() != expected",
             ["--lib", "completion_rejects_pending_bytes_even_when_leaf_count_matches"]),
            ("brynja-hash-parallel", "src/execution/stream.rs",
             "self.used()? != 0 || self.root.merged_leaves() != expected", "self.used()? != 0",
             ["--lib", "completion_mismatched_leaf_count_clears_all_output_paths"]),
            ("brynja-hash-parallel", "src/execution/stream.rs", "stream.check_complete()?;", "",
             ["--lib", "completion_mismatched_leaf_count_clears_all_output_paths"]),
            ("brynja-hash-parallel-std", "src/execution/worker.rs",
             "let _ = clear_owned_region(value);", "",
             ["--lib", "storage_clear_visits_every_byte_of_every_live_slot"]),
            ("brynja-hash-parallel", "src/execution/stream.rs",
             "let _ = clear_owned_region(&mut self.used);\n        let _ = clear_owned_region(&mut self.input_bits);",
             "let _ = clear_owned_region(&mut self.input_bits);",
             ["--lib", "cancellation_clears_both_input_metadata_regions_and_workspace"]),
            ("brynja-hash-parallel", "src/execution/stream.rs",
             "let _ = clear_owned_region(&mut self.input_bits);", "",
             ["--lib", "cancellation_clears_both_input_metadata_regions_and_workspace"]),
            ("brynja-hash-parallel", "src/execution/stream.rs", "if required > self.limit {", "if false {",
             ["--test", "execution_stream"]),
            ("brynja-hash-parallel", "src/execution/stream.rs", "if !self.complete {", "if self.complete {",
             ["--lib", "maximum_bit_count_rejects_before_callbacks_and_clears"]),
            ("brynja-hash-parallel", "src/execution/collector.rs", "if !self.complete {", "if self.complete {",
             ["--lib", "failed_operation_guard_clears_preexisting_metadata"]),
            ("brynja-hash-parallel", "src/execution/collector.rs", "|| !core::ptr::eq(plan, leaf.plan)", "|| false",
             ["--test", "execution", "wrong_duplicate_missing_and_reordered_leaves_close_root"]),
            ("brynja-hash-parallel", "src/execution/collector.rs", "output.copy_from_slice(secret.expose());", "let _ = secret;",
             ["--test", "official_vectors"]),
            ("brynja-hash-parallel", "src/execution/backend.rs", 'b"ParallelHash"', 'b"Incorrect"',
             ["--test", "official_vectors"]),
            ("brynja-hash-parallel-std", "src/execution/worker.rs", "failure.map_or(Ok(()), Err)", "Ok(())",
             ["--lib", "spawn_errors_panics_and_cancellation_join_and_close_root"]),
            ("brynja-hash-parallel-std", "src/execution/mod.rs", "!(1..=64).contains(&config.workers)", "!(0..=65).contains(&config.workers)",
             ["--test", "execution", "early_failures_preserve_public_and_clear_secret_and_scratch"]),
        ]
        for index, (package, file, before, after, tests) in enumerate(cases):
            path = roots[package] / file
            original = path.read_text()
            if original.count(before) != 1:
                raise ValueError("mutation no longer has one exact target: " + before)
            try:
                path.write_text(original.replace(before, after))
                for profile in ([], ["--release"]):
                    check(["cargo", "test", "--offline", "--features", "runtime-execution", *profile, *tests],
                          roots[package], environment, failing=True)
            finally:
                path.write_text(original)
            print(f"ParallelHash packaged compiled mutant rejected: {index + 1}/{len(cases)} in debug/release", flush=True)
        print(f"ParallelHash package execution: PASS; compiled regressions={len(cases) * 2}")


if __name__ == "__main__":
    main()
