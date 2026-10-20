"""Private synthetic admission/operation failures through the real CPU HMAC.

Only the test copy gains a synthetic Source and sealed Backend. Runtime source,
published APIs, real authority constructors and admission policy are unchanged.
"""
import shutil

from hmac_faults import ROOT, accepted, rejected, replace_once, result

TESTS = 6
PREFIX = "execution::model::cases::"
MUTANTS = (
    ("mod.rs", "let second = A::create(owner)?;",
     "let second = A::create(owner).unwrap();", "preadmission_and_every_boundary_release_owners"),
    ("mod.rs", "Some(A::create(owner)?)", "None", "preadmission_and_every_boundary_release_owners"),
    ("mod.rs", "key.len() > A::BLOCK_BYTES", "key.len() >= A::BLOCK_BYTES",
     "preadmission_and_every_boundary_release_owners"),
    ("mod.rs", "pub fn cancel(self) {}", "pub fn cancel(self) { core::mem::forget(self); }",
     "preadmission_and_every_boundary_release_owners"),
    ("mod.rs", "let _ = brynja_core::clear_owned_region(output);", "let _ = output;",
     "terminal_state_rejects_every_operation"),
    ("retained.rs", "guard.preserve = matches!(result, Ok(()) | Err(Error::MessageTooLong));",
     "guard.preserve = true;", "terminal_state_rejects_every_operation"),
    ("retained.rs", "preserve: false,", "preserve: true,", "terminal_state_rejects_every_operation"),
    ("retained.rs", "Ok(()) | Err(Error::MessageTooLong)", "Ok(())",
     "length_rejection_preserves_both_owners"),
    ("mod.rs", "if !crate::policy::valid_tag_length(A::TAG_BYTES, tag_bytes) {", "if false {",
     "invalid_policy_admits_nothing"),
    ("mod.rs", "A::validate()?;", "", "invalid_policy_admits_nothing"),
)


def prepare(prepared, fixture):
    shutil.copytree(prepared, fixture)
    execution = fixture / "src/execution"
    path = execution / "mod.rs"
    path.write_text(path.read_text() + "\n#[cfg(test)] mod model;\n")
    for name, destination in (("execution_model.rs", "model.rs"),
                              ("execution_cases.rs", "execution_cases.rs")):
        shutil.copyfile(ROOT / "assurance/hmac-faults" / name, execution / destination)
    path = execution / "backends.rs"
    source = replace_once(path.read_text(), "Static(&'a Authority),",
                          "Static(&'a Authority),\n    #[cfg(test)] Synthetic(&'a super::Kernel),")
    source = replace_once(source, "Self::Static(owner) => owner.report().kernel,",
                          "Self::Static(owner) => owner.report().kernel,\n"
                          "            #[cfg(test)] Self::Synthetic(kernel) => *kernel,")
    for anchor in ("Self::Static(owner) => sha2::Execution",
                   "Self::Static(owner) => sha3::KeccakSession"):
        source = replace_once(source, anchor,
                              "#[cfg(test)] Self::Synthetic(_) => return Err(Error::ExecutionFailed),\n"
                              "            " + anchor)
    path.write_text(source)


def check(prepared, directory, environment):
    fixture = directory / "execution-composition-faults"
    prepare(prepared, fixture)
    base = ["cargo", "test", "--offline", "--locked", "--features", "runtime-execution", "--lib"]
    for profile in ([], ["--release"]):
        accepted(result([*base, *profile, PREFIX], fixture, environment), TESTS)
    for filename, before, after, test in MUTANTS:
        path = fixture / "src/execution" / filename
        original = path.read_text()
        # Both byte and typed-bit secret finalizers must clear a terminal error.
        occurrences = original.count(before)
        if before.startswith("let _ = brynja_core"):
            if occurrences != 2:
                raise ValueError("HMAC terminal-output mutant anchor changed")
            variants = [original[:offset] + after + original[offset + len(before):]
                        for offset in (original.index(before), original.rindex(before))]
        else:
            variants = [replace_once(original, before, after)]
        command = [*base, "--release", PREFIX + test, "--", "--exact"]
        for mutant in variants:
            accepted(result(command, fixture, environment), 1)
            try:
                path.write_text(mutant)
                rejected(result(command, fixture, environment))
            finally:
                path.write_text(original)
            accepted(result(command, fixture, environment), 1)
    print("HMAC execution composition: 6 debug/release tests; "
          "2784 synthetic faults; 11 compiled mutants rejected; not native/erasure evidence")
