"""Private HMAC fault fixture; never adds test backdoors to published APIs."""
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
TESTS = 6


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError("HMAC fault/mutation anchor changed: " + before)
    return source.replace(before, after)


def result(command, directory, environment):
    # Import from the already admitted release-tool directory, never a family
    # supplied Cargo configuration or a consumer's source tree.
    import facade_cargo_environment
    facade_cargo_environment.check(directory, environment)
    return subprocess.run(command, cwd=directory, env=environment, text=True,
                          capture_output=True, timeout=300)


def accepted(run, count):
    if run.returncode or f"test result: ok. {count} passed; 0 failed; 0 ignored;" not in run.stdout:
        raise ValueError("HMAC fault baseline failed:\n" + run.stdout[-5000:] + run.stderr[-5000:])


def rejected(run):
    # A compilation error, crash or timeout is not a killed behavioral mutant.
    if run.returncode != 101 or "test result: FAILED. 0 passed; 1 failed; 0 ignored;" not in run.stdout:
        raise ValueError("HMAC mutant survived or failed without executing its test:\n"
                         + run.stdout[-5000:] + run.stderr[-5000:])


def check(roots, directory, environment):
    fixture = directory / "fault-consumer"
    shutil.copytree(roots["brynja-mac-hmac"] / "src", fixture / "src")
    manifest = '[workspace]\n[package]\nname="hmac-faults"\nversion="0.0.0"\nedition="2024"\n[dependencies]\n'
    for name in ("brynja-core", "brynja-hash-sha2", "brynja-hash-sha3"):
        features = ', features=["general-sha512-t"]' if name == "brynja-hash-sha2" else ''
        manifest += f'{name}={{path={json.dumps(str(roots[name]))}, default-features=false{features}}}\n'
    manifest += '[patch.crates-io]\n'
    manifest += ''.join(f'{name}={{path={json.dumps(str(path))}}}\n' for name, path in roots.items())
    (fixture / "Cargo.toml").write_text(manifest)
    source = fixture / "src/lib.rs"
    source.write_text(source.read_text() + '\n#[cfg(test)] mod fault_tests;\n')
    shutil.copyfile(ROOT / "assurance/hmac-faults/fault_tests.rs", fixture / "src/fault_tests.rs")
    # Add another std-enabled private test module to the copied leaf. Never
    # expose a callback/fault API or ship these probes in the runtime archive.
    shutil.copyfile(ROOT / "assurance/hmac-faults/adapter_tests.rs", fixture / "src/adapter_tests.rs")
    source.write_text(source.read_text() + '\n#[cfg(test)] mod adapter_tests;\n')
    scratch = fixture / "src/scratch.rs"
    anchor = 'let _ = clear_owned_region(&mut self.0);'
    scratch.write_text(replace_once(scratch.read_text(), anchor,
                                   anchor + '\ncrate::fault_tests::observe_scratch(&self.0);'))
    lock = result(["cargo", "generate-lockfile", "--offline"], fixture, environment)
    if lock.returncode:
        raise ValueError(lock.stderr)
    for profile in ([], ["--release"]):
        command = ["cargo", "test", "--offline", "--locked", *profile, "--lib"]
        accepted(result(command, fixture, environment), TESTS)
    mutants = (
        ("scratch.rs", anchor, 'let _ = &self.0;', "scratch_clears_populated_regions"),
        ("lib.rs", 'pub fn cancel(self) {}', 'pub fn cancel(self) { core::mem::forget(self); }',
         "every_hash_boundary_releases_owners"),
        ("engine.rs", 'let mut initialization = SecretRegionInitialization::begin(destination)?;\n        if !crate::policy::exact_output(self.tag_bytes, length) {\n            return Err(Error::TagLength);\n        }',
         'if !crate::policy::exact_output(self.tag_bytes, length) { return Err(Error::TagLength); }\n        let mut initialization = SecretRegionInitialization::begin(destination)?;',
         "invalid_destinations_reject_before_hash_finalization"),
        ("policy.rs", 'selected >= 16 && selected <= full',
         'selected >= 1 && selected <= full', "invalid_tag_policy_constructs_no_hash_owners"),
    )
    for filename, before, after, test in mutants:
        path = fixture / "src" / filename
        original = path.read_text()
        command = ["cargo", "test", "--offline", "--locked", "--release", "--lib",
                   "fault_tests::" + test, "--", "--exact"]
        accepted(result(command, fixture, environment), 1)
        try:
            path.write_text(replace_once(original, before, after))
            rejected(result(command, fixture, environment))
        finally:
            path.write_text(original)
        accepted(result(command, fixture, environment), 1)
    # These mutate the real adapter, not the synthetic model. Forgetting its
    # output after the callback returns must leave observable nonzero storage.
    for filename, binding, expose in (("algorithms.rs", "secret", "expose"),
                                      ("general.rs", "digest", "as_bytes")):
        path = fixture / "src" / filename
        original = path.read_text()
        before = f"consume({binding}.{expose}())"
        if original.count(before) != 2:
            raise ValueError("HMAC real adapter callback population changed")
        mutations = [
            (occurrence, f"let result = {before};\ncore::mem::forget({binding});\nresult")
            for occurrence in (0, 1)]
        mutations += [
            (0, f"let _ = {before};\nOk(())"),
            # Return/error cleanup is intact; only consumer unwinding leaks.
            (0, f"let {binding} = core::mem::ManuallyDrop::new({binding});\n"
                f"let result = {before};\n"
                f"drop(core::mem::ManuallyDrop::into_inner({binding}));\nresult"),
        ]
        for occurrence, after in mutations:
            command = ["cargo", "test", "--offline", "--locked", "--release", "--lib",
                       "adapter_tests::real_adapter_consumers_release_digest_on_every_exit",
                       "--", "--exact"]
            accepted(result(command, fixture, environment), 1)
            offset = original.index(before)
            if occurrence:
                offset = original.index(before, offset + len(before))
            mutant = original[:offset] + after + original[offset + len(before):]
            try:
                path.write_text(mutant)
                rejected(result(command, fixture, environment))
            finally:
                path.write_text(original)
            accepted(result(command, fixture, environment), 1)
    print(f"HMAC adapter faults: {TESTS} debug/release tests; 328 synthetic faults; "
          "144 real handoffs; 12 compiled mutants rejected")
