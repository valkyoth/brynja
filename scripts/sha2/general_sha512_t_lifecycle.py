"""Isolated, instrumented destructor evidence; never shipped in the library.

The probe observes live owned bytes inside Drop, never reads freed memory, and
requires real compiled assertion failures for each missing region clear.
"""
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIELDS = ("chaining_state", "partial_input", "message_length", "phase",
          "message_schedule", "block_copy", "padding_block", "output_staging")


def observer():
    checks = "\n".join(f'assert!(owner.{field}.iter().all(|b| *b == 0), "uncleared {field}");' for field in FIELDS)
    return '''
#[cfg(test)]
pub(crate) mod lifecycle_audit {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static DROPS: AtomicUsize = AtomicUsize::new(0);
    pub(crate) fn count() -> usize { DROPS.load(Ordering::SeqCst) }
    pub(crate) fn record(owner: &super::HardenedSha2Owner) {
        CHECKS
        DROPS.fetch_add(1, Ordering::SeqCst);
    }
}
'''.replace("CHECKS", checks)


def probe():
    poison = "\n".join(f"state.owner.{field}.fill(0xa5);" for field in FIELDS)
    return '''
#[test]
fn lifecycle_destructor_probe() -> Result<(), Sha512TError> {
    extern crate std;
    use crate::hardened::lifecycle_audit::count;
    let p = Sha512TBits::new(9)?;
    let start = count();
    let mut state = HardenedSha512T::new(p);
    POISON
    drop(state);
    assert_eq!(count(), start + 1, "ordinary Drop was bypassed");
    for route in 0..8 {
        let before = count();
        let mut state = HardenedSha512T::new(p);
        state.update(&[0x5a; 129])?;
        let mut output = [0xa5; 3];
        match route {
            0 => state.cancel(),
            1 => { let _ = state.finalize_public(crate::PublicDeclassification::acknowledge())?; }
            2 => { drop(state.finalize_secret(&mut output[..2])?); assert_eq!(output, [0,0,0xa5]); }
            3 => { assert!(state.finalize_secret(&mut output).is_err()); assert_eq!(output, [0;3]); }
            4 | 5 => {
                state.owner.message_length = (u128::MAX / 8).to_be_bytes();
                let tail = crate::BitString::new(&[0], 8).map_err(|_| Sha512TError::MessageTooLong)?;
                if route == 4 { assert!(state.finalize_bits_secret(tail, &mut output[..2]).is_err()); assert_eq!(output, [0,0,0xa5]); }
                else { assert!(state.finalize_bits_public(tail, crate::PublicDeclassification::acknowledge()).is_err()); }
            }
            6 => {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    let _live = state;
                    std::panic::resume_unwind(std::boxed::Box::new(()));
                }));
                assert!(result.is_err());
            }
            _ => {
                let tail = crate::BitString::new(&[0xa0], 3).map_err(|_| Sha512TError::MessageTooLong)?;
                drop(state.finalize_bits_secret(tail, &mut output[..2])?);
                assert_eq!(output, [0,0,0xa5]);
            }
        }
        assert_eq!(count(), before + 1, "state destructor count at route {route}");
    }
    for route in 0..4 {
        let before = count();
        let mut output = [0xa5; 2];
        let tail = crate::BitString::new(&[0xa0], 3).map_err(|_| Sha512TError::MessageTooLong)?;
        let auth = crate::PublicDeclassification::acknowledge();
        match route {
            0 => { let _ = crate::hardened_sha512_t_public(p, b"secret", auth)?; }
            1 => { let _ = crate::hardened_sha512_t_bits_public(p, tail, auth)?; }
            2 => { drop(crate::hardened_sha512_t_secret(p, b"secret", &mut output)?); assert_eq!(output, [0;2]); }
            _ => { drop(crate::hardened_sha512_t_bits_secret(p, tail, &mut output)?); assert_eq!(output, [0;2]); }
        }
        assert_eq!(count(), before + 1, "one-shot owner leaked at route {route}");
    }
    Ok(())
}
'''.replace("POISON", poison)


def run(*, mutations=False):
    with tempfile.TemporaryDirectory(prefix="brynja-general-lifecycle-") as directory:
        root = Path(directory)
        shutil.copytree(ROOT / "crates/brynja-hash-sha2/src", root / "src")
        dependencies = "\n".join(name + ' = { path = "' + str(ROOT / "crates" / name) + '" }'
                                 for name in ("brynja-core", "brynja-hash-core"))
        (root / "Cargo.toml").write_text(
            '[workspace]\n[package]\nname="brynja-hash-sha2"\nversion="0.1.0"\nedition="2024"\n'
            '[features]\ndefault=[]\ngeneral-sha512-t=[]\ncpu=[]\n[dependencies]\n' + dependencies + '\n')
        path = root / "src/hardened/owner.rs"
        original = path.read_text()
        boundary = "        self.wipe();\n    }\n}"
        if original.count(boundary) != 1:
            raise ValueError("ambiguous owner Drop instrumentation boundary")
        instrumented = original.replace(boundary, "        self.wipe();\n        lifecycle_audit::record(self);\n    }\n}") + observer()
        path.write_text(instrumented)
        module = root / "src/hardened/mod.rs"
        module.write_text(module.read_text() + '\n#[cfg(test)]\npub(crate) use owner::lifecycle_audit;\n')
        test = root / "src/general/hardened/tests.rs"
        test.write_text(test.read_text() + probe())
        command = ["cargo", "test", "--offline", "--manifest-path", str(root / "Cargo.toml"),
                   "--features", "general-sha512-t", "--lib", "lifecycle_destructor_probe", "--", "--test-threads=1"]
        for profile in ([], ["--release"]):
            selected = command[:2] + profile + command[2:]
            result = subprocess.run(selected, capture_output=True, timeout=180)
            if result.returncode or b"1 passed" not in result.stdout:
                raise ValueError(f"lifecycle positive control failed: {result.stdout!r} {result.stderr!r}")
            if mutations:
                for field in FIELDS:
                    token = f"        let _ = clear_owned_region(&mut self.{field});"
                    # Scratch-clearing calls also occur outside wipe(). Change
                    # only the terminal wipe function, not the compression path.
                    start = instrumented.index("    pub(crate) fn wipe(&mut self)")
                    prefix, body = instrumented[:start], instrumented[start:]
                    if body.count(token) != 1:
                        raise ValueError("ambiguous clearing mutation")
                    path.write_text(prefix + body.replace(token, ""))
                    result = subprocess.run(selected, capture_output=True, timeout=180)
                    if result.returncode == 0 or b"test result: FAILED" not in result.stdout or f"uncleared {field}".encode() not in result.stdout:
                        raise ValueError(f"missing clear not detected: {field}: {result.stdout!r} {result.stderr!r}")
                    path.write_text(instrumented)
                hard = root / "src/general/hardened.rs"
                source = hard.read_text()
                for before, after in (
                    ("        drop(self);", "        core::mem::forget(self);"),
                    ("        self.finish_public(None, authority)", "        let result = self.finish_public(None, authority); core::mem::forget(self); result"),
                ):
                    if source.count(before) != 1:
                        raise ValueError("ambiguous consuming-owner mutation")
                    hard.write_text(source.replace(before, after))
                    result = subprocess.run(selected, capture_output=True, timeout=180)
                    if result.returncode == 0 or b"test result: FAILED" not in result.stdout or b"state destructor count" not in result.stdout:
                        raise ValueError("consuming-owner bypass was not detected")
                    hard.write_text(source)
        print("General SHA-512/t destructor probe: debug/release PASS" + ("; 20 compiled clearing/ownership mutants rejected" if mutations else ""))


if __name__ == "__main__":
    run(mutations=True)
