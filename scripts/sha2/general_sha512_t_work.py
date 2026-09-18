"""Rust fallback-model block/round counters; not native assembly/timing evidence."""
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "assurance/general-sha512-t"
SITES = (
    ("compress64.rs", "    let mut schedule = [0_u64; 80];", 0),
    ("hardened/compress64.rs", "    for index in 0_usize..16 {", 1),
    ("compress64.rs", "    for (constant, word) in ROUND_CONSTANTS.iter().zip(schedule.iter()) {", 2),
    ("hardened/compress64.rs", "    for index in 0_usize..80 {", 3),
)


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError("ambiguous final work instrumentation")
    return text.replace(before, after)


def instrumented_model(text, expected):
    # Only the copied crate selects the Rust fallback. Production native assembly
    # has separate round-bound/cleanup checks; do not invent native round ticks.
    condition = "not(any(miri, kani))"
    if text.count(condition) != expected:
        raise ValueError("ambiguous hardened model selection")
    return text.replace(condition, 'not(any(miri, kani, feature = "work-model"))')


def run(*, mutations=False):
    with tempfile.TemporaryDirectory(prefix="brynja-general-work-") as directory:
        root = Path(directory)
        shutil.copytree(ROOT / "crates/brynja-hash-sha2/src", root / "src")
        deps = "\n".join(f'{name} = {{ path = "{(ROOT / "crates" / name).as_posix()}" }}'
                         for name in ("brynja-core", "brynja-hash-core"))
        (root / "Cargo.toml").write_text(
            '[workspace]\n[package]\nname="brynja-hash-sha2"\nversion="0.1.0"\nedition="2024"\n'
            '[features]\ndefault=[]\ngeneral-sha512-t=[]\ncpu=[]\nwork-model=[]\n[dependencies]\n' + deps + '\n')
        for name, expected in (("hardened/compress64.rs", 4), ("compress64.rs", 1)):
            path = root / "src" / name
            path.write_text(instrumented_model(path.read_text(), expected))
        lib = root / "src/lib.rs"
        lib.write_text(lib.read_text() + '\n#[cfg(test)]\nmod work_probe;\n')
        shutil.copyfile(FIXTURE / "work_probe.rs", root / "src/work_probe.rs")
        for name, before, counter in SITES:
            path = root / "src" / name
            hook = f"crate::work_probe::tick({counter});"
            after = ("    " + hook + "\n" + before) if counter < 2 else (before + "\n        " + hook)
            path.write_text(replace_once(path.read_text(), before, after))
        for profile in ([], ["--release"]):
            command = ["cargo", "test", "--locked", "--offline", "--manifest-path", str(root / "Cargo.toml"),
                       "--features", "general-sha512-t,work-model", "--lib", *profile, "work_probe::final_work_counts"]
            if not (root / "Cargo.lock").exists():
                subprocess.run(["cargo", "generate-lockfile", "--offline", "--manifest-path", str(root / "Cargo.toml")],
                               check=True, capture_output=True, timeout=60)
            result = subprocess.run(command, capture_output=True, timeout=240)
            if result.returncode or b"test result: ok. 1 passed; 0 failed;" not in result.stdout:
                raise ValueError(f"work positive control failed: {result.stdout!r} {result.stderr!r}")
            if mutations:
                changes = [(name, f"crate::work_probe::tick({counter});", "") for name, _, counter in SITES]
                changes += [
                    ("compress64.rs", "ROUND_CONSTANTS.iter().zip(schedule.iter())", "ROUND_CONSTANTS.iter().zip(schedule.iter()).take(79)"),
                    ("hardened/compress64.rs", "for index in 0_usize..80 {", "for index in 0_usize..79 {"),
                ]
                for name, before, after in changes:
                    path = root / "src" / name
                    source = path.read_text()
                    try:
                        path.write_text(replace_once(source, before, after))
                        bad = subprocess.run(command, capture_output=True, timeout=240)
                        expected = b"ordinary work" if name == "compress64.rs" else b"hardened work"
                        if not bad.returncode or b"test result: FAILED" not in bad.stdout or expected not in bad.stdout:
                            raise ValueError("work hook or shortened rounds not detected by compiled assertion")
                    finally:
                        path.write_text(source)
    print("General SHA-512/t Rust fallback-model work counts: PASS; 12240 cases per profile, ordinary and hardened; debug/release; not native assembly evidence")


if __name__ == "__main__":
    run(mutations=True)
