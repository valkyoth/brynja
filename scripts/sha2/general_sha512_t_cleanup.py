"""Source-bound emitted cleanup checks; not proof of register/spill erasure."""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/cryptography"))
import mir_cleanup_flow as flow


def check_consumer(section):
    # These five consumers retain the complete self in _1 until drop. Do not
    # accept drop of a similarly named temporary or a move into public output.
    blocks = flow.basic_blocks(section)
    graph, exits = flow.control_flow(blocks)
    # A second panic during cleanup terminates the process: no Rust owner can
    # promise cleanup after that. Retain all recoverable unwind/resume edges.
    for node, body in blocks.items():
        if "unwind terminate(" in body and not re.search(r"\b(?:resume;|unwind continue)", body):
            graph[node].discard(f"unwind:{node}")
    pending, seen = [("bb0", False)], set()
    while pending:
        node, cleared = pending.pop()
        if (node, cleared) in seen:
            continue
        seen.add((node, cleared))
        body = blocks.get(node, "")
        cleared |= bool(re.search(r"\bdrop\(_1\)\s*->", body))
        if node in exits and not cleared:
            raise ValueError("consumer exit lacks self drop")
        pending.extend((target, cleared) for target in graph[node])
    if not any(node.startswith("normal:") for node, _ in seen):
        raise ValueError("consumer has no reachable normal return")


def validate(mir, llvm, assembly):
    for method in ("finalize_public", "finalize_bits_public", "finalize_secret", "finalize_bits_secret"):
        section = flow.exact_function(mir, ("src/general/hardened.rs", f">::{method}(", "_1: HardenedSha512T"))
        check_consumer(section)
    section = flow.exact_function(mir, ("src/general/secret.rs", ">::declassify(", "_1: Sha512TSecretDigest"))
    check_consumer(section)
    wipe = flow.exact_function(mir, ("src/hardened/owner.rs", ">::wipe("))
    if wipe.count("clear_owned_region(") != 8:
        raise ValueError("eight owned regions are not cleared")
    for artifact in (llvm, assembly):
        if "HardenedSha2Owner" not in artifact or "wipe" not in artifact or "OwnedSecretRegion" not in artifact:
            raise ValueError("owner cleanup identities missing from codegen")


def main():
    for compiler in ("1.90.0", "1.98.1"):
        for profile in ("dev", "release"):
            with tempfile.TemporaryDirectory(prefix="brynja-general-cleanup-") as directory:
                env = dict(os.environ, CARGO_TARGET_DIR=directory, RUSTFLAGS="-Cpanic=unwind")
                command = ["cargo", f"+{compiler}", "rustc", "--locked", "-p", "brynja-hash-sha2",
                           "--features", "general-sha512-t", "--profile", profile, "--", "--emit=mir,llvm-ir,asm"]
                subprocess.run(command, cwd=ROOT, env=env, check=True, timeout=180, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                artifacts = []
                for extension in ("mir", "ll", "s"):
                    paths = list(Path(directory).rglob(f"brynja_hash_sha2-*.{extension}"))
                    if len(paths) != 1:
                        raise ValueError("ambiguous compiler artifact")
                    artifacts.append(paths[0].read_text())
                validate(*artifacts)
                print(f"general SHA-512/t: {compiler} {profile} unwind MIR/LLVM/assembly cleanup PASS")


if __name__ == "__main__":
    main()
