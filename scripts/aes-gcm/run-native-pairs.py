"""Run inside the prepared bundle on the requested OS; no timing collection."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
TARGETS = {"linux-arm64": ("Linux", "aarch64", "aarch64-unknown-linux-gnu", "+aes,+neon"),
           "macos-arm64": ("Darwin", "arm64", "aarch64-apple-darwin", "+aes,+neon"),
           "windows-x64": ("Windows", "amd64", "x86_64-pc-windows-msvc", "+aes,+sse2"),
           "linux-x64": ("Linux", "x86_64", "x86_64-unknown-linux-gnu", "+aes,+sse2")}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(host, out):
    system, machine, target, features = TARGETS[host]
    if (platform.system(), platform.machine().lower()) != (system, machine):
        raise ValueError("not the requested native OS/architecture")
    manifest = ROOT / "inputs.json"
    for name, expected in json.loads(manifest.read_text()).items():
        if sha(ROOT / name) != expected:
            raise ValueError("changed bundle input: " + name)
    cases = json.loads((ROOT / "cases.json").read_text())
    out.mkdir(exist_ok=False)
    with tempfile.TemporaryDirectory() as tmp:
        # Keep the platform linker/SDK environment, never a Cargo target runner,
        # custom compiler, Cargo config directory, or profile override.
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith(
            ("CARGO_", "RUSTC", "RUSTDOC", "RUSTFLAGS", "RUSTUP_TOOLCHAIN", "DYLD_", "LD_"))}
        env.update(CARGO_HOME=str(Path(tmp)/"cargo"), CARGO_TARGET_DIR=str(Path(tmp)/"target"),
                   CARGO_NET_OFFLINE="true", RUSTUP_AUTO_INSTALL="0")
        suffix = ".exe" if system == "Windows" else ""
        def cmd(args, cwd=ROOT, flags=None, stdin=None):
            e = env.copy()
            if flags is not None:
                e["RUSTFLAGS"] = "-Ctarget-feature=" + flags
            return subprocess.run(args, cwd=cwd, env=e, text=True, stdin=stdin,
                                  stdout=subprocess.PIPE, timeout=600, check=True).stdout
        for v in ("1.90.0", "1.100.0"):
            compiler = cmd(["rustc", "+"+v, "-vV"])
            if "host: " + target not in compiler.splitlines():
                raise ValueError("wrong compiler host")
            probe = Path(tmp)/("probe"+suffix)
            cmd(["rustc", "+"+v, "--edition=2024", "probe.rs", "-o", str(probe)])
            if cmd([str(probe)]).splitlines() != ["AES_STATIC_HOST_BUNDLE_PASS"]:
                raise ValueError("missing baseline host ISA")
            cargo = ["cargo", "+"+v]
            flags = ["--locked", "--offline", "--release", "--target", target, "--no-default-features"]
            test = cargo + ["test", *flags, "-p", "brynja-crypto", "--features",
                            "aes-gcm-execution,gmac-execution,ghash-runtime-execution"]
            result = dict(host=host, os=platform.release(), compiler=compiler, specialized=features,
                          inputs_sha256=sha(manifest), tests={}, images={}, replay={})
            for label, isa, args, count in (
                ("absence", "-aes", ["--test","aead_pair"], 1),
                ("required", features, ["--test","aead_pair"], 3),
                ("field", features, ["--test","ghash_runtime"], 1),
                ("lifecycle", features, ["--lib","aes_gcm::portable::paired::tests::"], 3),
                ("interruptions", features, ["--lib","aes_gcm::interruptions::tests::"], 9)):
                text = cmd(test + args, flags=isa)
                if f"test result: ok. {count} passed; 0 failed; 0 ignored;" not in text:
                    raise ValueError("missing native test population: " + label + "\n" + text[-400:])
                result["tests"][label] = count
            for family, datasets in cases.items():
                example = "gcmvs" if family == "aes-gcm" else "nist"
                for route, dep in (("direct","brynja-crypto"), ("facade","brynja")):
                    cwd = ROOT / dep / family
                    cmd(cargo+["build", *flags, "--example", example, "--features", route+",native"], cwd, features)
                    exe = Path(env["CARGO_TARGET_DIR"])/target/"release/examples"/(example+suffix)
                    image = sha(exe)
                    for name, expected in datasets.items():
                        with (ROOT / name).open("rb") as rows:
                            if cmd([str(exe)], cwd, stdin=rows).splitlines() != [expected]:
                                raise ValueError(f"incomplete {route}/{name}")
                        result["replay"][route+"/"+name] = expected
                    if sha(exe) != image:
                        raise ValueError("replay image changed")
                    result["images"][route+"/"+family] = image
            (out / (v+".json")).write_text(json.dumps(result, sort_keys=True, indent=2)+"\n")
            print(f"{host} {v}: 17 lifecycle/route tests, four downstream executables, eight corpus replays passed", flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("host", choices=TARGETS)
    p.add_argument("output", type=Path)
    args = p.parse_args()
    run(args.host, args.output)
