"""Run inside the prepared bundle on the requested OS; no timing collection."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import tempfile

ROOT = Path(__file__).absolute().parent
TARGETS = {"linux-arm64": ("Linux", "aarch64", "aarch64-unknown-linux-gnu", "+aes,+neon"),
           "macos-arm64": ("Darwin", "arm64", "aarch64-apple-darwin", "+aes,+neon"),
           "windows-x64": ("Windows", "amd64", "x86_64-pc-windows-msvc", "+aes,+sse2"),
           "linux-x64": ("Linux", "x86_64", "x86_64-unknown-linux-gnu", "+aes,+sse2")}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ordinary(path, kind):
    info = path.lstat()
    if not kind(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError("link or unexpected file type: " + str(path))


def no_cargo_config(directory):
    for start in (directory.absolute(), directory.resolve()):
        for base in (start, *start.parents):
            cargo = base / ".cargo"
            if os.path.lexists(cargo):
                ordinary(cargo, stat.S_ISDIR)
                if any(os.path.lexists(cargo / n) for n in ("config", "config.toml")):
                    raise ValueError("ambient Cargo configuration: " + str(cargo))


def unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate manifest name")
        result[name] = value
    return result


def leaf_guard(cmd, cargo, flags):
    case = "ghash::interrupted_pair_update_clears_live_frame"
    # Use baseline compiler flags: the leaf admits PCLMUL/PMULL at runtime.
    output = cmd(cargo + ["test", *flags, "-p", "brynja-universal-hash-ghash",
                          "--features", "__mode-execution", "--lib", "--", "--exact",
                          case, "--nocapture"])
    lines = output.splitlines()
    summaries = [line for line in lines if line.startswith("test result:")]
    if (len(summaries) != 1 or not summaries[0].startswith("test result: ok. 1 passed; 0 failed; 0 ignored;")
            or lines.count(f"test {case} ... ok") != 1
            or lines.count("GHASH_PAIRED_LIVE_CLEANUP_COMPLETE") != 1):
        raise ValueError("missing or ambiguous native leaf guard evidence")


def verified_copy(source, dest, pin):
    """Import only hashed ordinary files into a new private execution tree."""
    ordinary(source, stat.S_ISDIR)
    no_cargo_config(source)
    no_cargo_config(dest)
    manifest = source / "inputs.json"
    ordinary(manifest, stat.S_ISREG)
    raw = manifest.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin:
        raise ValueError("wrong native input manifest digest")
    entries = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(entries, dict) or not entries:
        raise ValueError("invalid manifest")
    files = {"inputs.json"}
    dirs = set()
    spellings = {"inputs.json": "inputs.json"}
    for name, digest in entries.items():
        parts = name.split("/")
        if (name.casefold() == "inputs.json" or not isinstance(digest, str)
                or not re.fullmatch("[0-9a-f]{64}", digest)
                or any(not re.fullmatch(r"[A-Za-z0-9_.+-]+", part)
                       or part.endswith(".") or part.lower() == ".cargo"
                       or re.fullmatch(r"CON|PRN|AUX|NUL|(?:COM|LPT)[0-9]",
                                       part.partition(".")[0], re.I) for part in parts)):
            raise ValueError("unsafe manifest name or digest")
        for i in range(1, len(parts)+1):
            prefix = "/".join(parts[:i])
            if spellings.setdefault(prefix.casefold(), prefix) != prefix:
                raise ValueError("ambiguous manifest path")
            if i < len(parts):
                dirs.add(prefix)
        files.add(name)
    if files & dirs:
        raise ValueError("manifest file used as directory")

    dest.mkdir(mode=0o700)
    seen = set()
    def visit(directory):
        for child in directory.iterdir():
            name = child.relative_to(source).as_posix()
            if name in dirs:
                ordinary(child, stat.S_ISDIR)
                (dest / name).mkdir()
                visit(child)
            elif name in files:
                ordinary(child, stat.S_ISREG)
                data = raw if name == "inputs.json" else child.read_bytes()
                if name != "inputs.json" and hashlib.sha256(data).hexdigest() != entries[name]:
                    raise ValueError("changed native bundle file: " + name)
                with (dest / name).open("xb") as out:
                    out.write(data)
                seen.add(name)
            else:
                raise ValueError("unexpected native bundle entry: " + name)
    visit(source)
    if seen != files:
        raise ValueError("missing native bundle files")


def run(host, out, pin):
    system, machine, target, features = TARGETS[host]
    if (platform.system(), platform.machine().lower()) != (system, machine):
        raise ValueError("not the requested native OS/architecture")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve() / "bundle"
        verified_copy(ROOT, root, pin)
        cases = json.loads((root / "cases.json").read_text())
        out.mkdir(exist_ok=False)
        # Keep the platform linker/SDK environment, never a Cargo target runner,
        # custom compiler, Cargo config directory, or profile override.
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith(
            ("CARGO_", "RUSTC", "RUSTDOC", "RUSTFLAGS", "RUSTUP_TOOLCHAIN", "DYLD_", "LD_"))}
        env.update(CARGO_HOME=str(Path(tmp)/"cargo"), CARGO_TARGET_DIR=str(Path(tmp)/"target"),
                   CARGO_NET_OFFLINE="true", RUSTUP_AUTO_INSTALL="0")
        suffix = ".exe" if system == "Windows" else ""
        def cmd(args, cwd=root, flags=None, stdin=None):
            no_cargo_config(cwd)
            for name in ("config", "config.toml"):
                if os.path.lexists(Path(env["CARGO_HOME"]) / name):
                    raise ValueError("ambient private Cargo home configuration")
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
                          inputs_sha256=pin, tests={}, images={}, replay={})
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
            leaf_guard(cmd, cargo, flags)
            result["tests"]["leaf-guard"] = 1
            for family, datasets in cases.items():
                example = "gcmvs" if family == "aes-gcm" else "nist"
                for route, dep in (("direct","brynja-crypto"), ("facade","brynja")):
                    cwd = root / dep / family
                    cmd(cargo+["build", *flags, "--example", example, "--features", route+",native"], cwd, features)
                    exe = Path(env["CARGO_TARGET_DIR"])/target/"release/examples"/(example+suffix)
                    image = sha(exe)
                    for name, expected in datasets.items():
                        with (root / name).open("rb") as rows:
                            if cmd([str(exe)], cwd, stdin=rows).splitlines() != [expected]:
                                raise ValueError(f"incomplete {route}/{name}")
                        result["replay"][route+"/"+name] = expected
                    if sha(exe) != image:
                        raise ValueError("replay image changed")
                    result["images"][route+"/"+family] = image
            (out / (v+".json")).write_text(json.dumps(result, sort_keys=True, indent=2)+"\n")
            print(f"{host} {v}: {sum(result['tests'].values())} lifecycle/route tests, four downstream executables, eight corpus replays passed", flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("host", choices=TARGETS)
    p.add_argument("output", type=Path)
    p.add_argument("--inputs-sha256", required=True, help="manifest digest from the trusted producer")
    args = p.parse_args()
    run(args.host, args.output, args.inputs_sha256)
