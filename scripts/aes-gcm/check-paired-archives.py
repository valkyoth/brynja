"""Replay pinned Go and NIST data through required x86 GCM and GMAC archive owners."""
import json
import os
from pathlib import Path
import platform
import runpy
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
portable = runpy.run_path(str(HERE / "check-portable-acceptance.py"))
linked = runpy.run_path(str(HERE / "paired_linked.py"))
ROOT, pkg, archives, gcm = (portable[k] for k in ("ROOT", "pkg", "archives", "gcm"))
TARGET = "x86_64-unknown-linux-gnu"
REJECT = (*pkg.REJECT_ENV, "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER", "QEMU_CPU")


def once(source, old, new):
    if source.count(old) != 1:
        raise ValueError("frozen replay adapter no longer has one expected call site: " + old)
    return source.replace(old, new)


def paired_source(source, family):
    """Change only the owner import, admission and constructor arguments in a temporary copy."""
    if family == "aes-gcm":
        names, module, rest, receiver = "Aes128Gcm, Aes192Gcm, Aes256Gcm", "aes_gcm", "GcmError", "for_open"
    elif family == "gmac":
        names, module, rest, receiver = "Aes128Gmac, Aes192Gmac, Aes256Gmac", "gmac", "GmacError, GmacTag", "for_verify"
    else:
        raise ValueError("unknown replay family")
    source = once(source, module + "::{" + names + ", " + rest + "}",
                  module + "::{" + rest + ", execution::{AesPair, " + names + "}}")
    site = "let mut schedule = [0; $size];"
    source = once(source, site, site + '\nlet pair = AesPair::require().expect("required native pair");')
    for constructor in ("from_reserved_range", "from_reserved_invocations", receiver):
        site = "::" + constructor + "("
        source = once(source, site, site + "&pair, ")
    return source


def prepare(root, family, dep, versions):
    consumer = root / dep / family
    name = "aes-gcm-consumer" if family == "aes-gcm" else "gmac-consumer"
    fixture = ROOT / "assurance" / name
    (consumer / "src").mkdir(parents=True)
    (consumer / "examples").mkdir()
    if family == "aes-gcm":
        exports = "pub use " + ("brynja::crypto;" if dep == "brynja" else "brynja_crypto as crypto;")
        (consumer / "src/lib.rs").write_text(exports)
        (consumer / "examples/gcmvs.rs").write_text(paired_source(
            (fixture / "examples/gcmvs.rs").read_text(), family))
    else:
        (consumer / "src/lib.rs").write_text(paired_source((fixture / "src/lib.rs").read_text(), family))
        shutil.copyfile(fixture / "examples/nist.rs", consumer / "examples/nist.rs")
    patches = "".join(f'{n}={{path={json.dumps(str(root / "unpacked" / (n+"-"+v)))}}}\n'
                      for n, v in versions.items())
    (consumer / "Cargo.toml").write_text(
        f'[workspace]\n[package]\nname="{name}"\nversion="0.0.0"\nedition="2024"\npublish=false\n'
        f'[features]\ndirect=[]\nfacade=[]\nnative=["{dep}/{family}-execution"]\n'
        f'[dependencies]\n{dep}={{version="={versions[dep]}",default-features=false}}\n'
        '[patch.crates-io]\n' + patches)
    return consumer


def controls(path, family):
    # Nonempty records exercise output checks in addition to the authentication
    # decision. Only change a known operation or an expected output.
    gcm_case = family == "aes-gcm"
    swaps = {"open": "reject", "reject": "open", "seal": "seal"}
    if gcm_case:
        swaps.update({"seal-in-place": "seal-in-place", "open-disjoint": "reject-disjoint",
                      "reject-disjoint": "open-disjoint"})
    output_checks = {"seal", "seal-in-place", "open", "open-disjoint"} if gcm_case else set()
    with path.open() as rows:
        for row in rows:
            f = row.rstrip("\n").split("\t")
            kind = f[0]
            if not f[4 if gcm_case else 3]:
                continue
            if kind in swaps:
                bad = f.copy()
                bad[0] = swaps.pop(kind)
                if kind.startswith("seal"):
                    bad[-1] = flip(bad[-1])
                yield "\t".join(bad) + "\n"
            if kind in output_checks:
                output_checks.remove(kind)
                field = 4 if kind.startswith("seal") else 5
                f[field] = flip(f[field])
                yield "\t".join(f) + "\n"
            if not swaps and not output_checks:
                return
    raise ValueError("incomplete nonempty native controls")


def flip(field):
    if not field:
        raise ValueError("empty differential control")
    return ("0" if field[0] != "0" else "1") + field[1:]


def replay(consumer, env, command, path, expected, family, *, negative=False):
    def run(**kwargs):
        pkg.cargo_environment.check(consumer, env)
        return subprocess.run(command, cwd=consumer, env=env, capture_output=True, text=True,
                              timeout=300, **kwargs)

    with path.open("rb") as rows:
        result = run(stdin=rows)
    if result.returncode or result.stdout.splitlines() != [expected]:
        raise ValueError(f"{family} {path.name}: incomplete paired replay: {result.stderr[-1000:]}")
    if negative:
        marker = "case 1: wrong result, output or scratch" if family == "aes-gcm" else "GMAC case 1 failed"
        for wrong in controls(path, family):
            bad = run(input=wrong)
            if bad.returncode == 0 or bad.stdout or marker not in bad.stderr:
                raise ValueError(f"{family}: incorrect expectation did not fail at the replay check")


def datasets(root):
    nist = runpy.run_path(str(HERE / "check-gcmvs.py"))
    if not nist["ARCHIVE"].is_file():
        raise ValueError("missing local checksum-pinned references/local/gcmtestvectors.zip")
    data = nist["corpus"](nist["ARCHIVE"])
    gcm_path, mac_path = (root / f"nist-{name}.tsv" for name in ("gcm", "gmac"))
    gcm_path.write_text(data)
    mac = runpy.run_path(str(ROOT / "scripts/gmac/check-consumer.py"))
    mac_path.write_text("".join(line + "\n" for line in mac["select_gmac"](data.splitlines())))
    return {family: (portable["transcript"](root, family), (path, expected))
            for family, path, expected in (("aes-gcm", gcm_path, "seal=16875 open=8371 reject=8504"),
                                           ("gmac", mac_path, "generate=3375 verify=1657 reject=1718"))}


def executable(messages, package_id, name, expected):
    artifacts = [msg.get("executable") for msg in map(json.loads, messages.splitlines())
                 if msg.get("reason") == "compiler-artifact" and msg.get("package_id") == package_id
                 and msg["target"]["name"] == name and msg["target"]["kind"] == ["example"]
                 and not msg["profile"]["test"]]
    if artifacts != [str(expected)] or expected.is_symlink() or not expected.is_file():
        raise ValueError("missing or ambiguous linked archive executable")
    return expected


def main():
    if (platform.system(), platform.machine()) != ("Linux", "x86_64") or any(k in os.environ for k in REJECT):
        raise ValueError("requires native Linux x86-64 without ambient compiler/runner overrides")
    portable["frozen"]()
    with pkg.cargo_environment.private_directory(ROOT) as tmp:
        root = Path(tmp)
        env = pkg.isolated_env(root)
        streams = datasets(root)
        versions = pkg.package_archives(root, pkg.MODERN, archives.ENDPOINTS[-1], env)
        # An ordinary baseline binary checks the AES ISA before starting any
        # specialized binary. The public pair itself requires PCLMUL and both KATs.
        for version in archives.ENDPOINTS:
            probe = root / ("probe-" + version)
            pkg.run(["rustc", "+" + version, "--edition=2024", str(ROOT / "assurance/aes-kernel-candidate/probe.rs"),
                     "-o", str(probe)], root, env)
            if pkg.run([str(probe)], root, env).stdout.splitlines() != ["AES_STATIC_HOST_BUNDLE_PASS"]:
                raise ValueError("missing baseline ISA preflight")
        native = dict(env, RUSTFLAGS="-Ctarget-feature=+aes,+sse2")
        for route, dep in (("direct", "brynja-crypto"), ("facade", "brynja")):
            for family, (go, nist) in streams.items():
                consumer = prepare(root, family, dep, versions)
                pkg.run(["cargo", "+" + archives.ENDPOINTS[0], "generate-lockfile", "--offline"], consumer, env)
                for version in archives.ENDPOINTS:
                    cargo = ["cargo", "+" + version]
                    flags = [*portable["BASE"], "--features", route + ",native"]
                    info = pkg.run(cargo + ["metadata", "--format-version", "1", *flags], consumer, native)
                    gcm["check_graph"](json.loads(info.stdout), consumer, versions, dep,
                                       features=(family + "-execution",), unpacked=root / "unpacked", paired=True)
                    example = "gcmvs" if family == "aes-gcm" else "nist"
                    built = pkg.run(cargo + ["build", "--release", "--target", TARGET, *flags, "--example", example,
                                             "--message-format=json"], consumer, native)
                    image = executable(built.stdout, json.loads(info.stdout)["resolve"]["root"], example,
                                       root / "target" / TARGET / "release/examples" / example)
                    sha = linked["digest"](image)
                    bodies = linked["review"](linked["load"](image), version)
                    command = [str(image)]
                    replay(consumer, native, command, *go, family, negative=True)
                    replay(consumer, native, command, *nist, family)
                    if linked["digest"](image) != sha:
                        raise ValueError("linked image changed during replay")
                    print(f"{version} {route} {family}: linked bodies={bodies} ELF sha256={sha}", flush=True)
                    print(f"{version} {route} {family}: paired Go and NIST archives passed", flush=True)
    print("X86_PAIRED_AEAD_LINKED_COMPLETE")
    print("X86_PAIRED_AEAD_ARCHIVES_COMPLETE")


if __name__ == "__main__":
    main()
