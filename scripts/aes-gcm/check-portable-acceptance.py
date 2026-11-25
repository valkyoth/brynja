"""v0.29.2: execute frozen public GCM and GMAC fixtures against one set of Cargo archives."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
gcm = runpy.run_path(str(HERE / "check-packaged-api.py"))
ROOT, pkg, archives = (gcm[k] for k in ("ROOT", "pkg", "archives"))
FIXTURE = ROOT / "assurance/aead-portable-acceptance"
BASE = ["--locked", "--offline", "--no-default-features"]
INPUTS = {
    "assurance/aead-portable-acceptance/README.md", "assurance/aead-portable-acceptance/lifecycle.rs",
    "assurance/aes-gcm-consumer/src/lib.rs", "assurance/aes-gcm-consumer/src/general_iv.rs",
    "assurance/aes-gcm-consumer/tests/nist_worked.rs", "assurance/aes-gcm-consumer/tests/nist-worked.txt",
    "assurance/aes-gcm-consumer/examples/gcmvs.rs", "assurance/gmac-consumer/src/lib.rs",
    "assurance/gmac-consumer/examples/nist.rs", "crates/brynja-crypto/tests/gmac.rs",
    "crates/brynja-crypto/tests/fixtures/gmac_nist.rs", "assurance/aes-gcm-oracle/boundaries.go",
    "assurance/gmac-oracle/boundaries.go",
}


def frozen():
    seen = set()
    for line in (FIXTURE / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split("  ")
        if name not in INPUTS or name in seen:
            raise ValueError("unexpected frozen input: " + name)
        seen.add(name)
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
            raise ValueError("frozen acceptance input changed: " + name)
    if seen != INPUTS:
        raise ValueError("incomplete frozen fixture inventory")


def readme_test():
    blocks = re.findall(r"^```rust\n(.*?)^```$", (FIXTURE / "README.md").read_text(), re.M | re.S)
    if len(blocks) != 1:
        raise ValueError("expected one executable README example")
    return blocks[0] + "\n#[test] fn example() { round_trip(&[1;16], &[2;16], *b\"test\", 1); }\n"


def prepare_mac(root, dep, versions):
    tree = root / dep
    consumer = tree / "assurance/gmac-consumer"
    source = ROOT / "assurance/gmac-consumer"
    shutil.copytree(source / "src", consumer / "src")
    shutil.copytree(source / "examples", consumer / "examples")
    # Preserve the test module's relative include, but take the shared NIST
    # decoder and integration tests from the *unpacked* crypto crate.
    archive = root / "unpacked" / ("brynja-crypto-" + versions["brynja-crypto"])
    tests = tree / "crates/brynja-crypto/tests"
    (tests / "fixtures").mkdir(parents=True)
    shutil.copyfile(archive / "tests/fixtures/gmac_nist.rs", tests / "fixtures/gmac_nist.rs")
    shutil.copyfile(archive / "tests/gmac.rs", tests / "gmac.rs")
    (consumer / "tests").mkdir()
    (consumer / "tests/vectors.rs").write_text(
        'extern crate self as brynja_crypto;\npub use gmac_consumer::crypto::gmac;\n'
        '#[path="../../../crates/brynja-crypto/tests/gmac.rs"] mod vectors;\n')
    (consumer / "tests/readme.rs").write_text(readme_test())
    shutil.copyfile(FIXTURE / "lifecycle.rs", consumer / "tests/lifecycle.rs")
    patches = "".join(f'{n}={{path={json.dumps(str(root / "unpacked" / (n+"-"+v)))}}}\n'
                      for n, v in versions.items())
    (consumer / "Cargo.toml").write_text(
        '[workspace]\n[package]\nname="gmac-consumer"\nversion="0.0.0"\nedition="2024"\n'
        'rust-version="1.90"\npublish=false\n[features]\ndirect=[]\nfacade=[]\n'
        f'gmac=["{dep}/gmac"]\ngcm=["{dep}/aes-gcm"]\n[dependencies]\n'
        f'{dep}={{version="={versions[dep]}",default-features=false}}\n[patch.crates-io]\n' + patches)
    return consumer


def transcript(root, family):
    spec = runpy.run_path(str(ROOT / f"scripts/{family}/check-boundaries.py"))
    path = root / (family + ".tsv")
    env = dict(PATH=os.environ["PATH"], HOME=str(root), GOCACHE=str(root / "go-cache"),
               GOENV="off", GOPROXY="off", GO111MODULE="off", CGO_ENABLED="0", GOTOOLCHAIN="local")
    with path.open("xb") as out:
        subprocess.run(["go", "run", str(spec["ORACLE"])], cwd=root, env=env, stdout=out,
                       check=True, timeout=180)
    with path.open("rb") as data:
        expected = spec["TRANSCRIPT" if family == "aes-gcm" else "DIGEST"]
        if hashlib.file_digest(data, "sha256").hexdigest() != expected:
            raise ValueError("differential transcript changed: " + family)
    return path, spec["EXPECTED"]


def replay(cargo, consumer, env, flags, example, data, expected):
    command = [*cargo, "run", "--release", *flags, "--example", example]
    pkg.cargo_environment.check(consumer, env)
    with data.open("rb") as rows:
        result = subprocess.run(command, cwd=consumer, env=env, stdin=rows, capture_output=True,
                                text=True, timeout=300)
    if result.returncode or result.stdout.strip() != expected:
        raise ValueError(f"{example} archived differential failed: {result.stderr[-2000:]}")
    with data.open() as rows:
        fields = rows.readline().rstrip("\n").split("\t")
    fields[-1] = ("0" if fields[-1][0] != "0" else "1") + fields[-1][1:]
    bad = subprocess.run(command, cwd=consumer, env=env, input="\t".join(fields)+"\n",
                         capture_output=True, text=True, timeout=60)
    marker = "GMAC case 1 failed" if example == "nist" else "case 1: wrong result"
    if not bad.returncode or bad.stdout or marker not in bad.stderr:
        raise ValueError("wrong expected tag did not fail replay: " + example)


def check_mac(root, consumer, dep, versions, compiler, route, env):
    cargo = ["cargo", "+" + compiler]
    mac = [*BASE, "--features", route + ",gmac"]
    both = [*BASE, "--features", route + ",gmac,gcm"]
    for flags, features in ((mac, ("gmac",)), (both, ("aes-gcm", "gmac"))):
        info = pkg.run(cargo + ["metadata", "--format-version", "1", *flags], consumer, env)
        gcm["check_graph"](json.loads(info.stdout), consumer, versions, dep, features=features,
                           unpacked=root / "unpacked")
    for flags, selection, count in ((mac, ["--lib"], 1), (mac, ["--doc"], 4),
                                    (mac, ["--test", "vectors"], 5),
                                    (both, ["--test", "readme"], 1),
                                    (both, ["--test", "lifecycle"], 2)):
        run = pkg.run(cargo + ["test", "--release", *flags, *selection], consumer, env)
        if not archives.exact_suite(run.stdout, count):
            raise ValueError("incomplete archive suite: " + str(selection))
    for flags in (mac, both):
        pkg.run(cargo + ["check", "--lib", "--target", "thumbv7em-none-eabi", *flags], consumer, env)
    absent = pkg.cargo_result(cargo + ["check", "--lib", "--message-format=json", *BASE,
                                       "--features", route], consumer, env, timeout=120)
    if not pkg.diagnostic_matches(absent, "E0432", filename="src/lib.rs"):
        raise ValueError("GMAC without opt-in did not fail at the expected import")
    probe = consumer / "src/bin/probe.rs"
    probe.parent.mkdir(exist_ok=True)
    for owner, method, correct, wrong, args in (
            ("gmac::Aes128Gmac", "verify", "&GmacTag", "&[u8;16]", "iv, &[], tag"),
            ("aes_gcm::Aes128Gcm", "open_in_place", "&[u8;16]", "&GmacTag", "iv, &[], tag, &mut [], &mut []")):
        body = ("use gmac_consumer::crypto::{"+owner+" as Owner,gmac::GmacTag};\n"
                "fn call(o:&Owner<'_>, iv:&[u8;12], tag:TYPE){let _ = o."+method+"("+args+");}\nfn main(){}")
        cmd = cargo + ["check", "--bin", "probe", "--message-format=json", *both]
        probe.write_text(body.replace("TYPE", correct))
        pkg.run(cmd, consumer, env)
        probe.write_text(body.replace("TYPE", wrong))
        if not pkg.diagnostic_matches(pkg.cargo_result(cmd, consumer, env, timeout=120), "E0308"):
            raise ValueError("unexpected cross-profile tag diagnostic")
    probe.unlink()  # A deliberately ill-typed binary must not affect later cargo tests.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true", help="skip the separately registered Go campaign")
    smoke = parser.parse_args().smoke
    if any(k in os.environ for k in pkg.REJECT_ENV):
        raise ValueError("remove ambient compiler/target overrides")
    frozen()
    with pkg.cargo_environment.private_directory(ROOT) as tmp:
        root = Path(tmp)
        env = pkg.isolated_env(root)
        versions = pkg.package_archives(root, pkg.MODERN, archives.ENDPOINTS[-1], env)
        streams = {} if smoke else {family: transcript(root, family) for family in ("aes-gcm", "gmac")}
        for route, dep in (("direct", "brynja-crypto"), ("facade", "brynja")):
            aead = gcm["prepare"](root, dep, versions)
            (aead / "examples").mkdir()
            shutil.copyfile(gcm["FIXTURE"] / "examples/gcmvs.rs", aead / "examples/gcmvs.rs")
            mac = prepare_mac(root, dep, versions)
            for consumer in (aead, mac):
                pkg.run(["cargo", "+"+archives.ENDPOINTS[0], "generate-lockfile", "--offline"], consumer, env)
            for compiler in archives.ENDPOINTS:
                gcm["check"](compiler, route, dep, aead, versions, env)
                check_mac(root, mac, dep, versions, compiler, route, env)
                for consumer, family, feature, example in (
                        (aead, "aes-gcm", "gcm", "gcmvs"), (mac, "gmac", "gmac", "nist")):
                    if family in streams:
                        replay(["cargo", "+"+compiler], consumer, env, [*BASE, "--features", route+","+feature],
                               example, *streams[family])
                print(f"{compiler} {route}: portable archived GCM and GMAC acceptance passed", flush=True)
    print("PORTABLE_AEAD_ARCHIVES_SMOKE_COMPLETE" if smoke else "PORTABLE_AEAD_ARCHIVES_COMPLETE")


if __name__ == "__main__":
    main()
