"""Offline archive acceptance for the portable AES-GCM public API."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tomllib

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "assurance/aes-gcm-consumer"
spec = importlib.util.spec_from_file_location("archive_checks", ROOT / "scripts/ghash/check-packaged-api.py")
archives = importlib.util.module_from_spec(spec)
spec.loader.exec_module(archives)
pkg = archives.pkg
LEAF = "brynja-aead-gcm"
VECTORS = "38b93d7c7b6cedee81dfecd0c99699ccc52783408aa8889f78608a9573cf8800"


def prepare(root, dependency, versions):
    consumer = root / ("consumer-" + dependency)
    for relative in ("src/lib.rs", "src/general_iv.rs", "tests/nist_worked.rs", "tests/nist-worked.txt"):
        out = consumer / relative
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(FIXTURE / relative, out)
    if hashlib.sha256((consumer / "tests/nist-worked.txt").read_bytes()).hexdigest() != VECTORS:
        raise ValueError("NIST fixture changed; verify against published examples")
    patches = "".join(f'{name}={{path={json.dumps(str(root / "unpacked" / (name+"-"+v)))}}}\n'
                      for name, v in versions.items())
    alias = "brynja-crypto" if dependency == LEAF else dependency
    (consumer / "Cargo.toml").write_text(
        '[workspace]\n[package]\nname="aes-gcm-consumer"\nversion="0.0.0"\nedition="2024"\n'
        'rust-version="1.90"\npublish=false\n[features]\ndirect=[]\nfacade=[]\n'
        f'gcm=["{alias}/aes-gcm"]\n[dependencies]\n'
        f'{alias}={{package="{dependency}",version="={versions[dependency]}",default-features=false}}\n'
        '[patch.crates-io]\n' + patches)
    return consumer


def check_graph(metadata, consumer, versions, dependency, *, features=("aes-gcm",), unpacked=None,
                paired=False):
    """Match every resolved edge against the downstream lock, not just crate names."""
    lock = tomllib.loads((FIXTURE / "Cargo.lock").read_text())
    edges = {p["name"]: set(p.get("dependencies", [])) for p in lock["package"]}
    stream = tuple(features) == ("hazmat-chacha20",)
    leaf = "brynja-cipher-chacha"
    if stream:
        edges["brynja-crypto"].discard(LEAF)
        edges[leaf] = {"brynja-core"}
        edges["brynja-crypto"].add(leaf)
    if paired:
        if tuple(features) not in (("aes-gcm-execution",), ("gmac-execution",)):
            raise ValueError("paired archive must select exactly one composed API")
        edges[LEAF].add("brynja-crypto-cpu")
        edges["brynja-cipher-aes"].add("brynja-crypto-cpu")
        edges["brynja-universal-hash-ghash"].add("brynja-crypto-cpu")
        edges["brynja-crypto-cpu"] = set()
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    packages = {p["id"]: p for p in metadata["packages"]}
    if metadata["resolve"]["root"] not in nodes or not any(
        packages[ident]["name"] == (dependency if dependency in (leaf, LEAF) else "brynja-crypto")
        for ident in nodes
    ):
        raise ValueError("missing archive consumer or crypto dependency")
    if dependency == LEAF:
        expected = {LEAF, "brynja-core", "brynja-cipher-aes", "brynja-universal-hash-ghash"}
        if paired:
            expected.add("brynja-crypto-cpu")
        if {packages[i]["name"] for i in nodes if i != metadata["resolve"]["root"]} != expected:
            raise ValueError("standalone composition reaches unexpected packages")
    for ident, node in nodes.items():
        package = packages[ident]
        name = package["name"]
        deps = {packages[d["pkg"]]["name"] for d in node["deps"]}
        path = Path(package["manifest_path"]).resolve()
        if ident == metadata["resolve"]["root"]:
            if path != consumer / "Cargo.toml" or deps != {dependency}:
                raise ValueError("wrong archive consumer entry point")
            continue
        archives_dir = consumer.parent / "unpacked" if unpacked is None else unpacked
        if name not in versions or path != archives_dir / f"{name}-{versions[name]}" / "Cargo.toml":
            raise ValueError("dependency did not resolve to its archive")
        forbidden_cpu = name.endswith("-cpu") and not (paired and name == "brynja-crypto-cpu")
        if deps != edges.get(name) or name.startswith("brynja-legacy") or name.endswith("-std") or forbidden_cpu:
            raise ValueError("unexpected archive dependency graph")
        active = set(node["features"])
        if stream and name == leaf:
            expected = {"hazmat-chacha20"} if dependency == leaf else {"hazmat-chacha20", "default"}
            if active != expected or package["features"].get("default") != []:
                raise ValueError("unexpected raw-stream archive feature set")
        elif name in ("brynja", "brynja-crypto", LEAF):
            expected = set(features)
            if paired and name in (LEAF, "brynja-crypto"):
                expected.add(features[0].removesuffix("-execution"))
            if (dependency == "brynja" and name == "brynja-crypto") or (name == LEAF and dependency != LEAF):
                expected.add("default")
            if active != expected or package["features"].get("default") != []:
                raise ValueError("unexpected archive feature set")
        elif paired and name == "brynja-crypto-cpu":
            if active != {"default", "aes-static-execution", "ghash-runtime-execution"} or package["features"].get("default") != []:
                raise ValueError("unexpected paired CPU features")
        elif name in ("brynja-cipher-aes", "brynja-universal-hash-ghash"):
            expected = {"default", "__mode"}
            if paired:
                expected.add("__mode-execution")
            if stream or active != expected or package["features"].get("default") != []:
                raise ValueError("unexpected mode dependency features")
        elif active - ({"default", "general-sha512-t"} if name == "brynja-hash-sha2" else {"default"}):
            raise ValueError("unexpected transitive feature")


def check(compiler, route, dependency, consumer, versions, env):
    cargo = ["cargo", "+" + compiler]
    base = ["--locked", "--offline", "--no-default-features"]
    flags = [*base, "--features", route + ",gcm"]

    def run(*args):
        return pkg.run(cargo + list(args), consumer, env).stdout

    info = json.loads(run("metadata", "--format-version", "1", *flags))
    check_graph(info, consumer, versions, dependency)
    for selection, count in [(["--lib"], 2), (["--test", "nist_worked"], 3), (["--doc"], 6)]:
        if not archives.exact_suite(run("test", "--release", *flags, *selection), count):
            raise ValueError("incomplete archive suite: " + str(selection))
    run("check", "--lib", "--target", "thumbv7em-none-eabi", *flags)
    # Keep the dependency and consumer route; turn off ONLY the AEAD opt-in.
    result = pkg.cargo_result(cargo + ["check", "--lib", "--message-format=json", *base,
                                      "--features", route], consumer, env, timeout=120)
    if not pkg.diagnostic_matches(result, "E0432", filename="src/lib.rs"):
        raise ValueError("unexpected diagnostic without the GCM feature")
    label = "standalone" if dependency == LEAF else route
    print(f"{compiler} {label}: archived sources, 18 NIST examples, API checks, Cortex-M compile", flush=True)


def main():
    if any(k in os.environ for k in pkg.REJECT_ENV):
        raise ValueError("remove ambient toolchain, target or compiler overrides")
    with pkg.cargo_environment.private_directory(ROOT) as temp:
        root = Path(temp)
        env = pkg.isolated_env(root)
        versions = pkg.package_archives(root, pkg.MODERN, archives.ENDPOINTS[-1], env)
        for route, dep in (("direct", LEAF), ("direct", "brynja-crypto"), ("facade", "brynja")):
            consumer = prepare(root, dep, versions)
            pkg.run(["cargo", "+" + archives.ENDPOINTS[0], "generate-lockfile", "--offline"], consumer, env)
            for compiler in archives.ENDPOINTS:
                check(compiler, route, dep, consumer, versions, env)
    print("AES_GCM_ARCHIVE_COMPLETE")


if __name__ == "__main__":
    main()
