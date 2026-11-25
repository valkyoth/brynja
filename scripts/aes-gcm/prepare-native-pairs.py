"""Prepare a portable, offline native execution bundle (no .git or Cargo caches)."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import shutil
import tarfile

here = Path(__file__).resolve().parent
base = runpy.run_path(str(here / "check-paired-archives.py"))
pkg = base["pkg"]


def prepare(output):
    base["portable"]["frozen"]()
    with pkg.cargo_environment.private_directory(base["ROOT"]) as tmp:
        root = Path(tmp)
        env = pkg.isolated_env(root)
        streams = base["datasets"](root)
        versions = pkg.package_archives(root, pkg.MODERN, "1.100.0", env)
        bundle = root / "bundle"
        bundle.mkdir()
        shutil.move(root / "unpacked", bundle / "unpacked")
        members = [f"unpacked/{n}-{v}" for n, v in versions.items()]
        (bundle / "Cargo.toml").write_text('[workspace]\nresolver="3"\nmembers=' + json.dumps(members)
            + '\n[patch.crates-io]\n' + ''.join(f'{n}={{path="{m}"}}\n' for n, m in zip(versions, members)))
        lock = ["cargo", "+1.90.0", "generate-lockfile", "--offline"]
        pkg.run(lock, bundle, env)
        for family in streams:
            for dep in ("brynja-crypto", "brynja"):
                consumer = base["prepare"](bundle, family, dep, versions)
                manifest = consumer / "Cargo.toml"
                manifest.write_text(manifest.read_text().replace(str(bundle / "unpacked"), "../../unpacked"))
                pkg.run(lock, consumer, env)
        cases = {}
        for family, data in streams.items():
            cases[family] = {}
            for (path, expected), kind in zip(data, ("go", "nist"), strict=True):
                name = family + "-" + kind + ".tsv"
                shutil.copyfile(path, bundle / name)
                cases[family][name] = expected
        (bundle / "cases.json").write_text(json.dumps(cases))
        shutil.copyfile(here / "run-native-pairs.py", bundle / "run.py")
        shutil.copyfile(base["ROOT"] / "assurance/aes-kernel-candidate/probe.rs", bundle / "probe.rs")
        files = sorted(p for p in bundle.rglob("*") if p.is_file())
        def sha(p):
            return hashlib.sha256(p.read_bytes()).hexdigest()
        manifest = bundle / "inputs.json"
        manifest.write_text(json.dumps({p.relative_to(bundle).as_posix(): sha(p) for p in files},
                                      sort_keys=True, indent=2) + "\n")
        with tarfile.open(output, "x:gz") as tar:
            for p in [*files, manifest]:
                tar.add(p, arcname=p.relative_to(bundle).as_posix())
        print(f"Bundle SHA-256: {sha(output)}\nInput manifest SHA-256: {sha(manifest)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    prepare(parser.parse_args().output)
