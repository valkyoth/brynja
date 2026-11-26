"""Install a public consumer from isolated, unpacked crates. No user-wide install."""
import argparse
import json
import os
from pathlib import Path
import platform
import runpy
import shutil

HERE = Path(__file__).resolve().parent
portable = runpy.run_path(str(HERE / "check-portable-acceptance.py"))
ROOT, pkg, archives, gcm = (portable[k] for k in ("ROOT", "pkg", "archives", "gcm"))
NAME = "brynja-aead-consumer"


def prepare(root, dep, versions):
    consumer = root / dep
    src = consumer / "src"
    src.mkdir(parents=True)
    shutil.copyfile(ROOT / "assurance/aead-installed-consumer/main.rs", src / "main.rs")
    shutil.copyfile(gcm["FIXTURE"] / "tests/nist-worked.txt", src / "nist-worked.txt")
    patches = "".join(f'{n}={{path={json.dumps(str(root / "unpacked" / (n+"-"+v)))}}}\n'
                      for n, v in versions.items())
    (consumer / "Cargo.toml").write_text(
        f'[workspace]\n[package]\nname="{NAME}"\nversion="0.0.0"\nedition="2024"\npublish=false\n'
        '[features]\ndirect=[]\nfacade=[]\nnative=[]\naes-gcm=[]\ngmac=[]\n'
        f'[dependencies]\nsubject={{package="{dep}",version="={versions[dep]}",default-features=false}}\n'
        '[patch.crates-io]\n' + patches)
    return consumer


def run(native):
    if any(k in os.environ for k in pkg.REJECT_ENV):
        raise ValueError("remove compiler or target overrides before running")
    if native and (platform.system(), platform.machine()) != ("Linux", "x86_64"):
        raise ValueError("--native-x86 requires native Linux x86-64")
    portable["frozen"]()
    with pkg.cargo_environment.private_directory(ROOT) as tmp:
        root = Path(tmp)
        env = pkg.isolated_env(root)
        versions = pkg.package_archives(root, pkg.MODERN, archives.ENDPOINTS[-1], env)
        for dep, route in (("brynja-crypto", "direct"), ("brynja", "facade")):
            consumer = prepare(root, dep, versions)
            pkg.run(["cargo", "+" + archives.ENDPOINTS[0], "generate-lockfile", "--offline"], consumer, env)
            for version in archives.ENDPOINTS:
                cargo = ["cargo", "+" + version]
                build = env
                if native:
                    host = "x86_64-unknown-linux-gnu"
                    if "host: " + host not in pkg.run(["rustc", "+" + version, "-vV"], root, env).stdout.splitlines():
                        raise ValueError("unexpected compiler host")
                    probe = root / "probe"
                    pkg.run(["rustc", "+" + version, "--edition=2024", str(ROOT / "assurance/aes-kernel-candidate/probe.rs"), "-o", str(probe)], root, env)
                    if pkg.run([str(probe)], root, env).stdout.splitlines() != ["AES_STATIC_HOST_BUNDLE_PASS"]:
                        raise ValueError("baseline CPU preflight did not pass")
                    build = dict(env, RUSTFLAGS="-Ctarget-feature=+aes,+sse2")
                for family in ("aes-gcm", "gmac"):
                    feature = family + ("-execution" if native else "")
                    flags = [*portable["BASE"], "--features", ",".join(
                        [route, family, "subject/" + feature] + (["native"] if native else []))]
                    info = pkg.run(cargo + ["metadata", "--format-version", "1", *flags], consumer, build)
                    gcm["check_graph"](json.loads(info.stdout), consumer, versions, dep,
                                       features=(feature,), paired=native)
                    prefix = root / "installed" / route / version / family
                    pkg.run(cargo + ["install", "--path", ".", "--root", str(prefix), *flags], consumer, build)
                    binary = prefix / "bin" / (NAME + (".exe" if os.name == "nt" else ""))
                    count = 26 if family == "aes-gcm" else 10
                    if pkg.run([str(binary)], root, env).stdout.splitlines() != [
                            f"INSTALLED_CONSUMER_PASS [{count}, {count}, {count}]"]:
                        raise ValueError("incomplete installed consumer run")
                    print(f"{version} {route} {feature}: installed consumer passed", flush=True)
    print("AEAD_INSTALLED_NATIVE_PASS" if native else "AEAD_INSTALLED_PORTABLE_PASS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-x86", action="store_true", help="require AES-NI/PCLMUL; no fallback")
    run(parser.parse_args().native_x86)
