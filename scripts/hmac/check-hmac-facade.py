#!/usr/bin/env python3
"""Focused HMAC facade acceptance from real archives, never an old-family sweep."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import tomllib
from unittest.mock import patch

import hmac_acceptance
import hmac_package
import hmac_combined_acceptance as combined

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "scripts/repository"))
spec = importlib.util.spec_from_file_location(
    "hmac_facade_host", ROOT / "scripts/repository/check-facade-package.py")
api = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = api
spec.loader.exec_module(api)

FEATURES = ("hmac-hardened-execution", "hmac-runtime-execution")
POSITIVE = '''pub fn portable(key: &[u8], message: &[u8], out: &mut [u8])
 -> Result<(), api::hmac::Error> {
    let _ = api::hmac::Hmac::<api::hmac::Sha256>::authenticate(key, message, out)?;
    Ok(())
}
'''
STATIC = '''pub fn accelerated<'a>(authority: &'a api::cpu::static_execution::Authority)
 -> Result<api::hmac::execution::Hmac<'a, api::hmac::Sha256>, api::hmac::Error> {
    api::hmac::execution::Hmac::from_static(authority, b"key")
}
'''
RUNTIME = '''pub fn runtime<'a>(authority: &'a api::cpu::runtime_execution::Authority)
 -> Result<api::hmac::execution::Hmac<'a, api::hmac::Sha256>, api::hmac::Error> {
    api::hmac::execution::Hmac::from_runtime(authority, b"key")
}
'''


def check_graph(cargo, consumer, env, roots, features):
    doc = json.loads(api.resolved_metadata(cargo, consumer, env, roots).stdout)
    api.graph(doc, features)
    return doc


def facade_isolation(doc):
    ids = {p["id"] for p in doc["packages"] if p["name"] in ("brynja", "brynja-crypto")}
    # Protocol dependencies may enable the empty `default` marker. It is not
    # an execution opt-in; every substantive facade feature must remain absent.
    api.require(all(set(n["features"]) <= {"default"}
                    for n in doc["resolve"]["nodes"] if n["id"] in ids),
                "leaf activation silently enabled facade feature")


def negatives(cargo, consumer, env, package):
    count = 0
    for _label, code, expected in hmac_acceptance.negative_cases():
        api.source(consumer, package, "use api::hmac::*;\n" + code)
        hmac_acceptance.diagnostic_rejection(
            api.run(cargo + ["check", "--offline", "--message-format=json"],
                    consumer, env, success=False), expected)
        count += 1
    print(f"{package}: {count} facade HMAC ownership/API negatives rejected", flush=True)


def execute(root, toolchain, bare_target):
    env = api.clean_environment(root)
    specifications = api.archives.specifications(api.packaging)
    specifications += tuple((name, tomllib.loads((ROOT / 'crates' / name / 'Cargo.toml').read_text())
                            ['package']['version'], ('src/lib.rs',)) for name in combined.ADDITIONAL)
    with patch.dict(os.environ, env, clear=True), \
            patch.object(api.packaging, "PACKAGING_PACKAGES", specifications):
        roots = api.parallelhash.package_roots(api.packaging, root)
    leaf = roots["brynja-mac-hmac"]
    hmac_package.validate_members(str(path.relative_to(leaf))
                                 for path in leaf.rglob("*") if path.is_file())
    consumer = root / "consumer"
    (consumer / "src").mkdir(parents=True)
    cargo = ["cargo", "+" + toolchain]
    fixture = (ROOT / "assurance/hmac-facade/acceptance.rs").read_text()
    for package in ("brynja-crypto", "brynja"):
        for defaults in (False, True):
            api.manifest(consumer, roots, package, [], defaults)
            api.source(consumer, package, fixture)
            for profile in ([], ["--release"]):
                api.test_run(cargo, consumer, env, 4, profile)
            check_graph(cargo, consumer, env, roots, [])
        api.source(consumer, package, POSITIVE)
        api.run(cargo + ["build", "--offline", "--target", bare_target], consumer, env)
        negatives(cargo, consumer, env, package)
        for feature in FEATURES:
            api.manifest(consumer, roots, package, [feature])
            api.source(consumer, package, POSITIVE + STATIC +
                       (RUNTIME if feature == "hmac-runtime-execution" else ""))
            # Existing CPU inline-assembly boundaries require a supported
            # target ABI/bundle for code generation. Generic bare x86 uses a
            # soft-float ABI: this lane is explicitly type-check only.
            api.run(cargo + ["check", "--offline", "--target", bare_target], consumer, env)
            api.run(cargo + ["build", "--offline"], consumer, env)
            check_graph(cargo, consumer, env, roots, [feature])
        # Activating the leaf elsewhere must not publish this facade's execution namespace.
        extra = ('leaf={package="brynja-mac-hmac", version="=0.1.0", '
                 'default-features=false, features=["runtime-execution"]}\n')
        api.manifest(consumer, roots, package, [], extra=extra)
        api.source(consumer, package, "pub use leaf::execution;\n")
        api.run(cargo + ["check", "--offline"], consumer, env)
        doc = check_graph(cargo, consumer, env, roots, ["hmac-runtime-execution"])
        facade_isolation(doc)
        api.source(consumer, package, "pub use api::hmac::execution;\n")
        hmac_acceptance.diagnostic_rejection(
            api.run(cargo + ["check", "--offline", "--message-format=json"],
                    consumer, env, success=False), "E0432")
        print(f"{package}: portable no_std build, opt-in no_std check/native build, feature isolation PASS", flush=True)
    api.adversarial.protocols(api, consumer, roots, cargo, env, bare_target)
    combined.execute(api, roots, consumer, cargo, env, bare_target)
    print("Focused HMAC facade acceptance: PASS; no native or independent qualification claim")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", default="1.99.1")
    parser.add_argument("--bare-target", default="x86_64-unknown-none")
    args = parser.parse_args()
    with api.cargo_environment.private_directory(ROOT) as raw:
        execute(Path(raw), args.toolchain, args.bare_target)


if __name__ == "__main__":
    main()
