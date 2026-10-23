#!/usr/bin/env python3
"""Mutation coverage for archive, graph and independent-oracle acceptance."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

import legacy_hmac_acceptance as policy

SPEC = importlib.util.spec_from_file_location("capture", Path(__file__).with_name("check-legacy-hmac-package.py"))
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


def graph():
    names = [*policy.NAMES, "brynja-crypto", "brynja-tls"]
    packages = [{"id": name, "name": name} for name in names]
    nodes = [{"id": name, "deps": []} for name in names]
    value = {"packages": packages, "workspace_members": names, "resolve": {"nodes": nodes}}
    for name in policy.NAMES[:-1]:
        edge(value, "brynja-legacy-hmac", name)
    edge(value, "brynja-tls", "brynja-crypto")
    return value


def edge(value, source, target, kind=None):
    node = next(n for n in value["resolve"]["nodes"] if n["id"] == source)
    node["deps"].append({"pkg": target, "dep_kinds": [{"kind": kind, "target": None}]})


class Acceptance(unittest.TestCase):
    def test_bit_model_population_and_mutations(self):
        rows = [f"{identity}:{tag}" for identity, tag in capture.legacy_hmac_bits.expected().items()]
        capture.legacy_hmac_bits.validate("\n".join(rows))
        for mutant in ([], rows[:-1], rows + rows[:1], rows[:-1] + ["sha1:129:1025:00"]):
            with self.subTest(count=len(mutant)), self.assertRaises(ValueError):
                capture.legacy_hmac_bits.validate("\n".join(mutant))

    def test_real_workspace_rejects_hash_default_and_feature_drift(self):
        spec = importlib.util.spec_from_file_location("workspace", capture.ROOT / "scripts/repository/validate-workspace-metadata.py")
        workspace = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(workspace)
        metadata = json.loads(subprocess.check_output(
            ["cargo", "metadata", "--offline", "--locked", "--all-features", "--format-version", "1"],
            cwd=capture.ROOT, text=True))
        packages = {p["name"]: p for p in metadata["packages"]}
        name = "brynja-legacy-hmac"
        entry = workspace.load_policy()[name]
        workspace.validate_dependencies(name, packages[name], entry, packages)
        for digest in ("brynja-legacy-sha1", "brynja-legacy-md5"):
            for field, replacement in (("uses_default_features", True), ("features", ["cpu"]), ("optional", True)):
                package = copy.deepcopy(packages[name])
                dependency = next(d for d in package["dependencies"] if d["name"] == digest)
                dependency[field] = replacement
                with self.subTest(digest=digest, field=field), self.assertRaises(ValueError):
                    workspace.validate_dependencies(name, package, entry, packages)

    def test_current_footprint(self):
        policy.members(policy.REQUIRED | policy.OPTIONAL)

    def test_missing_required_files(self):
        for name in policy.REQUIRED:
            with self.subTest(name=name), self.assertRaises(ValueError):
                policy.members(policy.REQUIRED - {name})

    def test_extra_or_noncanonical_files(self):
        for name in ("tests/rfc.rs", "evidence.json", "examples/oracle.rs", "../src.rs", "/src.rs",
                     "src/../engine.rs", "src\\engine.rs", "src//engine.rs", "README.md"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                policy.members([*policy.REQUIRED, name])

    def test_isolated_and_dev_only(self):
        value = graph()
        policy.isolation(value)
        edge(value, "brynja-crypto", "brynja-legacy-hmac", "dev")
        policy.isolation(value)

    def test_direct_indirect_and_build_edges(self):
        for source in ("brynja-crypto", "brynja-tls"):
            for kind in (None, "build"):
                value = graph()
                edge(value, source, "brynja-legacy-hmac", kind)
                with self.subTest(source=source, kind=kind), self.assertRaises(ValueError):
                    policy.isolation(value)

    def test_conditional_edges_are_not_ignored(self):
        value = graph()
        edge(value, "brynja-crypto", "brynja-legacy-hmac")
        value["resolve"]["nodes"][-2]["deps"][-1]["dep_kinds"][0]["target"] = 'cfg(target_os="windows")'
        with self.assertRaises(ValueError):
            policy.isolation(value)

    def test_missing_or_duplicate_identities(self):
        for mode in ("node", "package", "duplicate"):
            value = graph()
            if mode == "node":
                value["resolve"]["nodes"].pop()
            elif mode == "package":
                value["packages"].pop()
            else:
                value["packages"].append(copy.deepcopy(value["packages"][0]))
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                policy.isolation(value)

    def test_extra_implementation_dependency(self):
        value = graph()
        edge(value, "brynja-legacy-hmac", "brynja-crypto")
        with self.assertRaises(ValueError):
            policy.isolation(value)

    def test_missing_implementation_dependency(self):
        value = graph()
        value["resolve"]["nodes"][4]["deps"].pop()
        with self.assertRaises(ValueError):
            policy.isolation(value)

    def test_unknown_or_empty_edge_kinds(self):
        for kinds in ([], [{"kind": "unknown"}]):
            value = graph()
            value["resolve"]["nodes"][4]["deps"][0]["dep_kinds"] = kinds
            with self.subTest(kinds=kinds), self.assertRaises(ValueError):
                policy.isolation(value)

    def test_packaged_paths_and_population(self):
        roots = {name: Path("/extracted") / name for name in policy.NAMES}
        consumer = Path("/consumer")
        paths = {**roots, "legacy-hmac-external": consumer}
        valid = {"packages": [{"name": name, "source": None, "manifest_path": str(path / "Cargo.toml")}
                              for name, path in paths.items()]}
        policy.packaged_graph(valid, roots, consumer)
        for field, replacement in (("source", "registry+crates.io"), ("manifest_path", "/workspace/Cargo.toml")):
            value = copy.deepcopy(valid)
            value["packages"][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                policy.packaged_graph(value, roots, consumer)
        for rows in (valid["packages"][:-1], valid["packages"] + [valid["packages"][0]]):
            with self.assertRaises(ValueError):
                policy.packaged_graph({"packages": rows}, roots, consumer)

    def test_oracle_rejects_empty_missing_forged_duplicate(self):
        rows = []
        for name in ("md5", "sha1"):
            for key in (0, 1, 63, 64, 65, 80, 1024):
                for length in (0, 1, 55, 56, 63, 64, 65, 127, 128, 4096):
                    digest = capture.hmac.new(bytes([0xa7]) * key, bytes([0x39]) * length,
                                              getattr(capture.hashlib, name)).hexdigest()
                    rows.append(f"{name}:{key}:{length}:{digest}")
        capture.oracle("\n".join(rows))
        for mutant in ([], rows[:-1], rows + rows[:1], rows[:-1] + ["sha1:1024:4096:00"]):
            with self.subTest(count=len(mutant)), self.assertRaises(ValueError):
                capture.oracle("\n".join(mutant))


if __name__ == "__main__":
    unittest.main()
