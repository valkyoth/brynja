#!/usr/bin/env python3
"""Mutation regressions for the separate protected legacy consumer boundary."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

import legacy_hmac_hosted_acceptance as policy

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "scripts/repository"))
spec = importlib.util.spec_from_file_location("workspace", ROOT / "scripts/repository/validate-workspace-metadata.py")
workspace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workspace)


def graph(resident=False, accelerated=False):
    features = policy.features(resident, accelerated)
    roots = {name: Path("/archives") / name for name in features if name != "legacy-hosted-external"}
    consumer = Path("/consumer")
    packages = [{"id": name, "name": name, "source": None,
                 "manifest_path": str((consumer if name == "legacy-hosted-external" else roots[name]) / "Cargo.toml")}
                for name in features]
    nodes = [{"id": name, "features": sorted(values)} for name, values in features.items()]
    return {"packages": packages, "resolve": {"nodes": nodes}}, roots, consumer


class HostedAcceptance(unittest.TestCase):
    def test_accelerated_closure_is_explicit_and_preserves_profile(self):
        for resident in (False, True):
            original, roots, consumer = graph(resident, True)
            policy.graph(original, roots, consumer, resident, True)
            for selected_resident, accelerated in ((resident, False), (not resident, True)):
                with self.assertRaises(ValueError):
                    policy.graph(original, roots, consumer, selected_resident, accelerated)
            for index, node in enumerate(original["resolve"]["nodes"]):
                for feature in node["features"]:
                    changed = copy.deepcopy(original)
                    changed["resolve"]["nodes"][index]["features"].remove(feature)
                    with self.subTest(resident=resident, node=node["id"], feature=feature), self.assertRaises(ValueError):
                        policy.graph(changed, roots, consumer, resident, True)
        policy.runtime("test result: ok. 10 passed; 0 failed; 0 ignored;", 10)
        for value in ("6 passed; 0 failed; 0 ignored;", "10 passed; 0 failed; 1 ignored;"):
            with self.assertRaises(ValueError):
                policy.runtime("test result: ok. " + value, 10)

    def test_archive_population(self):
        policy.members(policy.FILES)
        for name in policy.FILES:
            with self.subTest(missing=name), self.assertRaises(ValueError):
                policy.members(policy.FILES - {name})
        for name in ("evidence.json", "tests/acceptance.rs", "../x", "/x", "src/../x", "src//x", "src\\x", "README.md"):
            with self.subTest(extra=name), self.assertRaises(ValueError):
                policy.members([*policy.FILES, name])

    def test_graph_identity_origin_and_features(self):
        original, roots, consumer = graph()
        policy.graph(original, roots, consumer)
        for index, package in enumerate(original["packages"]):
            for field, value in (("name", "foreign"), ("source", "registry+foreign"), ("manifest_path", "/outside/Cargo.toml")):
                changed = copy.deepcopy(original)
                changed["packages"][index][field] = value
                with self.subTest(package=package["name"], field=field), self.assertRaises(ValueError):
                    policy.graph(changed, roots, consumer)
            changed = copy.deepcopy(original)
            changed["resolve"]["nodes"][index]["features"].append("acceleration")
            with self.subTest(package=package["name"]), self.assertRaises(ValueError):
                policy.graph(changed, roots, consumer)
        for field in ("packages", "nodes"):
            for duplicate in (True, False):
                changed = copy.deepcopy(original)
                rows = changed[field] if field == "packages" else changed["resolve"][field]
                if duplicate:
                    rows.append(copy.deepcopy(rows[0]))
                else:
                    rows.pop()
                with self.subTest(field=field, duplicate=duplicate), self.assertRaises(ValueError):
                    policy.graph(changed, roots, consumer)

    def test_runtime_requires_all_six_executions(self):
        original = "test result: ok. 6 passed; 0 failed; 0 ignored;"
        policy.runtime(original, 6)
        for changed in ("", original.replace("6 passed", "5 passed"), original.replace("0 failed", "1 failed"), original.replace("0 ignored", "1 ignored")):
            with self.subTest(output=changed), self.assertRaises(ValueError):
                policy.runtime(changed, 6)

    def test_resident_graph_cannot_substitute_strict_or_enable_acceleration(self):
        original, roots, consumer = graph(True)
        policy.graph(original, roots, consumer, True)
        with self.assertRaises(ValueError):
            policy.graph(original, roots, consumer, False)
        for name in (policy.HOST, "brynja-crypto-cpu-std"):
            for feature in ("protected-memory", "macos-resident-acceleration", "strict-execution"):
                changed = copy.deepcopy(original)
                node = next(n for n in changed["resolve"]["nodes"] if n["id"] == name)
                node["features"] = [feature]
                with self.subTest(name=name, feature=feature), self.assertRaises(ValueError):
                    policy.graph(changed, roots, consumer, True)

    def test_real_workspace_hosted_features_and_defaults(self):
        graph = json.loads(subprocess.check_output(["cargo", "metadata", "--offline", "--locked", "--all-features", "--format-version=1"], cwd=ROOT, text=True))
        packages = {p["name"]: p for p in graph["packages"]}
        name = policy.HOST
        entry = workspace.load_policy()[name]
        workspace.validate_dependencies(name, packages[name], entry, packages)
        workspace.validate_features(name, packages[name], entry)
        for replacement in ([], ["dep:brynja-crypto-cpu-std"], ["brynja-crypto-cpu-std/strict-hmac"], ["brynja-crypto-cpu-std/runtime-execution"]):
            package = copy.deepcopy(packages[name])
            package["features"]["strict-execution"] = replacement
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                workspace.validate_features(name, package, entry)
        package = copy.deepcopy(packages[name])
        package["features"]["default"] = ["strict-execution"]
        with self.assertRaises(ValueError):
            workspace.validate_features(name, package, entry)
        for replacement in ([], ["brynja-crypto-cpu-std/protected-memory"], ["brynja-crypto-cpu-std/macos-resident-acceleration"]):
            package = copy.deepcopy(packages[name])
            package["features"]["macos-resident"] = replacement
            with self.subTest(resident=replacement), self.assertRaises(ValueError):
                workspace.validate_features(name, package, entry)
        for dependency in ("brynja-legacy-hmac", "brynja-crypto-cpu-std"):
            for field, value in (("uses_default_features", True), ("features", ["hmac-execution"]), ("req", "*")):
                package = copy.deepcopy(packages[name])
                selected = next(d for d in package["dependencies"] if d["name"] == dependency)
                selected[field] = value
                with self.subTest(dependency=dependency, field=field), self.assertRaises(ValueError):
                    workspace.validate_dependencies(name, package, entry, packages)
        for feature in ("strict-sha1-acceleration", "macos-resident-sha1-acceleration"):
            for replacement in ([], ["brynja-legacy-hmac/sha1-execution"], ["brynja-legacy-hmac/md5-batch"]):
                package = copy.deepcopy(packages[name])
                package["features"][feature] = replacement
                with self.subTest(feature=feature, replacement=replacement), self.assertRaises(ValueError):
                    workspace.validate_features(name, package, entry)


if __name__ == "__main__":
    unittest.main()
