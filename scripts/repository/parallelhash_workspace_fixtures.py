"""Reject test-to-production promotion and default-on ParallelHash adapters."""
import copy
import parallelhash_workspace_policy as policy


def check(no_default, all_features, package, node, dependency, reject):
    count = 0
    for baseline, mode in ((no_default, "no-default-features"), (all_features, "all-features")):
        for target in ("brynja-crypto-cpu", "brynja-crypto-cpu-std"):
            for field, value, message in (
                ("kind", None, "dependency kind/target"),
                ("kind", "build", "dependency kind/target"),
                ("target", "cfg(unix)", "dependency kind/target"),
                ("optional", True, "optionality drifted"),
                ("features", [], "directly enables features"),
                ("uses_default_features", False, "default-feature policy"),
                ("req", "*", "must pin"),
                ("source", "registry+https://example.invalid/index", "external dependency"),
            ):
                changed = copy.deepcopy(baseline)
                dependency(changed, "brynja-hash-parallel", target)[field] = value
                reject(changed, mode, message, "a changed ParallelHash test dependency")
                count += 1
            changed = copy.deepcopy(baseline)
            target_id = package(changed, target)["id"]
            edge = next(d for d in node(changed, "brynja-hash-parallel")["deps"] if d["pkg"] == target_id)
            edge["dep_kinds"] = [{"kind": None, "target": None}]
            reject(changed, mode, "dependency kind/target", "a test edge promoted in the resolved graph")
            count += 1
        for owner in ("brynja-hash-parallel", "brynja-hash-parallel-std"):
            for feature, value in (("default", ["runtime-execution"]), ("runtime-execution", [])):
                changed = copy.deepcopy(baseline)
                package(changed, owner)["features"][feature] = value
                reject(changed, mode, "feature policy differs", "a default-on or truncated ParallelHash route")
                count += 1
        for target in ("brynja-crypto-cpu", "brynja-crypto-cpu-std"):
            changed = copy.deepcopy(baseline)
            dependency(changed, "brynja-hash-parallel-std", target)["optional"] = False
            reject(changed, mode, "optionality drifted", "an unconditional std CPU dependency")
            count += 1
    for value in ([], ["x", "x"], [1], {}, None, ""):
        try:
            policy.feature_dependencies(value)
        except ValueError:
            continue
        raise AssertionError("malformed optional dependency group accepted")
    assert policy.feature_dependencies("cpu") == ["cpu"]
    assert policy.feature_dependencies(["cpu", "host"]) == ["cpu", "host"]
    print(f"ParallelHash workspace policy rejects {count} dependency/feature/edge and six malformed-group regressions")
