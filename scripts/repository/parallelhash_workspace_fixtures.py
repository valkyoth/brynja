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
        for feature, value in (("strict-execution", []), ("default", ["strict-execution"]),
                               ("strict-execution", ["runtime-execution"])):
            changed = copy.deepcopy(baseline)
            package(changed, "brynja-hash-parallel-std")["features"][feature] = value
            reject(changed, mode, "feature policy differs", "a weakened protected ParallelHash feature")
            count += 1
        changed = copy.deepcopy(baseline)
        dependency(changed, "brynja-hash-parallel-std", "brynja-crypto-cpu-std")["features"] = ["runtime-execution"]
        reject(changed, mode, "directly enables features", "strict scalar enabling runtime authority")
        count += 1
    for value in ([], ["x", "x"], [1], {}, None, ""):
        try:
            policy.feature_dependencies(value)
        except ValueError:
            continue
        raise AssertionError("malformed optional dependency group accepted")
    assert policy.feature_dependencies("cpu") == ["cpu"]
    assert policy.feature_dependencies(["cpu", "host"]) == ["cpu", "host"]
    primitives = ["brynja-core", "brynja-cipher-aes", "brynja-universal-hash-ghash"]
    for owner, pairs in (
        ("brynja-aead-gcm", [("aes-gcm", "gmac", primitives),
                             ("aes-gcm-execution", "gmac-execution", "brynja-crypto-cpu")]),
        ("brynja-crypto", [("aes-gcm", "gmac", "brynja-aead-gcm")]),
    ):
        edges = {feature: deps for first, second, deps in pairs for feature in (first, second)}
        expected = [name for _, _, deps in pairs for name in policy.feature_dependencies(deps)]
        assert policy.reviewed_optional_names(owner, {"optional": edges}) == expected
        for feature in edges:
            for bad in ({k: v for k, v in edges.items() if k != feature}, {**edges, feature: "other"}):
                try:
                    policy.reviewed_optional_names(owner, {"optional": bad})
                except ValueError:
                    continue
                raise AssertionError(f"{owner} accepted missing or redirected {feature}")
        # Unreviewed aliases must still reach the duplicate check in load_policy.
        extra = policy.reviewed_optional_names(owner, {"optional": {**edges, "other": expected[0]}})
        assert extra.count(expected[0]) == 2
    mapping = dict.fromkeys(("chacha20-sse2", "chacha20-neon"), "brynja-crypto-cpu")
    assert policy.unique_chacha_cpu_dependency({"optional": mapping}) == ["brynja-crypto-cpu"]
    for feature in mapping:
        for bad in ({k: v for k, v in mapping.items() if k != feature}, {**mapping, feature: "brynja-core"}):
            try:
                policy.unique_chacha_cpu_dependency({"optional": bad})
            except ValueError:
                continue
            raise AssertionError("missing or redirected ChaCha20 CPU edge accepted")
    edges = dict.fromkeys(("poly1305-avx2", "poly1305-neon"), "brynja-crypto-cpu")
    assert policy.reviewed_optional_names("brynja-mac-poly1305", {"optional": edges}) == ["brynja-crypto-cpu"]
    for feature in edges:
        for bad in ({k: v for k, v in edges.items() if k != feature},
                    {**edges, feature: "brynja-core"}, {**edges, "extra": "brynja-crypto-cpu"}):
            try:
                policy.reviewed_optional_names("brynja-mac-poly1305", {"optional": bad})
            except ValueError:
                continue
            raise AssertionError("unreviewed Poly1305 CPU edge accepted")
    print(f"ParallelHash workspace policy rejects {count} dependency/feature/edge and six malformed-group regressions")
