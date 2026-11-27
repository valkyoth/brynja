"""Exact first-party test edges and multi-dependency opt-in feature policy."""
from __future__ import annotations


def feature_dependencies(value):
    values = value if isinstance(value, list) else [value]
    if not values or any(not isinstance(name, str) or not name for name in values):
        raise ValueError("malformed optional dependency group")
    if len(values) != len(set(values)):
        raise ValueError("repeated optional dependency group member")
    return values


def optional_names(entry):
    return [name for value in entry["optional"].values()
            for name in feature_dependencies(value)]


def unique_chacha_cpu_dependency(entry):
    if entry["optional"] != {feature: "brynja-crypto-cpu" for feature in ("chacha20-sse2", "chacha20-neon")}:
        raise ValueError("both ChaCha20 SIMD features must select the CPU crate")
    return ["brynja-crypto-cpu"]


def dev_names(name, entry):
    expected = (["brynja-crypto-cpu", "brynja-crypto-cpu-std"]
                if name == "brynja-hash-parallel" else [])
    if entry.get("dev", []) != expected:
        raise ValueError("unreviewed development dependency policy")
    return expected


def direct_features(owner, dependency):
    if owner in {"brynja-hash-parallel", "brynja-hash-parallel-std"}:
        if dependency == "brynja-crypto-cpu":
            return ["hardened-execution"]
        if dependency == "brynja-crypto-cpu-std":
            return ["runtime-execution"] if owner == "brynja-hash-parallel" else []
    return None


def cpu_target(owner, dependency):
    return 'cfg(any(target_arch = "x86_64", target_arch = "aarch64"))' if (owner, dependency) == ("brynja-cipher-chacha", "brynja-crypto-cpu") else None


def production_edges(document, packages, names, policy):
    """Validate Cargo's edge kinds before excluding test-only edges from reachability."""
    nodes = {node["id"]: node for node in document["resolve"]["nodes"]}
    result = {identity: {dep["pkg"] for dep in node["deps"]}
              for identity, node in nodes.items()}
    for owner, package in packages.items():
        expected = {names[name]: "dev" for name in dev_names(owner, policy[owner])}
        for dep in nodes[package["id"]]["deps"]:
            kind = expected.get(dep["pkg"])
            target = cpu_target(owner, "brynja-crypto-cpu" if dep["pkg"] == names.get("brynja-crypto-cpu") else None)
            if dep.get("dep_kinds") != [{"kind": kind, "target": target}]:
                raise ValueError(f"{owner} resolved dependency kind/target drifted")
            if kind == "dev":
                result[package["id"]].remove(dep["pkg"])
    return result
