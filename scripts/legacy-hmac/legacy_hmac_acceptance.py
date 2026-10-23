"""Legacy HMAC source-only footprint and resolved normal-edge isolation."""
from pathlib import Path, PurePosixPath

NAMES = ("brynja-core", "brynja-hash-core", "brynja-legacy-sha1",
         "brynja-legacy-md5", "brynja-legacy-hmac")
REQUIRED = frozenset({"Cargo.toml", "Cargo.toml.orig", "LICENSE-APACHE", "LICENSE-MIT", "README.md",
                      "src/lib.rs", "src/algorithms.rs", "src/engine.rs", "src/output.rs", "src/scratch.rs",
                      "src/execution/mod.rs", "src/execution/adapter.rs", "src/execution/retained.rs",
                      "src/md5_batch/mod.rs", "src/md5_batch/engine.rs", "src/md5_batch/output.rs"})
OPTIONAL = frozenset({"Cargo.lock", ".cargo_vcs_info.json"})


def require(condition, message):
    if not condition:
        raise ValueError("legacy HMAC acceptance: " + message)


def members(names):
    names = list(names)
    require(len(names) == len(set(names)), "duplicate archive member")
    for name in names:
        path = PurePosixPath(name)
        require(str(path) == name and not path.is_absolute() and ".." not in path.parts
                and "\\" not in name, "noncanonical archive member")
    require(REQUIRED <= set(names) <= REQUIRED | OPTIONAL, "runtime-only archive population")


def packaged_graph(graph, roots, consumer):
    packages = graph["packages"]
    expected = set(NAMES) | {"legacy-hmac-external"}
    require(len(packages) == len(expected) and {p["name"] for p in packages} == expected,
            "unexpected extracted dependency closure")
    for package in packages:
        path = consumer if package["name"] == "legacy-hmac-external" else roots[package["name"]]
        require(package["source"] is None and
                Path(package["manifest_path"]).resolve() == path.resolve() / "Cargo.toml",
                "dependency escaped extracted archives")


def isolation(graph):
    packages = {p["id"]: p for p in graph["packages"]}
    require(len(packages) == len(graph["packages"]), "duplicate package identity")
    nodes = {n["id"]: n for n in graph["resolve"]["nodes"]}
    require(set(nodes) == set(packages), "missing resolved nodes")
    legacy = [p["id"] for p in packages.values() if p["name"] == "brynja-legacy-hmac"]
    require(len(legacy) == 1, "missing/ambiguous legacy HMAC identity")

    def reachable(start):
        visited, pending = set(), [start]
        while pending:
            identity = pending.pop()
            if identity in visited:
                continue
            require(identity in nodes, "unresolved dependency")
            visited.add(identity)
            for dep in nodes[identity]["deps"]:
                require(bool(dep["dep_kinds"]), "missing dependency kind")
                require(all(k["kind"] in (None, "build", "dev") for k in dep["dep_kinds"]),
                        "unknown dependency kind")
                # Include every target's normal/build edge; exclude only dev-only edges.
                if any(k["kind"] != "dev" for k in dep["dep_kinds"]):
                    pending.append(dep["pkg"])
        return visited

    closure = reachable(legacy[0])
    require({packages[p]["name"] for p in closure} == set(NAMES) and len(closure) == len(NAMES),
            "legacy implementation dependency closure changed")
    for identity in graph["workspace_members"]:
        name = packages[identity]["name"]
        if not name.startswith("brynja-legacy"):
            require(legacy[0] not in reachable(identity), "legacy HMAC reached modern/workspace consumer: " + name)
