"""Bind compiler profiles to the resolved feature graph, not a CLI label."""
import json

from hmac_engine_codegen import require

OWNERS = ("brynja-mac-hmac", "brynja-hash-sha2", "brynja-hash-sha3", "brynja-crypto-cpu")


def graph(document, profile):
    require(profile in ("runtime", "static"), "unknown execution feature profile")
    packages = document["packages"]
    nodes = document["resolve"]["nodes"]
    require(len({row["id"] for row in packages}) == len(packages)
            and len({row["id"] for row in nodes}) == len(nodes), "duplicate execution graph identity")
    for name in (*OWNERS, "brynja-hmac-execution-cleanup"):
        rows = [row for row in packages if row["name"] == name]
        require(len(rows) == 1 and rows[0]["source"] is None,
                "missing/nonlocal execution graph owner: " + name)
        enabled = [row["features"] for row in nodes if row["id"] == rows[0]["id"]]
        require(len(enabled) == 1, "missing execution feature node: " + name)
        features = set(enabled[0])
        require(("runtime-execution" in features) == (profile == "runtime"),
                "execution feature profile contaminated: " + name)
        if name in OWNERS:
            require("hardened-execution" in features, "missing hardened owner feature: " + name)
    if profile == "static":
        require(all("runtime-execution" not in row["features"] for row in nodes),
                "unexpected runtime dependency in static feature graph")


def validate(verifier, fixture, directory, compiler, target, profile):
    features = [] if profile == "runtime" else ["--no-default-features"]
    raw = verifier.run(["cargo", "+" + compiler, "metadata", "--manifest-path", str(fixture),
                        "--locked", "--offline", "--format-version", "1",
                        "--filter-platform", target, *features], verifier.environment(directory))
    graph(json.loads(raw), profile)
