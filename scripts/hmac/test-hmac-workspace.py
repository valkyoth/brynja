#!/usr/bin/env python3
"""Only exact general-hash and opt-in hardened-execution edges are admitted."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts/repository/validate-workspace-metadata.py"


def validate(document, mode, valid, diagnostic="directly enables features on brynja-hash-sha2"):
    with tempfile.TemporaryDirectory(prefix="brynja-hmac-graph-") as directory:
        path = Path(directory) / "metadata.json"
        path.write_text(json.dumps(document))
        result = subprocess.run(["python3", str(VALIDATOR), "--mode", mode, str(path)],
                                cwd=ROOT, text=True, capture_output=True, timeout=30)
        if valid:
            if result.returncode:
                raise ValueError(result.stderr)
        elif (not result.returncode
              or diagnostic not in result.stderr):
            raise ValueError("HMAC feature mutation escaped its exact feature check")


def main():
    for mode in ("no-default-features", "all-features"):
        document = json.loads(subprocess.check_output(
            ["cargo", "metadata", "--format-version", "1", "--locked", "--offline", "--" + mode],
            cwd=ROOT, text=True, timeout=30))
        validate(document, mode, True)
        for features in ([], ["cpu"], ["conformance-testing"],
                         ["general-sha512-t", "hardened-execution"]):
            changed = copy.deepcopy(document)
            package = next(p for p in changed["packages"] if p["name"] == "brynja-mac-hmac")
            edge = next(d for d in package["dependencies"] if d["name"] == "brynja-hash-sha2")
            edge["features"] = features
            validate(changed, mode, False)
        package = next(p for p in document["packages"] if p["name"] == "brynja-mac-hmac")
        edges = package["features"]["hardened-execution"]
        for index in range(len(edges)):
            changed = copy.deepcopy(document)
            candidate = next(p for p in changed["packages"] if p["name"] == "brynja-mac-hmac")
            candidate["features"]["hardened-execution"] = edges[:index] + edges[index + 1:]
            validate(changed, mode, False, "feature policy differs")
        changed = copy.deepcopy(document)
        candidate = next(p for p in changed["packages"] if p["name"] == "brynja-mac-hmac")
        candidate["features"]["default"] = ["hardened-execution"]
        validate(changed, mode, False, "feature policy differs")
        for name, feature in (("brynja-mac-hmac", "runtime-execution"),
                              ("brynja-crypto-cpu-std", "hmac-execution"),
                              ("brynja-crypto-cpu-std", "strict-hmac")):
            edges = next(p for p in document["packages"] if p["name"] == name)["features"][feature]
            for index in range(len(edges)):
                changed = copy.deepcopy(document)
                candidate = next(p for p in changed["packages"] if p["name"] == name)
                candidate["features"][feature] = edges[:index] + edges[index + 1:]
                validate(changed, mode, False, "feature policy differs")
        changed = copy.deepcopy(document)
        candidate = next(p for p in changed["packages"] if p["name"] == "brynja-crypto-cpu-std")
        candidate["features"]["default"] = ["hmac-execution"]
        validate(changed, mode, False, "feature policy differs")
    print("HMAC workspace feature closure: 2 baselines and 38 rejected mutations PASS")


if __name__ == "__main__":
    main()
