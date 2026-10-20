#!/usr/bin/env python3
"""Only the exact HMAC general-hash feature edge is admitted."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts/repository/validate-workspace-metadata.py"


def validate(document, mode, valid):
    with tempfile.TemporaryDirectory(prefix="brynja-hmac-graph-") as directory:
        path = Path(directory) / "metadata.json"
        path.write_text(json.dumps(document))
        result = subprocess.run(["python3", str(VALIDATOR), "--mode", mode, str(path)],
                                cwd=ROOT, text=True, capture_output=True, timeout=30)
        if valid:
            if result.returncode:
                raise ValueError(result.stderr)
        elif (not result.returncode
              or "directly enables features on brynja-hash-sha2" not in result.stderr):
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
    print("HMAC workspace feature closure: 2 baselines and 8 rejected mutations PASS")


if __name__ == "__main__":
    main()
