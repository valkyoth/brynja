"""Current facade archive closure; historical hash acceptance stays untouched."""
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[2]
HMAC = ("brynja-mac-hmac", "0.1.0", ("src/lib.rs",))


def specifications(packaging):
    declared = packaging.PACKAGING_PACKAGES
    if HMAC[0] not in {name for name, *_ in declared}:
        declared = (*declared, HMAC)
    if len({name for name, *_ in declared}) != len(declared):
        raise ValueError("duplicate facade archive identity")
    result = []
    for name, _old_version, required in declared:
        package = tomllib.loads((ROOT / "crates" / name / "Cargo.toml").read_text())["package"]
        if package["name"] != name:
            raise ValueError("facade archive manifest identity changed")
        result.append((name, package["version"], required))
    return tuple(result)
