"""Offline GCMVS replay. Only the checksum-pinned NIST archive is admitted."""
from collections import Counter
import hashlib
import io
from itertools import product
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
ARCHIVE = ROOT / "references/local/gcmtestvectors.zip"
SHA256 = "f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023"
SIZE = 9154174
NAMES = {f"gcm{mode}{bits}.rsp": (mode, bits)
         for mode in ("EncryptExtIV", "Decrypt") for bits in (128, 192, 256)}
GRID = set(product((8, 96, 1024), (0, 104, 128, 256, 408), (0, 128, 160, 384, 720),
                   (32, 64, 96, 104, 112, 120, 128)))


def rows(data, mode, bits):
    blocks = re.split(r"\n\s*\n", data.decode("ascii").replace("\r\n", "\n").strip())
    if len(blocks) != 1 + len(GRID) * 16:
        raise ValueError("incomplete response file")
    seen = set()
    for offset in range(1, len(blocks), 16):
        heading = blocks[offset].splitlines()
        fields = re.fullmatch(r"\[Keylen = (\d+)\]\n\[IVlen = (\d+)\]\n\[PTlen = (\d+)\]\n"
                              r"\[AADlen = (\d+)\]\n\[Taglen = (\d+)\]", "\n".join(heading))
        if not fields:
            raise ValueError("invalid parameter heading")
        key, *params = map(int, fields.groups())
        grid = tuple(params)
        if key != bits or grid not in GRID or grid in seen:
            raise ValueError("wrong or duplicate parameter group")
        seen.add(grid)
        iv, pt, aad, tag = grid
        for count, block in enumerate(blocks[offset + 1:offset + 16]):
            lines = block.splitlines()
            fail = lines[-1] == "FAIL"
            if lines[0] != f"Count = {count}" or (fail and mode != "Decrypt"):
                raise ValueError("invalid case identity or outcome")
            lengths = {"Key": key, "IV": iv, "AAD": aad, "CT": pt, "Tag": tag}
            if not fail:
                lengths["PT"] = pt
            record = {}
            for line in lines[1:-1] if fail else lines[1:]:
                name, delim, value = line.partition(" = ")
                if (not delim or name not in lengths or name in record
                        or len(value) * 4 != lengths[name] or not re.fullmatch("[a-f0-9]*", value)):
                    raise ValueError("invalid vector field")
                record[name] = value
            if record.keys() != lengths.keys():
                raise ValueError("missing vector field")
            kind = "excluded" if tag in (32, 64) else (
                "reject" if fail else "seal" if mode == "EncryptExtIV" else "open")
            yield kind, "\t".join([kind, *(record.get(k, "") for k in ("Key", "IV", "AAD", "CT", "PT", "Tag"))])


def corpus(path):
    with path.open("rb") as fp:
        raw = fp.read(SIZE + 1)
    if len(raw) != SIZE or hashlib.sha256(raw).hexdigest() != SHA256:
        raise ValueError("wrong GCMVS ZIP; consult the AES-GCM development checklist")
    cases, counts = [], Counter()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if sorted(archive.namelist()) != sorted(NAMES):
            raise ValueError("unexpected GCMVS members")
        for name, (mode, bits) in NAMES.items():
            for kind, row in rows(archive.read(name), mode, bits):
                counts[kind] += 1
                if kind != "excluded":
                    cases.append(row)
    if counts != {"seal": 16875, "open": 8371, "reject": 8504, "excluded": 13500}:
        raise ValueError("unexpected GCMVS inventory")
    return "\n".join(cases) + "\n"


def main():
    if not ARCHIVE.is_file():
        raise SystemExit("Missing references/local/gcmtestvectors.zip; see docs/assurance/aes-gcm-development.md")
    data = corpus(ARCHIVE)
    with tempfile.TemporaryDirectory(prefix="gcmvs-target-") as target:
        for version in ("1.90.0", "1.100.0"):
            command = ["cargo", "+" + version, "run", "--locked", "--offline", "--release",
                       "--manifest-path", "assurance/aes-gcm-consumer/Cargo.toml", "--no-default-features",
                       "--features", "direct", "--example", "gcmvs", "--target-dir", target]
            run = subprocess.run(command, cwd=ROOT, input=data, capture_output=True, text=True, timeout=240)
            expected = "seal=16875 open=8371 reject=8504"
            if run.returncode or run.stdout.strip() != expected:
                raise RuntimeError("GCMVS replay incomplete: " + run.stderr[-2000:])
            # A replay which only counted cases could otherwise appear green.
            # Mislabel one genuine authentication failure as a successful open,
            # and change one expected seal tag. Neither may reach the summary.
            first_seal = data.split("\n", 1)[0]
            wrong_tag = first_seal[:-1] + ("0" if first_seal[-1] != "0" else "1")
            wrong_open = next(s for s in data.splitlines() if s.startswith("reject\t")).replace("reject", "open", 1)
            for control in (wrong_tag, wrong_open):
                bad = subprocess.run(command, cwd=ROOT, input=control + "\n", capture_output=True,
                                     text=True, timeout=60)
                if not bad.returncode or bad.stdout or "case 1: wrong result" not in bad.stderr:
                    raise ValueError("GCMVS consumer did not reject an incorrect expected result")
            print(f"{version}: {expected}; excluded short tags=13500", flush=True)
    print("AES_GCM_GCMVS_COMPLETE")


if __name__ == "__main__":
    main()
