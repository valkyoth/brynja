"""Bounded linked-code review of the exact retained GHASH timing executables."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess

OBS = Path(__file__).resolve().parents[2] / "assurance/ghash-observations"
VERSIONS = ("1.90.0", "1.100.0")
# CPU screen names, objdump file format, optional decoder extensions.
CONFIG = {
    "x86": (("pclmul-amd", "pclmul-intel"), "elf64-x86-64", []),
    "arm-linux": (("pmull-aws",), "elf64-littleaarch64", ["--mattr=+aes"]),
    "arm-mac": (("pmull-apple",), "mach-o arm64", ["--mcpu=apple-m2"]),
    "rv64": (("rv64-x60",), "elf64-littleriscv", ["--mattr=+zbc"]),
}
TIME = "brynja_ghash_timing::timed"
OWNER = "brynja_universal_hash_ghash::ghash::Ghash"
UPDATE, FINISH = OWNER + "::update", OWNER + "::finish"
NOW = "std::sys::pal::unix::time::Timespec::now"
CLEAR = "brynja_core::secret_memory_volatile::zeroize_region_volatile"
PCL = "brynja_crypto_cpu::ghash_pclmul::multiply"
PMULL = "brynja_crypto_cpu::ghash_pmull::multiply"
HEADER = re.compile(r"^[0-9a-f]+ <(.*)>:$")
INSN = re.compile(r"^\s*([0-9a-f]+):\s+(\S+)(?:\s+(.*))?$")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identity(arch, ver):
    hashes = set()
    for name in CONFIG[arch][0]:
        path = OBS / ("timing-" + name)
        data = (path / "build.json").read_bytes()
        binary = json.loads(data)["builds"][ver]["binary_sha256"]
        rec = json.loads((path / (ver + ".json")).read_text())
        if rec["host"] != name.split("-")[-1] or (rec["binary_sha256"], rec["build_sha256"]) != (binary, digest(data)):
            raise ValueError("timing and build identities disagree")
        hashes.add(binary)
    if len(hashes) != 1:
        raise ValueError("distinct binaries cannot share a review")
    return hashes.pop()


def name(s):
    return re.sub(r"::h[0-9a-f]{16}$", "", s).replace("<", "").replace(">", "")


def extract(text, arch):
    if not any(line.endswith("\tfile format " + CONFIG[arch][1]) for line in text.splitlines()):
        raise ValueError("wrong disassembly format")
    lines = []
    keep = False
    for line in text.splitlines():
        if m := HEADER.fullmatch(line):
            keep = name(m[1]) in (TIME, UPDATE, PCL, PMULL)
            if keep:
                lines.append(line)
        elif keep and line.strip():
            if not INSN.fullmatch(line):
                raise ValueError("unexpected text inside function")
            lines.append(line.rstrip())
    return "\n".join(lines) + "\n"


def calls(body, target):
    out = []
    for i, (op, operands) in enumerate(body):
        if op in ("bl", "callq", "jal", "jalr") and (m := re.search(r" <(.*)>$", operands)):
            if name(m[1]) == target:
                out.append(i)
    return out


def review(arch, text):
    bodies = {}
    for line in text.splitlines():
        if m := HEADER.fullmatch(line):
            symbol = name(m[1])
            if symbol in bodies or symbol not in (TIME, UPDATE, PCL, PMULL):
                raise ValueError("ambiguous body")
            body = bodies[symbol] = []
        else:
            m = INSN.fullmatch(line)
            if not m or not bodies or m[2] == "<unknown>":
                raise ValueError("undecoded instruction")
            body.append((m[2], m[3] or ""))
    timed = bodies[TIME]
    clocks = calls(timed, NOW)
    if len(clocks) != 2:
        raise ValueError("expected two clock sites")
    window = timed[clocks[0]+1:clocks[1]]
    finish = calls(window, FINISH)
    if len(finish) != 1 or len(calls(window[finish[0]+1:], CLEAR)) != 1:
        raise ValueError("missing finish/clear before end clock")
    batch = window[:finish[0]]
    product = PCL if arch == "x86" else PMULL
    if UPDATE in bodies:
        if len(calls(batch, UPDATE)) != 16:
            raise ValueError("missing measured updates")
        if product in bodies and len(calls(bodies[UPDATE], product)) != 1:
            raise ValueError("update does not call field product")
        route = "timed -> update" + (" -> multiply" if product in bodies else "")
    else:
        if len(calls(batch, product)) != 16:
            raise ValueError("missing measured products")
        route = "timed (inlined update) -> multiply"
    kernel = bodies[product] if product in bodies else bodies[UPDATE]
    family = {"x86": {"pclmulqdq": 4}, "arm-linux": {"pmull": 3},
              "arm-mac": {"pmull.1q": 3}, "rv64": {"clmul": 3, "clmulh": 3}}[arch]
    sites = [(i, op) for i, (op, args) in enumerate(kernel) if op in family]
    if Counter(op for _, op in sites) != family:
        raise ValueError("field instruction mix mismatch")
    if arch == "arm-linux" and any(not re.fullmatch(r"v\d+\.1q, v\d+\.1d, v\d+\.1d", kernel[i][1]) for i, _ in sites):
        raise ValueError("unexpected polynomial lane width")
    # For an inlined kernel, inspect only the first-to-last field instruction
    # span. Surrounding owner admission/length/error branches are not covered.
    span = kernel if product in bodies else kernel[sites[0][0]:sites[-1][0]+1]
    if any(re.match(r"^(?:j|call|loop|b(?:\.|l$|lr$|r$|$|eq|ne|ge|lt)|[ct]bn?z)", op) for op, _ in span):
        raise ValueError("branch or call in reviewed product span")
    return dict(route=route, measured_call_sites=16, field_instructions=family,
                straight_line_scope="multiply body" if product in bodies else "first to last product instruction")


def collect(arch, bundle, dest):
    # Verify both files before disassembling either. Never execute a subject.
    for ver in VERSIONS:
        if digest((bundle / ver).read_bytes()) != identity(arch, ver):
            raise ValueError("not the executable used for timing")
    tool = subprocess.check_output(["llvm-objdump", "--version"], text=True).splitlines()[1].strip()
    dest.mkdir(parents=True, exist_ok=False)
    for ver in VERSIONS:
        dump = subprocess.check_output(["llvm-objdump", "-d", "-C", "--disassemble-zeroes", "--no-show-raw-insn", *CONFIG[arch][2],
                                        str(bundle / ver)], text=True, timeout=60)
        listing = extract(dump, arch)
        result = review(arch, listing)
        (dest / (ver + ".asm")).write_text(listing)
        (dest / (ver + ".json")).write_text(json.dumps(dict(arch=arch, compiler=ver, decoder=tool,
            binary_sha256=identity(arch, ver), listing_sha256=digest(listing.encode()), result=result), indent=2) + "\n")


def replay(arch, dest):
    for ver in VERSIONS:
        listing = (dest / (ver + ".asm")).read_bytes()
        rec = json.loads((dest / (ver + ".json")).read_text())
        if (rec["arch"] != arch or rec["compiler"] != ver or rec["binary_sha256"] != identity(arch, ver)
                or rec["listing_sha256"] != digest(listing) or rec["result"] != review(arch, listing.decode())):
            raise ValueError("inconsistent linked review")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("arch", choices=CONFIG)
    parser.add_argument("directory", type=Path, help="saved review (must be new when collecting)")
    parser.add_argument("--bundle", type=Path, help="collect from these exact timing binaries; otherwise replay")
    args = parser.parse_args()
    if args.bundle:
        collect(args.arch, args.bundle, args.directory)
    replay(args.arch, args.directory)
    print("GHASH linked review:", args.arch, "both compiler endpoints passed")
