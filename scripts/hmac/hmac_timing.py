"""Strict population and paired timing screen; never a constant-time proof."""
import math
import statistics

WIDTHS = dict(zip(
    ("sha224", "sha256", "sha384", "sha512", "sha512_224", "sha512_256",
     "sha3_224", "sha3_256", "sha3_384", "sha3_512", "general129", "general511"),
    (28, 32, 48, 64, 28, 32, 28, 32, 48, 64, 16, 63), strict=True))
SAMPLES = 512
ROUTES = ("portable", "static", "runtime", "linux-protected", "linux-compiled", "macos-resident", "macos-compiled")
FAMILIES = ("all", "sha256", "sha512", "keccak")
COMPILED = ("static", "linux-compiled", "macos-compiled")
ACCELERATED = (*COMPILED, "runtime")
# A coarse diagnostic alarm, not a release security threshold or a waiver.
LIMIT = 10.0


def population(route="portable", family="all"):
    if route not in ROUTES or family not in FAMILIES or (route in ACCELERATED and family == "all"):
        raise ValueError("invalid timing route/family")
    return {name: width for name, width in WIDTHS.items() if family == "all" or
            (family == "sha256" and name in ("sha224", "sha256")) or
            (family == "keccak" and name.startswith("sha3_")) or
            (family == "sha512" and name not in ("sha224", "sha256") and not name.startswith("sha3_"))}


def marker(route="portable", family="all"):
    count = len(population(route, family))
    return f"HMAC_TIMING_COMPLETE {count} {count * 8} 512 4 {route} {family}"


MARKER = marker()


def screen(pairs):
    if len(pairs) != SAMPLES or any(type(n) is not int or n <= 0 for row in pairs for n in row):
        raise ValueError("invalid timing sample population/value")
    differences = [left - right for left, right in pairs]
    mean = statistics.mean(differences)
    variance = statistics.variance(differences)
    # A constant nonzero difference is a signal, never a divide-by-zero pass.
    score = abs(mean) / math.sqrt(variance / SAMPLES) if variance else (0.0 if mean == 0 else math.inf)
    return {"class0_mean_ns": statistics.mean(left for left, _ in pairs),
            "class1_mean_ns": statistics.mean(right for _, right in pairs),
            "paired_t_abs": score if math.isfinite(score) else None,
            "signal": score >= LIMIT}


def parse(text, route="portable", family="all"):
    expected_marker = marker(route, family)
    lines = text.splitlines()
    if not lines or lines[-1] != expected_marker or lines.count(expected_marker) != 1:
        raise ValueError("missing/duplicate timing completion marker")
    cursor = 0
    results = []
    # Ordered occurrences matter: general129's 16-byte profiles intentionally
    # repeat, giving a second campaign rather than silently deduplicating it.
    for identity, width in population(route, family).items():
        for tag_bytes in (16, width):
            for key_bytes in (32, 200):
                for mode in ("verify", "key"):
                    pairs = []
                    for sample in range(SAMPLES):
                        if cursor >= len(lines) - 1:
                            raise ValueError("truncated timing campaign")
                        fields = lines[cursor].split()
                        expected = ["SAMPLE", identity, mode, str(key_bytes), str(tag_bytes), str(sample)]
                        if len(fields) != 8 or fields[:6] != expected:
                            raise ValueError("timing identity/order/population changed")
                        pairs.append(tuple(int(n) for n in fields[6:]))
                        cursor += 1
                    results.append({"identity": identity, "mode": mode,
                                    "key_bytes": key_bytes, "tag_bytes": tag_bytes, **screen(pairs)})
    if cursor != len(lines) - 1:
        raise ValueError("unexpected extra timing output")
    return results
