"""Exact legacy timing population and coarse paired screen; not a CT proof."""
import math
import statistics

ROUTES = ("portable", "static", "linux-protected", "linux-compiled",
          "macos-resident", "macos-compiled")
COMPILED = ("static", "linux-compiled", "macos-compiled")
WIDTHS = {"sha1": 20, "md5": 16}
SAMPLES = 512
REPEAT = 4
LIMIT = 10.0


def lanes(route, family, arch):
    if route not in ROUTES or family not in WIDTHS or arch not in ("x86_64", "aarch64"):
        raise ValueError("invalid timing route/family/architecture")
    if route.startswith("macos-") and arch != "aarch64":
        raise ValueError("resident timing requires Apple Silicon")
    return (8 if arch == "x86_64" else 4) if family == "md5" and route in COMPILED else 1


def marker(route, family, arch):
    return f"LEGACY_HMAC_TIMING_COMPLETE {route} {family} {lanes(route, family, arch)} 8 {SAMPLES} {REPEAT}"


def screen(pairs):
    if (len(pairs) != SAMPLES or any(len(row) != 2 for row in pairs)
            or any(type(n) is not int or not 0 < n < 2**64 for row in pairs for n in row)):
        raise ValueError("invalid timing sample population/value")
    differences = [a - b for a, b in pairs]
    mean, variance = statistics.mean(differences), statistics.variance(differences)
    score = abs(mean) / math.sqrt(variance / SAMPLES) if variance else (0.0 if mean == 0 else math.inf)
    return {"class0_mean_ns": statistics.mean(a for a, _ in pairs),
            "class1_mean_ns": statistics.mean(b for _, b in pairs),
            "paired_t_abs": score if math.isfinite(score) else None,
            "signal": score >= LIMIT}


def parse(text, route, family, arch):
    end = marker(route, family, arch)
    lines = text.splitlines()
    if not lines or lines[-1] != end or lines.count(end) != 1:
        raise ValueError("missing/duplicate/wrong timing completion marker")
    cursor, rows = 0, []
    for tag_bytes in (10, WIDTHS[family]):
        for key_bytes in (32, 200):
            for mode in ("verify", "key"):
                pairs = []
                for sample in range(SAMPLES):
                    if cursor >= len(lines) - 1:
                        raise ValueError("truncated timing campaign")
                    fields = lines[cursor].split()
                    expected = ["SAMPLE", family, mode, str(key_bytes), str(tag_bytes), str(sample)]
                    if len(fields) != 8 or fields[:6] != expected:
                        raise ValueError("timing identity/order/population changed")
                    if any(not n.isascii() or not n.isdecimal() for n in fields[6:]):
                        raise ValueError("invalid timing value encoding")
                    pairs.append(tuple(int(n) for n in fields[6:]))
                    cursor += 1
                rows.append({"family": family, "mode": mode, "key_bytes": key_bytes,
                             "tag_bytes": tag_bytes, **screen(pairs)})
    if cursor != len(lines) - 1:
        raise ValueError("unexpected extra timing output")
    return rows
