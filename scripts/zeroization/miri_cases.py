"""Reviewed decomposition of costly legacy hash, KMAC and SP 800-185 matrices.

Routine cases are boundary/lifecycle sampling, not exhaustive crypto evidence.
Extended tasks address every original combination, one case/chunk per invocation.
The native Rust tests retain their complete matrices in both profiles.
"""
from __future__ import annotations

PROFILES = ("existing-full", "routine", "extended")
TUPLE = "execution::core_state::tests::borrowed_staging_matches_independently_packed_cshake"


def profile_for(stage: str, requested: str | None = None) -> str:
    if stage not in {"internal", "public"}:
        raise ValueError("unknown release stage for Miri")
    selected = requested or ("extended" if stage == "public" else "routine")
    if selected not in PROFILES or (stage == "public" and selected == "routine"):
        raise ValueError("Miri profile cannot satisfy this release stage")
    return selected


def matrices(group: str) -> list[dict]:
    if group in ('sha1', 'md5'):
        package = 'brynja-legacy-' + group
        return [
            {'name': 'engine::tests::every_valid_offset_survives_absorption_and_padding',
             'marker': group + '-padding', 'total': 129,
             'routine': [0, 1, 54, 55, 56, 57, 62, 63, 64, 65, 119, 120, 127, 128],
             'package': package, 'features': []},
            {'name': 'engine::tests::borrowed_bulk_updates_match_single_bytes_at_every_boundary',
             'marker': group + '-bulk', 'total': 258,
             'routine': [0, 1, 2, 7, 31, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129,
                         191, 192, 193, 255, 256, 257], 'package': package, 'features': []},
            {'name': f'hardened_in_place::tests::scoped_{group}_streaming_bits_reuse_and_output_lifetime',
             'marker': group + '-scoped', 'total': 288,
             'routine': [(size * 3 + size % 3) * 8 + size % 8 for size in range(12)],
             'package': package, 'features': []},
        ]
    if group == 'kmac':
        return [{'name': 'packer::framing_tests::borrowed_fragments_match_bit_oracle_at_every_alignment',
                 'marker': 'kmac-framing', 'total': 8, 'routine': list(range(8)),
                 'package': 'brynja-mac-kmac', 'features': []}]
    if group == "tuplehash":
        # Both strengths, every initial residue and final width, all seven
        # staging lengths, without the full Cartesian product.
        routine = [((wide * 8 + used) * 8 + used) * 7 + used % 7
                   for wide in range(2) for used in range(8)]
        return [{"name": TUPLE, "marker": "tuplehash-staging", "total": 896,
                 "routine": routine, "package": "brynja-hash-tuple"}]
    if group != "parallelhash":
        return []
    result = []
    # Each routine row covers all bit widths and every registered B. B=1
    # receives only 2*B+1 input bytes; larger B retains rate-crossing messages.
    for module, prefix, blocks in (
        ("tests", "scoped_parallel", 6),
        ("xof::tests", "scoped_parallel_xof", 5),
        ("scheduled::tests", "scoped_scheduled", 4),
    ):
        for strength in (128, 256):
            name = f"{prefix}{strength}_matches" + ("" if prefix == "scoped_scheduled" else "_and_clears")
            result.append({"name": f"hardened_in_place::{module}::{name}", "marker": name,
                           "total": blocks * 8, "routine": [(bit % blocks) * 8 + bit for bit in range(8)],
                           "package": "brynja-hash-parallel"})
    return result


def tasks(group: str, original: list[list[str]], profile: str) -> list[dict]:
    if profile not in PROFILES:
        raise ValueError("unknown Miri coverage profile")
    if profile == "existing-full":
        return [{"argv": argv, "environment": {}, "marker": None} for argv in original]
    registered = matrices(group)
    result = []
    for argv in original:
        argv = list(argv)
        if registered:
            if "--" not in argv:
                argv.append("--")
            for case in registered:
                argv.extend(["--skip", case["name"]])
        result.append({"argv": argv, "environment": {}, "marker": None})
    for matrix in registered:
        indices = matrix["routine"] if profile == "routine" else range(matrix["total"])
        for index in indices:
            features = matrix.get('features', ['hardened-execution'])
            argv = ['-p', matrix['package']]
            if features:
                argv += ['--features', ','.join(features)]
            result.append({"argv": [*argv, "--lib", matrix["name"], "--", "--exact"],
                           "environment": {"BRYNJA_MIRI_CASE": str(index), "BRYNJA_MIRI_PROFILE": profile},
                           "marker": f"MIRI_CASE_PASS: {matrix['marker']}:{index}"})
    return result
