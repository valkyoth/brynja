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
    if group == 'sha3':
        # Each identity retains its own rate-1/rate/rate+1 transitions. Testing
        # every other identity's rate as well remains extended/native work.
        boundaries = [0, 1, 71, 72, 73, 103, 104, 105, 135, 136, 137,
                      143, 144, 145, 167, 168, 169, 339]
        sample = [identity * len(boundaries) + boundaries.index(length)
                  for identity, rate in enumerate((144, 136, 104, 72))
                  for length in (0, 1, rate - 1, rate, rate + 1, 339)]
        return [dict(name=name, marker=marker, total=total, routine=indices,
                     package='brynja-hash-sha3', features=[], target=['--test', 'hardened'])
                for name, marker, total, indices in (
                    ('every_rate_and_multiblock_boundary_matches', 'sha3-fixed-boundaries', 72, sample),
                    ('every_partial_bit_width_matches_every_fixed_identity', 'sha3-fixed-bits', 28, list(range(28))),
                    ('every_partial_secret_xof_width_matches_and_clears', 'sha3-secret-xof-bits', 7, list(range(7))))]
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
                 'package': 'brynja-mac-kmac', 'features': []},
                {'name': 'hardened_in_place::tests::scoped_lifecycle_strength_and_verification_failures',
                 'marker': 'kmac-scoped-lifecycle', 'total': 18, 'routine': list(range(18)),
                 'package': 'brynja-mac-kmac', 'features': []},
                {'name': 'hardened_in_place::xof::tests::scoped_xof_lifecycle_shapes_and_large_public_reads',
                 'marker': 'kmac-scoped-xof-lifecycle', 'total': 16, 'routine': list(range(16)),
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
    result.append({'name': 'backend::tests::scoped_leaf_matches_shake_for_every_tail_and_rate_boundary',
                   'marker': 'parallelhash-leaf', 'total': 65,
                   'routine': [0, *(1 + length * 8 + length for length in range(8))],
                   'package': 'brynja-hash-parallel', 'features': []})
    return result


def singles(group: str) -> list[str]:
    if group != 'sha3':
        return []
    # Keep the empty-owner test (and any future tests) in the original broad
    # invocation. Each moved test remains selected exactly once, independently
    # resumable, without changing its input sizes or assertions.
    return [
        'every_fixed_identity_matches_the_ordinary_algorithm',
        'every_fixed_secret_output_transfers_and_clears',
        'fixed_output_failure_is_atomic_by_classification',
        'both_xofs_match_across_irregular_absorb_and_squeeze_boundaries',
        'xof_secret_fragments_transfer_and_clear_independently',
        'bit_input_and_bit_output_match_both_ordinary_xofs',
        'sealed_capabilities_accept_only_registered_public_types',
        'cancel_and_early_drop_cover_absorber_and_reader_lifecycles',
        'recoverable_unwind_clears_typed_secret_destination',
    ]


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
            for name in [case['name'] for case in registered] + singles(group):
                argv.extend(["--skip", name])
        result.append({"argv": argv, "environment": {}, "marker": None})
    for matrix in registered:
        indices = matrix["routine"] if profile == "routine" else range(matrix["total"])
        for index in indices:
            features = matrix.get('features', ['hardened-execution'])
            argv = ['-p', matrix['package']]
            if features:
                argv += ['--features', ','.join(features)]
            result.append({"argv": [*argv, *matrix.get('target', ['--lib']), matrix["name"], "--", "--exact"],
                           "environment": {"BRYNJA_MIRI_CASE": str(index), "BRYNJA_MIRI_PROFILE": profile},
                           "marker": f"MIRI_CASE_PASS: {matrix['marker']}:{index}"})
    for name in singles(group):
        result.append({'argv': ['-p', 'brynja-hash-sha3', '--test', 'hardened', name, '--', '--exact'],
                       'environment': {}, 'marker': None})
    return result
