#!/usr/bin/env python3
"""Validate a PARTIAL emitted-site candidate map; never qualify AES faults.

This is bookkeeping over pinned development observations, not a debugger run,
fault-injection receipt, production build identity, or admission decision.
"""
import hashlib
import importlib.util
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
MAP = "assurance/aes-fault-emitted-site-candidates.json"
SPEC = importlib.util.spec_from_file_location(
    "fault_source_inventory", Path(__file__).with_name("check-aes-fault-sites.py"))
SOURCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOURCE)
WIDTHS = [16, 24, 32]
PATHS = ["public", "encrypt", "decrypt"]
REPLICAS = ("primary", "complemented")


def require(condition):
    if not condition:
        raise ValueError("invalid partial emitted-site map")


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()))


def labels(artifact):
    """Stable context labels; repeated loop hits are not separate code sites."""
    for width in WIDTHS:
        for path in PATHS:
            for replica in REPLICAS:
                base = (f'{artifact["binary_sha256"][:16]}/local-key-copy/'
                        f'aes{width * 8}/{path}/{replica}')
                yield base + "/call"
                for byte_offset in artifact["word_offsets_by_width"][str(width)]:
                    yield base + f"/word{byte_offset}/load"
                    yield base + f"/word{byte_offset}/store"


def capture_labels(artifact, family):
    """Import/use capture contexts; word-copy offsets are not runtime coverage."""
    for width in WIDTHS:
        for owner in ("cached", "operation-local"):
            for path in PATHS:
                for replica in ("primary", "complemented"):
                    base = (f'{artifact["binary_sha256"][:16]}/{family["family"]}/'
                            f'aes{width * 8}/{owner}/{path}/{replica}')
                    yield base + "/capture-call"
                    yield base + "/copy-return"


def retained_labels(artifact):
    """Pre/post validation call contexts, not internal comparison sites."""
    for width in WIDTHS:
        for owner in ("cached", "operation-local"):
            for path in PATHS:
                base = (f'{artifact["binary_sha256"][:16]}/retained-key/'
                        f'aes{width * 8}/{owner}/{path}')
                yield base + "/pre-validation-call"
                yield base + "/post-validation-call"


def result_labels(artifact, family):
    """Transform return contexts, not mutations or comparison sites."""
    for width in WIDTHS:
        for owner in ("cached", "operation-local"):
            for path in PATHS:
                yield (f'{artifact["binary_sha256"][:16]}/{family["family"]}/'
                       f'aes{width * 8}/{owner}/{path}/transform-return')


def completion_labels(artifact):
    """Inner codeword store contexts only, not outer completion or permit."""
    for width in WIDTHS:
        for owner in ("cached", "operation-local"):
            for path in PATHS:
                yield (f'{artifact["binary_sha256"][:16]}/completion/'
                       f'aes{width * 8}/{owner}/{path}/inner-store')


def outer_completion_labels(artifact):
    """Operation-local outer store contexts, not completed lifecycle checks."""
    for width in WIDTHS:
        for path in PATHS:
            yield (f'{artifact["binary_sha256"][:16]}/completion/'
                   f'aes{width * 8}/operation-local/{path}/outer-store')


def permit_labels(artifact):
    """Healthy permit boundaries, not receipt internals or bypass passes."""
    for width in WIDTHS:
        for owner in ("cached", "operation-local"):
            for path in PATHS:
                base = (f'{artifact["binary_sha256"][:16]}/final-permit/'
                        f'aes{width * 8}/{owner}/{path}')
                for stage in ("entry", "deny-before-guarded-copy", "healthy-return"):
                    yield base + "/" + stage


def readback_labels(artifact):
    """Guarded-write call contexts, not full destination-check coverage."""
    for width in WIDTHS:
        for owner in ("cached", "operation-local"):
            for path in PATHS:
                base = (f'{artifact["binary_sha256"][:16]}/readbacks/'
                        f'aes{width * 8}/{owner}/{path}')
                yield base + "/guarded-forward"
                yield base + "/guarded-reverse"


def secret_destination_labels(artifact):
    """Actual secret destination call contexts, not fault passes."""
    for width in WIDTHS:
        for owner in ("cached", "operation-local"):
            for path in ("encrypt", "decrypt"):
                base = (f'{artifact["binary_sha256"][:16]}/secret-destination/'
                        f'aes{width * 8}/{owner}/{path}')
                for stage in ("entry", "staging", "actual-validation"):
                    yield base + "/" + stage


def actual_secret_readback_labels(artifact):
    """Two validator call sites share one helper; independence remains open."""
    for width in WIDTHS:
        for owner in ("cached", "operation-local"):
            for path in ("encrypt", "decrypt"):
                base = (f'{artifact["binary_sha256"][:16]}/readbacks/'
                        f'aes{width * 8}/{owner}/{path}')
                yield base + "/actual-secret-forward"
                yield base + "/actual-secret-reverse"


def secret_result_labels(artifact):
    """Healthy result construction, not the final caller handoff or a fault pass."""
    for width in WIDTHS:
        for owner in ("cached", "operation-local"):
            for path in ("encrypt", "decrypt"):
                base = (f'{artifact["binary_sha256"][:16]}/secret-destination/'
                        f'aes{width * 8}/{owner}/{path}')
                for stage in ("lifecycle-complete-call", "result-pointer-store",
                              "result-length-store"):
                    yield base + "/" + stage


def secret_caller_labels(artifact):
    """Fixture-specific call/return contexts, not a final-handoff fault test."""
    for width in WIDTHS:
        for owner in ("cached", "operation-local"):
            for path in ("encrypt", "decrypt"):
                base = (f'{artifact["binary_sha256"][:16]}/secret-destination/'
                        f'aes{width * 8}/{owner}/{path}')
                yield base + "/fixture-call"
                yield base + "/fixture-return"


def validate(data, inventory, observation, capture_observation, retained_observation,
             result_observation, completion_observation, outer_completion_observation,
             permit_observation, readbacks_observation, secret_destination_observation,
             secret_result_observation, secret_caller_observation):
    fields(data, "schema status qualification source_inventory observation_record observation_sha256 capture_observation_record capture_observation_sha256 retained_observation_record retained_observation_sha256 result_observation_record result_observation_sha256 completion_observation_record completion_observation_sha256 outer_completion_observation_record outer_completion_observation_sha256 permit_observation_record permit_observation_sha256 readbacks_observation_record readbacks_observation_sha256 secret_destination_observation_record secret_destination_observation_sha256 secret_result_observation_record secret_result_observation_sha256 secret_caller_observation_record secret_caller_observation_sha256 family class owner phase mutation_family expected_outcome fault_results dc1_pairings capture_families capture_artifacts retained_family retained_artifacts result_families result_artifacts completion_family completion_artifacts outer_completion_artifacts permit_family permit_artifacts readbacks_family readbacks_artifacts secret_destination_family secret_destination_artifacts secret_result_artifacts secret_caller_artifacts artifacts limits")
    require(type(data["schema"]) is int and data["schema"] == 1)
    require(data["status"] == "partial-development-site-map" and data["qualification"] == "none")
    require(data["source_inventory"] == SOURCE.INVENTORY)
    require(data["observation_record"] == "assurance/aes-fault-local-recapture-map-observations.json")
    require(re.fullmatch(r"[0-9a-f]{64}", data["observation_sha256"]) is not None)
    require(data["capture_observation_record"] == "assurance/aes-fault-capture-current-observations.json")
    require(re.fullmatch(r"[0-9a-f]{64}", data["capture_observation_sha256"]) is not None)
    require(data["retained_observation_record"] == "assurance/aes-fault-retained-validation-observations.json")
    require(re.fullmatch(r"[0-9a-f]{64}", data["retained_observation_sha256"]) is not None)
    require(data["result_observation_record"] == "assurance/aes-fault-result-map-observations.json")
    require(re.fullmatch(r"[0-9a-f]{64}", data["result_observation_sha256"]) is not None)
    require(data["completion_observation_record"] == "assurance/aes-fault-completion-map-observations.json")
    require(re.fullmatch(r"[0-9a-f]{64}", data["completion_observation_sha256"]) is not None)
    require(data["outer_completion_observation_record"] == "assurance/aes-fault-outer-completion-map-observations.json")
    require(re.fullmatch(r"[0-9a-f]{64}", data["outer_completion_observation_sha256"]) is not None)
    require(data["permit_observation_record"] == "assurance/aes-fault-permit-map-observations.json")
    require(re.fullmatch(r"[0-9a-f]{64}", data["permit_observation_sha256"]) is not None)
    require(data["readbacks_observation_record"] == "assurance/aes-fault-readbacks-map-observations.json")
    require(re.fullmatch(r"[0-9a-f]{64}", data["readbacks_observation_sha256"]) is not None)
    require(data["secret_destination_observation_record"] ==
            "assurance/aes-fault-secret-destination-map-observations.json")
    require(re.fullmatch(r"[0-9a-f]{64}", data["secret_destination_observation_sha256"])
            is not None)
    require(data["secret_result_observation_record"] ==
            "assurance/aes-fault-secret-result-map-observations.json")
    require(re.fullmatch(r"[0-9a-f]{64}", data["secret_result_observation_sha256"])
            is not None)
    require(data["secret_caller_observation_record"] ==
            "assurance/aes-fault-secret-caller-map-observations.json")
    require(re.fullmatch(r"[0-9a-f]{64}", data["secret_caller_observation_sha256"])
            is not None)
    require(data["family"] == "local-key-copy" and data["class"] == "D3")
    require(data["owner"] == "operation-local" and data["phase"] == "use")
    require(data["mutation_family"] == "transient-byte")
    require(data["expected_outcome"] == "reject-or-correct")
    require(data["fault_results"] == [] and data["dc1_pairings"] == [])
    require(type(data["capture_families"]) is list and len(data["capture_families"]) == 2)
    require(type(data["capture_artifacts"]) is list and len(data["capture_artifacts"]) == 2)
    require(type(data["retained_artifacts"]) is list and len(data["retained_artifacts"]) == 2)
    require(type(data["result_artifacts"]) is list and len(data["result_artifacts"]) == 2)
    require(type(data["completion_artifacts"]) is list
            and len(data["completion_artifacts"]) == 2)
    require(type(data["outer_completion_artifacts"]) is list
            and len(data["outer_completion_artifacts"]) == 2)
    require(type(data["permit_artifacts"]) is list and len(data["permit_artifacts"]) == 2)
    require(type(data["readbacks_artifacts"]) is list
            and len(data["readbacks_artifacts"]) == 2)
    require(type(data["secret_destination_artifacts"]) is list
            and len(data["secret_destination_artifacts"]) == 2)
    require(type(data["secret_result_artifacts"]) is list
            and len(data["secret_result_artifacts"]) == 2)
    require(type(data["secret_caller_artifacts"]) is list
            and len(data["secret_caller_artifacts"]) == 2)
    require(type(data["limits"]) is list and len(data["limits"]) >= 3)
    require(all(type(value) is str and value.strip() for value in data["limits"]))
    families, bypasses = SOURCE.validate(inventory)
    require(inventory["artifact_mappings"] == [])
    matching = [s for s in inventory["sites"] if s["id"] == data["family"]]
    require(len(matching) == 1)
    site = matching[0]
    require(site["status"] == "open" and site["classes"] == [data["class"]])
    require(site["owners"] == [data["owner"]] and site["phase"] == data["phase"])
    require(site["mutation"] == data["mutation_family"])
    require(site["outcome"] == data["expected_outcome"])
    fields(observation, "schema status qualification recorded_at_utc source_context reproduction observations limits")
    require(observation["schema"] == 1 and observation["qualification"] == "none")
    require(observation["status"] == "partial-development-observations")
    require(type(data["artifacts"]) is list and len(data["artifacts"]) == 2)
    require(type(observation["observations"]) is list and len(observation["observations"]) == 2)
    hashes, all_labels = set(), []
    expected_cases = [f"aes{width * 8}/{path}" for width in WIDTHS for path in PATHS]
    for artifact, observed in zip(data["artifacts"], observation["observations"]):
        fields(artifact, "status binary_sha256 toolchain arch caller_symbol call_offsets copy_leaf_symbol word_load_offset word_store_offset width_bytes paths word_offsets_by_width")
        require(artifact["status"] == "baseline-observed-not-faulted")
        digest = artifact["binary_sha256"]
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None and digest not in hashes)
        hashes.add(digest)
        for mapped, recorded in (("binary_sha256", "binary_sha256"),
                                 ("toolchain", "toolchain"), ("arch", "arch"),
                                 ("caller_symbol", "function"), ("call_offsets", "call_offsets")):
            require(artifact[mapped] == observed[recorded])
        require(artifact["copy_leaf_symbol"] == observed["copy_leaf"]["symbol"])
        require(artifact["word_load_offset"] == observed["copy_leaf"]["events"]["word_load"])
        require(artifact["word_store_offset"] == observed["copy_leaf"]["events"]["word_store"])
        require(artifact["width_bytes"] == WIDTHS and artifact["paths"] == PATHS)
        require(artifact["word_offsets_by_width"] == {
            str(width): list(range(0, width, 8)) for width in WIDTHS
        })
        require(observed["baseline_cases"] == expected_cases)
        all_labels.extend(labels(artifact))
    require(len(all_labels) == 252 and len(set(all_labels)) == len(all_labels))
    fields(capture_observation, "schema status qualification recorded_at_utc source_context reproduction case_matrix artifacts limits")
    require(type(capture_observation["schema"]) is int and capture_observation["schema"] == 1)
    require(capture_observation["status"] == "partial-development-observations")
    require(capture_observation["qualification"] == "none")
    require(capture_observation["case_matrix"] == {
        "width_bytes": WIDTHS, "owners": ["cached", "ephemeral"],
        "paths": PATHS, "scopes": ["key", "input"], "count_per_artifact": 36,
    })
    require(type(capture_observation["artifacts"]) is list
            and len(capture_observation["artifacts"]) == 2)
    for family, name, scope, phase in zip(
            data["capture_families"], ("key-capture", "block-capture"),
            ("key", "input"), ("import", "use")):
        fields(family, "family scope class owner phase mutation_family expected_outcome")
        require(family == {"family": name, "scope": scope, "class": "D3",
                           "owner": ["cached", "operation-local"], "phase": phase,
                           "mutation_family": "transient-byte",
                           "expected_outcome": "reject-or-correct"})
        source = [site for site in inventory["sites"] if site["id"] == name]
        require(len(source) == 1 and source[0]["status"] == "open")
        require(source[0]["classes"] == [family["class"]])
        require(source[0]["owners"] == family["owner"] and source[0]["phase"] == phase)
        require(source[0]["mutation"] == family["mutation_family"])
        require(source[0]["outcome"] == family["expected_outcome"])
    capture_hashes = set()
    for artifact, recorded, local in zip(data["capture_artifacts"],
                                         capture_observation["artifacts"], data["artifacts"]):
        fields(artifact, "binary_sha256 status")
        require(artifact["status"] == "baseline-observed-not-faulted")
        digest = artifact["binary_sha256"]
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                and digest not in capture_hashes)
        capture_hashes.add(digest)
        require(digest == recorded["binary_sha256"] == local["binary_sha256"])
        require(recorded["toolchain"] == local["toolchain"])
        require(recorded["arch"] == local["arch"] == "x86_64")
        require(recorded["baseline_count"] == 36)
        require(recorded["capture"]["symbol"] ==
                "brynja_crypto::aes::fault_integrity::capture::pair")
        require(recorded["capture"]["events"]["first_call"] == 39)
        require(recorded["capture"]["events"]["second_call"] == 60)
        require(recorded["copy"]["symbol"] == local["copy_leaf_symbol"])
        require(recorded["copy"]["events"]["return"] == 62)
        require(recorded["capture"]["shape"] == recorded["wrapper"]["shape"] ==
                recorded["copy"]["shape"])
        for family in data["capture_families"]:
            all_labels.extend(capture_labels(artifact, family))
    fields(data["retained_family"], "family class owner phase mutation_family expected_outcome")
    require(data["retained_family"] == {
        "family": "retained-key", "class": "D2",
        "owner": ["cached", "operation-local"], "phase": "lifetime",
        "mutation_family": "persistent-byte", "expected_outcome": "retained-mismatch",
    })
    retained_site = [s for s in inventory["sites"] if s["id"] == "retained-key"]
    require(len(retained_site) == 1 and retained_site[0]["status"] == "open")
    require(retained_site[0]["classes"] == ["D2"])
    require(retained_site[0]["owners"] == data["retained_family"]["owner"])
    require(retained_site[0]["phase"] == "lifetime")
    require(retained_site[0]["mutation"] == "persistent-byte")
    require(retained_site[0]["outcome"] == "retained-mismatch")
    fields(retained_observation, "schema status qualification recorded_at_utc source_context reproduction artifacts limits")
    require(type(retained_observation["schema"]) is int and retained_observation["schema"] == 1)
    require(retained_observation["status"] == "partial-development-observations")
    require(retained_observation["qualification"] == "none")
    require(type(retained_observation["artifacts"]) is list
            and len(retained_observation["artifacts"]) == 2)
    retained_hashes = set()
    expected_retained_cases = [f"aes{width * 8}/{owner}/{path}"
                               for width in WIDTHS
                               for owner in ("cached", "ephemeral") for path in PATHS]
    for artifact, recorded, local in zip(data["retained_artifacts"],
                                         retained_observation["artifacts"], data["artifacts"]):
        fields(artifact, "binary_sha256 status")
        require(artifact["status"] == "baseline-observed-not-faulted")
        digest = artifact["binary_sha256"]
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                and digest not in retained_hashes)
        retained_hashes.add(digest)
        require(digest == recorded["binary_sha256"] == local["binary_sha256"])
        require(recorded["toolchain"] == local["toolchain"])
        require(recorded["arch"] == local["arch"] == "x86_64")
        require(recorded["call_offsets"] == [88, 233])
        retained_symbol = "brynja_crypto::aes::fault_integrity::retained::Retained"
        prefix = (retained_symbol if recorded["toolchain"] == "1.90.0"
                  else "<" + retained_symbol + ">")
        require(recorded["compute_symbol"] == prefix + "::compute")
        require(recorded["validate_symbol"] == prefix + "::validate")
        require(recorded["baseline_cases"] == expected_retained_cases)
        all_labels.extend(retained_labels(artifact))
    fields(result_observation, "schema status qualification recorded_at_utc source_context reproduction artifacts limits")
    require(result_observation["schema"] == 1)
    require(result_observation["status"] == "partial-development-observations")
    require(result_observation["qualification"] == "none")
    require(type(result_observation["artifacts"]) is list
            and len(result_observation["artifacts"]) == 2)
    require(type(data["result_families"]) is list and len(data["result_families"]) == 2)
    for family, name in zip(data["result_families"], ("primary-result", "secondary-result")):
        fields(family, "family class owner phase mutation_family expected_outcome")
        require(family == {"family": name, "class": "D1",
                           "owner": ["cached", "operation-local"], "phase": "use",
                           "mutation_family": "transient-byte",
                           "expected_outcome": "reject-or-correct"})
        site = [s for s in inventory["sites"] if s["id"] == name]
        require(len(site) == 1 and site[0]["status"] == "open")
        require(site[0]["classes"] == ["D1"] and site[0]["owners"] == family["owner"])
        require(site[0]["phase"] == "use" and site[0]["mutation"] == "transient-byte")
        require(site[0]["outcome"] == "reject-or-correct")
    result_hashes = set()
    for artifact, recorded, local in zip(data["result_artifacts"],
                                         result_observation["artifacts"], data["artifacts"]):
        fields(artifact, "binary_sha256 status")
        require(artifact["status"] == "baseline-observed-not-faulted")
        digest = artifact["binary_sha256"]
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                and digest not in result_hashes)
        result_hashes.add(digest)
        require(digest == recorded["binary_sha256"] == local["binary_sha256"])
        require(recorded["toolchain"] == local["toolchain"] and recorded["arch"] == "x86_64")
        require(recorded["compute_symbol"] == next(
            item["compute_symbol"] for item in retained_observation["artifacts"]
            if item["binary_sha256"] == digest))
        require(recorded["primary_call_offsets"] == {"16": 184, "24": 170, "32": 198})
        require(recorded["primary_return_offset"] == 203)
        require(recorded["secondary_call_offset"] == 221)
        require(recorded["secondary_return_offset"] == 226)
        require(recorded["baseline_cases"] == expected_retained_cases)
        for family in data["result_families"]:
            all_labels.extend(result_labels(artifact, family))
    fields(data["completion_family"], "family classes owner phase mutation_family expected_outcome")
    require(data["completion_family"] == {
        "family": "completion", "classes": ["L1", "C1"],
        "owner": ["cached", "operation-local"], "phase": "use",
        "mutation_family": "codeword-or-bypass", "expected_outcome": "bypass-obligation",
    })
    completion_site = [s for s in inventory["sites"] if s["id"] == "completion"]
    require(len(completion_site) == 1 and completion_site[0]["status"] == "open")
    require(completion_site[0]["classes"] == ["L1", "C1"])
    require(completion_site[0]["owners"] == data["completion_family"]["owner"])
    require(completion_site[0]["phase"] == "use")
    require(completion_site[0]["mutation"] == "codeword-or-bypass")
    require(completion_site[0]["outcome"] == "bypass-obligation")
    fields(completion_observation, "schema status qualification recorded_at_utc source_context reproduction artifacts limits")
    require(completion_observation["schema"] == 1)
    require(completion_observation["status"] == "partial-development-observations")
    require(completion_observation["qualification"] == "none")
    require(type(completion_observation["artifacts"]) is list
            and len(completion_observation["artifacts"]) == 2)
    completion_hashes = set()
    for artifact, recorded, local in zip(data["completion_artifacts"],
                                         completion_observation["artifacts"], data["artifacts"]):
        fields(artifact, "binary_sha256 status")
        require(artifact["status"] == "baseline-observed-not-faulted")
        digest = artifact["binary_sha256"]
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                and digest not in completion_hashes)
        completion_hashes.add(digest)
        require(digest == recorded["binary_sha256"] == local["binary_sha256"])
        require(recorded["toolchain"] == local["toolchain"] and recorded["arch"] == "x86_64")
        require(recorded["compute_symbol"] == next(
            item["compute_symbol"] for item in retained_observation["artifacts"]
            if item["binary_sha256"] == digest))
        require(recorded["store_offset"] == 272 and recorded["return_offset"] == 276)
        require(recorded["baseline_cases"] == expected_retained_cases)
        all_labels.extend(completion_labels(artifact))
    fields(outer_completion_observation, "schema status qualification recorded_at_utc source_context reproduction artifacts limits")
    require(outer_completion_observation["schema"] == 1)
    require(outer_completion_observation["status"] == "partial-development-observations")
    require(outer_completion_observation["qualification"] == "none")
    require(type(outer_completion_observation["artifacts"]) is list
            and len(outer_completion_observation["artifacts"]) == 2)
    outer_hashes = set()
    expected_outer_cases = [f"aes{width * 8}/operation-local/{path}"
                            for width in WIDTHS for path in PATHS]
    for artifact, recorded, local in zip(data["outer_completion_artifacts"],
                                         outer_completion_observation["artifacts"],
                                         data["artifacts"]):
        fields(artifact, "binary_sha256 status")
        require(artifact["status"] == "baseline-observed-not-faulted")
        digest = artifact["binary_sha256"]
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                and digest not in outer_hashes)
        outer_hashes.add(digest)
        require(digest == recorded["binary_sha256"] == local["binary_sha256"])
        require(recorded["toolchain"] == local["toolchain"] and recorded["arch"] == "x86_64")
        require(recorded["inner_symbol"] == next(
            item["compute_symbol"] for item in retained_observation["artifacts"]
            if item["binary_sha256"] == digest))
        require(recorded["inner_store_offset"] == 272)
        expected = ({"1.90.0": (863, 2094), "1.100.0": (606, 1295)})[local["toolchain"]]
        outer_base = "brynja_crypto::aes::fault_integrity::retained::ephemeral::Ephemeral"
        expected_outer_symbol = (outer_base if local["toolchain"] == "1.90.0"
                                 else "<" + outer_base + ">") + "::compute"
        require(recorded["outer_symbol"] == expected_outer_symbol)
        require((recorded["outer_inner_call_offset"], recorded["outer_store_offset"])
                == expected)
        require(recorded["baseline_cases"] == expected_outer_cases)
        all_labels.extend(outer_completion_labels(artifact))
    fields(data["permit_family"], "family classes owner phase mutation_family expected_outcome")
    require(data["permit_family"] == {
        "family": "final-permit", "classes": ["L1", "C1"],
        "owner": ["cached", "operation-local"], "phase": "release",
        "mutation_family": "codeword-or-bypass", "expected_outcome": "bypass-obligation",
    })
    permit_site = [s for s in inventory["sites"] if s["id"] == "final-permit"]
    require(len(permit_site) == 1 and permit_site[0]["status"] == "open")
    require(permit_site[0]["classes"] == ["L1", "C1"])
    require(permit_site[0]["owners"] == data["permit_family"]["owner"])
    require(permit_site[0]["phase"] == "release")
    require(permit_site[0]["mutation"] == "codeword-or-bypass")
    require(permit_site[0]["outcome"] == "bypass-obligation")
    fields(permit_observation, "schema status qualification recorded_at_utc source_context reproduction artifacts limits")
    require(permit_observation["schema"] == 1)
    require(permit_observation["status"] == "partial-development-observations")
    require(permit_observation["qualification"] == "none")
    require(type(permit_observation["artifacts"]) is list
            and len(permit_observation["artifacts"]) == 2)
    permit_hashes = set()
    expected_permit_cases = [f"aes{width * 8}/{owner}/{path}"
                             for width in WIDTHS
                             for owner in ("cached", "ephemeral") for path in PATHS]
    for artifact, recorded, local in zip(data["permit_artifacts"],
                                         permit_observation["artifacts"], data["artifacts"]):
        fields(artifact, "binary_sha256 status")
        require(artifact["status"] == "baseline-observed-not-faulted")
        digest = artifact["binary_sha256"]
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                and digest not in permit_hashes)
        permit_hashes.add(digest)
        require(digest == recorded["binary_sha256"] == local["binary_sha256"])
        require(recorded["toolchain"] == local["toolchain"] and recorded["arch"] == "x86_64")
        require(recorded["permit_symbol"] ==
                "brynja_crypto::aes::fault_integrity::authorization_model::permit_fresh")
        expected = {"1.90.0": (21, 49, 146, 397),
                    "1.100.0": (20, 47, 143, 240)}[local["toolchain"]]
        require((recorded["deny_store_offset"], recorded["receipt_call_offset"],
                 recorded["guarded_call_offset"], recorded["return_offset"]) == expected)
        require(recorded["baseline_cases"] == expected_permit_cases)
        all_labels.extend(permit_labels(artifact))
    fields(data["readbacks_family"], "family classes owner phase mutation_family expected_outcome")
    require(data["readbacks_family"] == {
        "family": "readbacks", "classes": ["C1"],
        "owner": ["cached", "operation-local"], "phase": "release",
        "mutation_family": "single-bypass", "expected_outcome": "bypass-obligation",
    })
    readback_site = [s for s in inventory["sites"] if s["id"] == "readbacks"]
    require(len(readback_site) == 1 and readback_site[0]["status"] == "open")
    require(readback_site[0]["classes"] == ["C1"])
    require(readback_site[0]["owners"] == data["readbacks_family"]["owner"])
    require(readback_site[0]["phase"] == "release")
    require(readback_site[0]["mutation"] == "single-bypass")
    require(readback_site[0]["outcome"] == "bypass-obligation")
    fields(readbacks_observation, "schema status qualification recorded_at_utc source_context reproduction artifacts limits")
    require(readbacks_observation["schema"] == 1)
    require(readbacks_observation["status"] == "partial-development-observations")
    require(readbacks_observation["qualification"] == "none")
    require(type(readbacks_observation["artifacts"]) is list
            and len(readbacks_observation["artifacts"]) == 2)
    readback_hashes = set()
    for artifact, recorded, local in zip(data["readbacks_artifacts"],
                                         readbacks_observation["artifacts"], data["artifacts"]):
        fields(artifact, "binary_sha256 status")
        require(artifact["status"] == "baseline-observed-not-faulted")
        digest = artifact["binary_sha256"]
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                and digest not in readback_hashes)
        readback_hashes.add(digest)
        require(digest == recorded["binary_sha256"] == local["binary_sha256"])
        require(recorded["toolchain"] == local["toolchain"] and recorded["arch"] == "x86_64")
        require(recorded["guarded_symbol"] ==
                "brynja_crypto::aes::fault_integrity::transaction::guarded_write")
        require(recorded["check_symbol"] ==
                "brynja_crypto::aes::fault_integrity::transaction::check")
        expected = {"1.90.0": ([459, 486], [456, 480]),
                    "1.100.0": ([327, 354], [324, 348])}[local["toolchain"]]
        require((recorded["call_offsets"], recorded["selector_offsets"]) == expected)
        require(recorded["baseline_cases"] == expected_permit_cases)
        all_labels.extend(readback_labels(artifact))
    fields(data["secret_destination_family"],
           "family classes owner phase mutation_family expected_outcome")
    require(data["secret_destination_family"] == {
        "family": "secret-destination", "classes": ["D4", "C1"],
        "owner": ["cached", "operation-local"], "phase": "release",
        "mutation_family": "destination-or-bypass",
        "expected_outcome": "destination-obligation",
    })
    secret_site = [s for s in inventory["sites"] if s["id"] == "secret-destination"]
    require(len(secret_site) == 1 and secret_site[0]["status"] == "open")
    require(secret_site[0]["classes"] == ["D4", "C1"])
    require(secret_site[0]["owners"] == data["secret_destination_family"]["owner"])
    require(secret_site[0]["phase"] == "release")
    require(secret_site[0]["mutation"] == "destination-or-bypass")
    require(secret_site[0]["outcome"] == "destination-obligation")
    fields(secret_destination_observation,
           "schema status qualification recorded_at_utc source_context reproduction artifacts limits")
    require(secret_destination_observation["schema"] == 1)
    require(secret_destination_observation["status"] == "partial-development-observations")
    require(secret_destination_observation["qualification"] == "none")
    require(type(secret_destination_observation["artifacts"]) is list
            and len(secret_destination_observation["artifacts"]) == 2)
    secret_hashes = set()
    expected_secret_cases = [f"aes{width * 8}/{owner}/{path}"
                             for width in WIDTHS
                             for owner in ("cached", "ephemeral")
                             for path in ("encrypt", "decrypt")]
    prefix = "brynja_crypto::aes::fault_integrity::retained::"
    for artifact, recorded, local in zip(data["secret_destination_artifacts"],
                                         secret_destination_observation["artifacts"],
                                         data["artifacts"]):
        fields(artifact, "binary_sha256 status")
        require(artifact["status"] == "baseline-observed-not-faulted")
        digest = artifact["binary_sha256"]
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                and digest not in secret_hashes)
        secret_hashes.add(digest)
        require(digest == recorded["binary_sha256"] == local["binary_sha256"])
        require(recorded["toolchain"] == local["toolchain"] and recorded["arch"] == "x86_64")
        require(recorded["validate_symbol"] ==
                "brynja_crypto::aes::fault_integrity::transaction::validate")
        require(recorded["validate_check_offsets"] == [23, 48])
        legacy = local["toolchain"] == "1.90.0"
        expected_owners = {
            "cached": {"symbol": (prefix + "Cached::secret" if legacy else
                                   "<" + prefix + "Cached>::secret"),
                       "address": 0x108660 if legacy else 0xc4d80,
                       "guarded": 626 if legacy else 446,
                       "validate": 743 if legacy else 524,
                       "permit": 817 if legacy else 598},
            "ephemeral": {"symbol": (prefix + "ephemeral::Ephemeral::secret_profile"
                                       if legacy else
                                       "<" + prefix + "ephemeral::Ephemeral>::secret_profile"),
                          "address": 0x109b00 if legacy else 0xc2770,
                          "guarded": 657 if legacy else 490,
                          "validate": 783 if legacy else 577,
                          "permit": 857 if legacy else 651},
        }
        require(recorded["owners"] == expected_owners)
        require(recorded["baseline_cases"] == expected_secret_cases)
        all_labels.extend(secret_destination_labels(artifact))
        all_labels.extend(actual_secret_readback_labels(artifact))
    fields(secret_result_observation,
           "schema status qualification recorded_at_utc source_context reproduction artifacts limits")
    require(secret_result_observation["schema"] == 1)
    require(secret_result_observation["status"] == "partial-development-observations")
    require(secret_result_observation["qualification"] == "none")
    require(secret_result_observation["source_context"]["clean_checkout"] is False)
    require(type(secret_result_observation["artifacts"]) is list
            and len(secret_result_observation["artifacts"]) == 2)
    result_hashes = set()
    for artifact, recorded, local in zip(data["secret_result_artifacts"],
                                         secret_result_observation["artifacts"],
                                         data["artifacts"]):
        fields(artifact, "binary_sha256 status")
        require(artifact["status"] == "baseline-observed-not-faulted")
        fields(recorded, "schema status qualification arch toolchain binary_sha256 complete_symbol complete_address owners baseline_cases limits")
        digest = artifact["binary_sha256"]
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                and digest not in result_hashes)
        result_hashes.add(digest)
        require(digest == recorded["binary_sha256"] == local["binary_sha256"])
        require(recorded["schema"] == 1 and recorded["arch"] == "x86_64")
        require(recorded["status"] == "development-secret-result-construction-observed")
        require(recorded["qualification"] == "none")
        require(recorded["toolchain"] == local["toolchain"])
        legacy = local["toolchain"] == "1.90.0"
        complete_symbol = "brynja_crypto::aes::fault_integrity::transaction::Operation::complete"
        if not legacy:
            complete_symbol = ("<brynja_crypto::aes::fault_integrity::transaction::Operation>"
                               "::complete")
        require(recorded["complete_symbol"] == complete_symbol)
        require(recorded["complete_address"] == (0x10bf80 if legacy else 0xc37c0))
        expected_owners = {
            "cached": {"complete": 834 if legacy else 616,
                       "pointer_store": 908 if legacy else 687,
                       "length_store": 912 if legacy else 691,
                       "result_register": "rbx"},
            "ephemeral": {"complete": 875 if legacy else 669,
                          "pointer_store": 928 if legacy else 722,
                          "length_store": 932 if legacy else 726,
                          "result_register": "rcx"},
        }
        require(recorded["owners"] == expected_owners)
        require(recorded["baseline_cases"] == expected_secret_cases)
        all_labels.extend(secret_result_labels(artifact))
    fields(secret_caller_observation,
           "schema status qualification recorded_at_utc source_context reproduction artifacts limits")
    require(secret_caller_observation["schema"] == 1)
    require(secret_caller_observation["status"] == "partial-development-observations")
    require(secret_caller_observation["qualification"] == "none")
    require(secret_caller_observation["source_context"]["clean_checkout"] is False)
    require(type(secret_caller_observation["artifacts"]) is list
            and len(secret_caller_observation["artifacts"]) == 2)
    caller_hashes = set()
    prefix = "brynja_crypto::aes::fault_integrity::retained::probe_tests::run_"
    for artifact, recorded, local in zip(data["secret_caller_artifacts"],
                                         secret_caller_observation["artifacts"],
                                         data["artifacts"]):
        fields(artifact, "binary_sha256 status")
        require(artifact["status"] == "baseline-observed-not-faulted")
        fields(recorded, "schema status qualification arch toolchain binary_sha256 callers baseline_cases limits")
        digest = artifact["binary_sha256"]
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                and digest not in caller_hashes)
        caller_hashes.add(digest)
        require(digest == recorded["binary_sha256"] == local["binary_sha256"])
        require(recorded["schema"] == 1 and recorded["arch"] == "x86_64")
        require(recorded["status"] == "development-secret-fixture-caller-return-observed")
        require(recorded["qualification"] == "none")
        require(recorded["toolchain"] == local["toolchain"])
        legacy = local["toolchain"] == "1.90.0"
        expected_callers = {
            "cached": {"symbol": prefix + "cached",
                       "address": 0x113c60 if legacy else 0xdf560,
                       "call": 1114 if legacy else 985,
                       "status": 1131 if legacy else 997,
                       "status_instruction": ("cmpl $0x1,0x40(%rsp)" if legacy else
                                              "cmpl $0x1,0x358(%rsp)")},
            "ephemeral": {"symbol": prefix + "ephemeral",
                          "address": 0x1144e0 if legacy else 0xdfce0,
                          "call": 884 if legacy else 832,
                          "status": 889 if legacy else 837,
                          "status_instruction": ("cmpb $0x0,0x10(%rsp)" if legacy else
                                                 "cmpb $0x0,0x28(%rsp)")},
        }
        require(recorded["callers"] == expected_callers)
        require(recorded["baseline_cases"] == expected_secret_cases)
        all_labels.extend(secret_caller_labels(artifact))
    require(len(all_labels) == 1158 and len(set(all_labels)) == len(all_labels))
    require(families == 22 and bypasses == 9)
    return len(hashes), len(all_labels), families - 10, bypasses


def check(root=ROOT):
    map_path = SOURCE.file_at(root, MAP)
    data = SOURCE.load(map_path)
    inventory = SOURCE.load(SOURCE.file_at(root, data["source_inventory"]))
    observation_path = SOURCE.file_at(root, data["observation_record"])
    raw = observation_path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == data["observation_sha256"])
    observation = SOURCE.load(observation_path)
    capture_path = SOURCE.file_at(root, data["capture_observation_record"])
    capture_raw = capture_path.read_bytes()
    require(hashlib.sha256(capture_raw).hexdigest() == data["capture_observation_sha256"])
    capture_observation = SOURCE.load(capture_path)
    retained_path = SOURCE.file_at(root, data["retained_observation_record"])
    retained_raw = retained_path.read_bytes()
    require(hashlib.sha256(retained_raw).hexdigest() == data["retained_observation_sha256"])
    retained_observation = SOURCE.load(retained_path)
    result_path = SOURCE.file_at(root, data["result_observation_record"])
    result_raw = result_path.read_bytes()
    require(hashlib.sha256(result_raw).hexdigest() == data["result_observation_sha256"])
    result_observation = SOURCE.load(result_path)
    completion_path = SOURCE.file_at(root, data["completion_observation_record"])
    completion_raw = completion_path.read_bytes()
    require(hashlib.sha256(completion_raw).hexdigest() == data["completion_observation_sha256"])
    completion_observation = SOURCE.load(completion_path)
    outer_completion_path = SOURCE.file_at(root, data["outer_completion_observation_record"])
    outer_completion_raw = outer_completion_path.read_bytes()
    require(hashlib.sha256(outer_completion_raw).hexdigest()
            == data["outer_completion_observation_sha256"])
    outer_completion_observation = SOURCE.load(outer_completion_path)
    permit_path = SOURCE.file_at(root, data["permit_observation_record"])
    permit_raw = permit_path.read_bytes()
    require(hashlib.sha256(permit_raw).hexdigest() == data["permit_observation_sha256"])
    permit_observation = SOURCE.load(permit_path)
    readbacks_path = SOURCE.file_at(root, data["readbacks_observation_record"])
    readbacks_raw = readbacks_path.read_bytes()
    require(hashlib.sha256(readbacks_raw).hexdigest() == data["readbacks_observation_sha256"])
    readbacks_observation = SOURCE.load(readbacks_path)
    secret_path = SOURCE.file_at(root, data["secret_destination_observation_record"])
    secret_raw = secret_path.read_bytes()
    require(hashlib.sha256(secret_raw).hexdigest() ==
            data["secret_destination_observation_sha256"])
    secret_destination_observation = SOURCE.load(secret_path)
    secret_result_path = SOURCE.file_at(root, data["secret_result_observation_record"])
    secret_result_raw = secret_result_path.read_bytes()
    require(hashlib.sha256(secret_result_raw).hexdigest() ==
            data["secret_result_observation_sha256"])
    secret_result_observation = SOURCE.load(secret_result_path)
    secret_caller_path = SOURCE.file_at(root, data["secret_caller_observation_record"])
    secret_caller_raw = secret_caller_path.read_bytes()
    require(hashlib.sha256(secret_caller_raw).hexdigest() ==
            data["secret_caller_observation_sha256"])
    secret_caller_observation = SOURCE.load(secret_caller_path)
    return validate(data, inventory, observation, capture_observation,
                    retained_observation, result_observation, completion_observation,
                    outer_completion_observation, permit_observation,
                    readbacks_observation, secret_destination_observation,
                    secret_result_observation, secret_caller_observation)


def main():
    try:
        require(len(sys.argv) == 1)
        artifacts, labels_count, unmapped, bypasses = check()
    except (OSError, ValueError, TypeError, KeyError):
        print("Partial emitted-site map invalid; no qualification performed.", file=sys.stderr)
        return 2
    print(f"Partial emitted map valid: {artifacts} pinned test artifacts; {labels_count} baseline context labels.")
    print(f"Other source families wholly unmapped: {unmapped}; bypass families OPEN: {bypasses}.")
    print("No fault results, DC1 pairings, qualified builds or public admission.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
