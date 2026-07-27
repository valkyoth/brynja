#!/usr/bin/env python3
"""Shared, dependency-free helpers for Brynja's standards evidence."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "standards/source-policy.toml"
RFC_SOURCES = ROOT / "rfc/SOURCES"
RFC_HASHES = ROOT / "rfc/SHA256SUMS"
LOCAL_SOURCES = ROOT / "references/LOCAL_SOURCES"
LOCAL_HASHES = ROOT / "references/LOCAL_SHA256SUMS"
RFC_INDEX = ROOT / "standards/snapshots/rfc-index.json"
ERRATA = ROOT / "standards/ERRATA.json"
STANDARDS_HASHES = ROOT / "standards/SHA256SUMS"
LEDGER = ROOT / "standards/source-ledger.json"
IANA_DIRECTORY = ROOT / "standards/snapshots/iana"
USER_AGENT = "brynja-standards-ledger/0.3 (+https://github.com/valkyoth/brynja)"
RFC_NS = {"r": "https://www.rfc-editor.org/rfc-index"}
IANA_NS = {"i": "http://www.iana.org/assignments"}


def read_policy(path: Path = POLICY) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def read_source_file(path: Path, key_type=str) -> dict:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, url, role = line.split()
        result[key_type(key)] = {"url": url, "role": role}
    return result


def read_hash_file(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        digest, name = line.split("  ", 1)
        result[name] = digest
    return result


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        if response.status != 200:
            raise RuntimeError(f"{url}: HTTP {response.status}")
        return response.read()


def direct_text(element: ET.Element | None) -> str:
    if element is None:
        return ""
    return "".join(element.itertext()).strip()


def related(entry: ET.Element, relation: str) -> list[int]:
    return sorted(
        int(node.text.removeprefix("RFC"))
        for node in entry.findall(f"r:{relation}/r:doc-id", RFC_NS)
    )


def project_rfc_index(data: bytes, numbers: set[int]) -> dict:
    root = ET.fromstring(data)
    entries = {}
    for entry in root.findall("r:rfc-entry", RFC_NS):
        doc_id = direct_text(entry.find("r:doc-id", RFC_NS))
        if not doc_id.startswith("RFC"):
            continue
        number = int(doc_id[3:])
        if number not in numbers:
            continue
        date = entry.find("r:date", RFC_NS)
        entries[str(number)] = {
            "current_status": direct_text(
                entry.find("r:current-status", RFC_NS)
            ),
            "date": {
                "month": direct_text(date.find("r:month", RFC_NS))
                if date is not None
                else "",
                "year": direct_text(date.find("r:year", RFC_NS))
                if date is not None
                else "",
            },
            "obsoleted_by": related(entry, "obsoleted-by"),
            "obsoletes": related(entry, "obsoletes"),
            "publication_status": direct_text(
                entry.find("r:publication-status", RFC_NS)
            ),
            "stream": direct_text(entry.find("r:stream", RFC_NS)),
            "title": direct_text(entry.find("r:title", RFC_NS)),
            "updated_by": related(entry, "updated-by"),
            "updates": related(entry, "updates"),
        }
    missing = numbers - {int(number) for number in entries}
    if missing:
        raise RuntimeError(f"RFC index omits locked RFCs: {sorted(missing)}")
    return {
        "schema": 1,
        "source": "https://www.rfc-editor.org/rfc-index.xml",
        "rfcs": entries,
    }


def errata_url(number: int) -> str:
    query = urllib.parse.urlencode(
        {"rfc_number": number, "status": "any", "presentation": "table"}
    )
    return f"https://errata.rfc-editor.org/search/?{query}"


class ErrataTableParser(HTMLParser):
    """Parse the RFC Editor's stable table presentation."""

    statuses = ("Verified", "Reported", "Held for Document Update", "Rejected")

    def __init__(self, number: int) -> None:
        super().__init__()
        self.number = number
        self.heading = False
        self.heading_text: list[str] = []
        self.status = ""
        self.in_row = False
        self.in_cell = False
        self.cell_text: list[str] = []
        self.cells: list[str] = []
        self.records: list[dict] = []

    def handle_starttag(self, tag: str, _attrs) -> None:
        if tag == "h2":
            self.heading = True
            self.heading_text = []
        elif tag == "tr":
            self.in_row = True
            self.cells = []
        elif tag == "td" and self.in_row:
            self.in_cell = True
            self.cell_text = []

    def handle_data(self, data: str) -> None:
        if self.heading:
            self.heading_text.append(data)
        if self.in_cell:
            self.cell_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "h2" and self.heading:
            heading = "".join(self.heading_text).strip()
            self.status = next(
                (
                    status
                    for status in self.statuses
                    if heading.startswith(status)
                ),
                "",
            )
            self.heading = False
        elif tag == "td" and self.in_cell:
            self.cells.append(" ".join("".join(self.cell_text).split()))
            self.in_cell = False
        elif tag == "tr" and self.in_row:
            self.in_row = False
            if self.cells and self.status:
                self.record_row()

    def record_row(self) -> None:
        match = re.fullmatch(r"RFC([0-9]+) \(([0-9]+)\)", self.cells[0])
        if match is None or len(self.cells) != 7:
            raise RuntimeError(f"unrecognized errata table row: {self.cells}")
        number = int(match.group(1))
        if number != self.number:
            raise RuntimeError(
                f"RFC {self.number} response included RFC {number}"
            )
        identifier = int(match.group(2))
        self.records.append(
            {
                "date_reported": self.cells[6],
                "id": identifier,
                "rfc": number,
                "section": self.cells[1],
                "status": self.status,
                "type": self.cells[2],
                "url": f"https://errata.rfc-editor.org/eid{identifier}/",
            }
        )


def parse_errata(data: bytes, number: int) -> list[dict]:
    parser = ErrataTableParser(number)
    parser.feed(data.decode("utf-8"))
    return sorted(parser.records, key=lambda item: item["id"])


def errata_disposition(status: str) -> tuple[str, str]:
    if status == "Verified":
        return "apply", "Verified erratum is normative input for implementation."
    if status in {"Reported", "Held for Document Update"}:
        return (
            "track-not-applied",
            "Unverified or held erratum is tracked but cannot alter requirements.",
        )
    if status == "Rejected":
        return "not-applicable", "Rejected erratum does not alter requirements."
    raise RuntimeError(f"unknown errata status: {status!r}")


def errata_review(record: dict, policy: dict) -> tuple[str, str]:
    lifecycle = lifecycle_for(record["rfc"], policy)
    domains, _ = domain_maps(policy)
    milestones = milestones_for(domains[record["rfc"]], policy)
    owner = milestones[0]
    prefix = "v" if not owner.startswith("H") else ""
    if lifecycle in {"exclusion", "caller-owned"}:
        implementation = f"boundary:{prefix}{owner}"
    elif lifecycle == "evidence":
        implementation = f"evidence:{prefix}{owner}"
    else:
        implementation = f"planned:{prefix}{owner}"

    status = record["status"]
    kind = record["type"]
    if status == "Verified":
        security = (
            f"Apply the verified {kind.lower()} correction when extracting "
            f"requirements for {implementation}; its owning milestone must "
            "bind the decision to code or boundary and positive/negative tests."
        )
    elif status in {"Reported", "Held for Document Update"}:
        security = (
            f"Do not let this unverified {kind.lower()} report alter normative "
            f"behavior; track it against {implementation} and recheck official "
            "status before dependent implementation and release."
        )
    elif status == "Rejected":
        implementation = "not-applicable:rfc-editor-rejected"
        security = (
            f"Do not alter normative behavior for this rejected "
            f"{kind.lower()} report; retain it to prevent accidental admission."
        )
    else:
        raise RuntimeError(f"unknown errata status: {status!r}")
    return implementation, security


def validate_iana_snapshot(data: bytes, expected_id: str) -> dict:
    root = ET.fromstring(data)
    if root.tag != f"{{{IANA_NS['i']}}}registry":
        raise RuntimeError(f"{expected_id}: unexpected IANA XML root")
    if root.get("id") != expected_id:
        raise RuntimeError(
            f"{expected_id}: snapshot identifies {root.get('id')!r}"
        )
    return {
        "created": direct_text(root.find("i:created", IANA_NS)),
        "title": direct_text(root.find("i:title", IANA_NS)),
        "updated": direct_text(root.find("i:updated", IANA_NS)),
    }


def lifecycle_for(number: int, policy: dict) -> str:
    for name, values in policy["lifecycle"].items():
        if number in values:
            return name.replace("_", "-")
    return "current"


def domain_maps(policy: dict) -> tuple[dict[int, list[str]], dict[str, list[str]]]:
    rfc_domains: dict[int, list[str]] = {}
    local_domains: dict[str, list[str]] = {}
    for domain in policy["domain"]:
        for number in domain["rfcs"]:
            rfc_domains.setdefault(number, []).append(domain["id"])
        for name in domain["local"]:
            local_domains.setdefault(name, []).append(domain["id"])
    return rfc_domains, local_domains


def milestones_for(domains: list[str], policy: dict) -> list[str]:
    selected = {
        milestone
        for domain in policy["domain"]
        if domain["id"] in domains
        for milestone in domain["milestones"]
    }
    return sorted(selected, key=milestone_key)


def milestone_key(value: str) -> tuple:
    historical = value.startswith("H")
    numeric = value[1:] if historical else value
    return (historical, *(int(part) for part in numeric.split(".")))
