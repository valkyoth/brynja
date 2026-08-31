#!/usr/bin/env python3
"""Bounded network observations for the authority lifecycle register."""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import stat
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from pathlib import Path

import lifecycle_model as model
import standards_lib as standards


MAX_WORKERS = 8
TIMEOUT_SECONDS = 60
RFC_INDEX_URL = "https://www.rfc-editor.org/rfc-index.xml"


class ExactRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects because every observed identity is exact."""

    def redirect_request(self, request, fp, code, msg, headers, new_url):
        raise model.LifecycleError(
            f"redirect-rejected: {request.full_url} -> {new_url}"
        )


OPENER = urllib.request.build_opener(ExactRedirectHandler())


class VisibleTextParser(HTMLParser):
    """Project stable visible publication text, excluding active content."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hidden = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in {"script", "style", "svg", "template"}:
            self.hidden += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "svg", "template"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data: str) -> None:
        if not self.hidden:
            text = " ".join(data.split())
            if text:
                self.parts.append(text)


def landing_projection(data: bytes, url: str = "") -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    parser = VisibleTextParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception as error:
        raise model.LifecycleError("malformed landing page HTML") from error
    parts = parser.parts
    if urllib.parse.urlsplit(url).hostname == "csrc.nist.gov":
        publication_markers = [
            index
            for index, line in enumerate(parts)
            if line == "Publications"
        ]
        marker = publication_markers[-1] if publication_markers else -1
        starts = [
            index
            for index, line in enumerate(parts)
            if index > marker and re.fullmatch(r"(?:NIST )?(?:FIPS|SP) [0-9].*", line)
        ]
        if not starts:
            raise model.LifecycleError("malformed NIST publication identity")
        start = starts[0]
        end = next(
            (index for index in range(start + 1, len(parts)) if parts[index] == "HEADQUARTERS"),
            len(parts),
        )
        parts = parts[start:end]
    projected = "\n".join(parts).encode()
    if len(projected) < 20:
        raise model.LifecycleError("malformed landing page has no bounded visible identity")
    return projected


def fetch_exact(url: str, max_bytes: int) -> bytes:
    standards.validate_https_url(url)
    if max_bytes <= 0:
        raise model.LifecycleError("fetch bound must be positive")
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "brynja-standards-lifecycle/0.24.5 (+https://github.com/valkyoth/brynja)"},
    )
    try:
        response = OPENER.open(request, timeout=TIMEOUT_SECONDS)
    except urllib.error.HTTPError as error:
        if 300 <= error.code < 400:
            raise model.LifecycleError(f"redirect-rejected: {url}") from error
        raise
    with response:
        if response.status != 200 or response.geturl() != url:
            raise model.LifecycleError(f"redirect-rejected: {url}")
        declared = response.headers.get("Content-Length")
        if declared is not None:
            try:
                size = int(declared)
            except ValueError as error:
                raise model.LifecycleError(f"malformed Content-Length: {url}") from error
            if size < 0 or size > max_bytes:
                raise model.LifecycleError(f"oversized: {url}")
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise model.LifecycleError(f"oversized: {url}")
    return data


def error_state(error: Exception) -> str:
    text = str(error).lower()
    if "redirect-rejected" in text:
        return "redirect-rejected"
    if "oversized" in text:
        return "oversized"
    if "malformed" in text or "parse" in text or "doctype" in text:
        return "malformed"
    return "unavailable"


def landing_candidate(policy: dict, fetcher=fetch_exact) -> dict:
    urls = sorted({item["landing_url"] for item in policy["local"]})
    result = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(fetcher, url, policy["monitor"]["landing_max_bytes"]): url
            for url in urls
        }
        for future in as_completed(futures):
            url = futures[future]
            try:
                data = future.result()
            except Exception as error:
                raise model.LifecycleError(f"landing capture failed for {url}: {error}") from error
            try:
                projected = landing_projection(data, url)
            except Exception as error:
                raise model.LifecycleError(f"landing projection failed for {url}: {error}") from error
            result[url] = {
                "projection": "visible-text-v1",
                "sha256": standards.sha256(projected),
                "size": len(projected),
            }
    return {
        "landings": result,
        "observed_at": policy["monitor"]["baseline_observed_at"],
        "schema": 1,
    }


def content_observations(register: dict, policy: dict, fetcher=fetch_exact) -> list[dict]:
    rows = register["authorities"]
    maximum = policy["monitor"]["document_max_bytes"]
    observations = []

    def inspect(row: dict) -> tuple[dict, bytes]:
        return row, fetcher(row["content_url"], maximum)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(inspect, row): row for row in rows}
        for future in as_completed(futures):
            row = futures[future]
            try:
                _, data = future.result()
                digest = standards.sha256(data)
                if digest != row["content_sha256"]:
                    observations.append(
                        model.observation(row, "changed", f"content sha256 {digest}")
                    )
            except Exception as error:  # network and parser failures are evidence
                observations.append(model.observation(row, error_state(error), str(error)))
    return observations


def landing_observations(register: dict, policy: dict, fetcher=fetch_exact) -> list[dict]:
    rows_by_url: dict[str, list[dict]] = {}
    for row in register["authorities"]:
        if row["landing_channel"] == "bounded-page-sha256":
            rows_by_url.setdefault(row["landing_url"], []).append(row)
    observations = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(fetcher, url, policy["monitor"]["landing_max_bytes"]): url
            for url in rows_by_url
        }
        for future in as_completed(futures):
            url = futures[future]
            try:
                data = future.result()
                digest = standards.sha256(landing_projection(data, url))
                for row in rows_by_url[url]:
                    if digest != row["metadata"]["landing_sha256"]:
                        observations.append(
                            model.observation(row, "changed", f"landing sha256 {digest}")
                        )
            except Exception as error:
                for row in rows_by_url[url]:
                    observations.append(model.observation(row, error_state(error), str(error)))
    return observations


def rfc_index_observations(register: dict, policy: dict, fetcher=fetch_exact) -> list[dict]:
    rows = [row for row in register["authorities"] if row["id"].startswith("rfc:")]
    numbers = {int(row["id"].split(":", 1)[1]) for row in rows}
    try:
        data = fetcher(RFC_INDEX_URL, standards.MAX_RFC_INDEX_BYTES)
        projection = standards.project_rfc_index(data, numbers)["rfcs"]
    except Exception as error:
        return [model.observation(row, error_state(error), str(error)) for row in rows]
    observations = []
    for row in rows:
        current = projection[row["id"].split(":", 1)[1]]
        expected = row["metadata"]
        observed = {
            "current_status": current["current_status"],
            "updated_by": current["updated_by"],
        }
        replacements = current["obsoleted_by"]
        if observed != {key: expected[key] for key in observed} or replacements != row["replacements"]:
            observations.append(
                model.observation(row, "changed", f"RFC lifecycle metadata {json.dumps(current, sort_keys=True)}")
            )
    return observations


def errata_observations(register: dict, policy: dict, fetcher=fetch_exact) -> list[dict]:
    rows = {int(row["id"].split(":", 1)[1]): row for row in register["authorities"] if row["id"].startswith("rfc:")}

    def inspect(number: int) -> tuple[int, list[dict]]:
        data = fetcher(standards.errata_url(number), standards.MAX_ERRATA_BYTES)
        return number, standards.parse_errata(data, number)

    results: dict[int, list[dict]] = {}
    observations = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(inspect, number): number for number in rows}
        for future in as_completed(futures):
            number = futures[future]
            try:
                key, records = future.result()
                results[key] = records
            except Exception as error:
                observations.append(model.observation(rows[number], error_state(error), str(error)))
    for number, records in results.items():
        observed = [
            {
                "disposition": standards.errata_disposition(record["status"])[0],
                "id": record["id"],
                "status": record["status"],
            }
            for record in records
        ]
        if observed != rows[number]["metadata"]["errata"]:
            observations.append(
                model.observation(rows[number], "changed", f"RFC {number} errata changed")
            )
    return observations


def observe(register: dict, policy: dict, fetcher=fetch_exact) -> list[dict]:
    observations = content_observations(register, policy, fetcher)
    observations += landing_observations(register, policy, fetcher)
    observations += rfc_index_observations(register, policy, fetcher)
    observations += errata_observations(register, policy, fetcher)
    return sorted(observations, key=lambda item: (item["authority"], item["state"], item["detail"]))


def artifact(register: dict, observations: list[dict], observed_at: str) -> dict:
    reviews = model.load_json(model.REVIEWS)
    unresolved = model.retain_unresolved(reviews["unresolved_observations"], observations)
    return {
        "observations": observations,
        "observed_at": observed_at,
        "register_sha256": standards.sha256(standards.json_bytes(register)),
        "result": "PASS" if not unresolved else "REVIEW REQUIRED",
        "schema": 1,
        "unresolved_observations": unresolved,
    }


def current_date() -> str:
    return dt.datetime.now(dt.timezone.utc).date().isoformat()


def write_new_json(path: Path, value: object) -> None:
    """Create one artifact exclusively without following a final symlink."""

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise model.LifecycleError(f"refusing existing artifact path: {path}") from error
    with os.fdopen(descriptor, "wb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise model.LifecycleError(f"artifact is not a regular file: {path}")
        handle.write(standards.json_bytes(value))
        handle.flush()
        os.fsync(handle.fileno())


def write_existing_json(path: Path, value: object) -> None:
    """Replace one repository-owned regular file without following a symlink."""

    try:
        original_mode = path.lstat().st_mode
    except OSError as error:
        raise model.LifecycleError(f"refusing unsafe repository path: {path}") from error
    if not stat.S_ISREG(original_mode):
        raise model.LifecycleError(f"repository evidence is not a regular file: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(standards.json_bytes(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, stat.S_IMODE(original_mode))
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
