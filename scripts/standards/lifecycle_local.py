"""Verified local document cache; outages never establish remote freshness."""
from __future__ import annotations

import os
from pathlib import Path
import re
import socket
import ssl
import stat
import threading
import urllib.error

import lifecycle_model as model
import lifecycle_network as network
import standards_lib as standards


CACHE = Path("references/local/authority-cache")


def safe(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise model.LifecycleError("symlinked local authority document")
    return path


def read_verified(path: Path, digest: str, maximum: int) -> bytes:
    safe(path)
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
            raise model.LifecycleError("local authority document is non-regular or oversized")
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
    except OSError as error:
        raise model.LifecycleError(f"local authority document unavailable: {path.name}") from error
    if len(data) > maximum:
        raise model.LifecycleError("local authority document grew past its bound")
    standards.verify_sha256(data, digest, path.name)
    return data


def cache_path(root: Path, row: dict) -> Path:
    digest = row["content_sha256"]
    if not isinstance(digest, str) or standards.SHA256_PATTERN.fullmatch(digest) is None:
        raise model.LifecycleError("invalid local authority digest")
    return safe(root / CACHE / (digest + ".document"))


def source_path(root: Path, row: dict) -> Path:
    identifier = row["id"]
    kind, name = identifier.split(":", 1)
    if kind == "rfc" and name.isascii() and name.isdigit():
        return safe(root / "rfc" / ("rfc" + name + ".txt"))
    if kind == "iana" and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
        return safe(root / "standards/snapshots/iana" / (name + ".xml"))
    if kind in {"itu", "nist", "riscv"} and Path(name).name == name and name.endswith(".pdf"):
        return safe(root / "references/local" / name)
    raise model.LifecycleError(f"no reviewed local source mapping: {identifier}")


def prepare(register: dict, policy: dict, root: Path = model.ROOT) -> int:
    """Copy only already verified local sources; never download or repin bytes."""
    maximum = policy["monitor"]["document_max_bytes"]
    directory = safe(root / CACHE)
    directory.mkdir(parents=True, exist_ok=True)
    for row in register["authorities"]:
        path = cache_path(root, row)
        if path.exists():
            read_verified(path, row["content_sha256"], maximum)
            continue
        data = read_verified(source_path(root, row), row["content_sha256"], maximum)
        # Exclusive creation: no replacement of previously reviewed local bytes.
        with path.open("xb") as stream:
            stream.write(data)
        read_verified(path, row["content_sha256"], maximum)
    return len(register["authorities"])


def is_outage(error: Exception) -> bool:
    if isinstance(error, urllib.error.HTTPError):
        return error.code in {408, 429} or 500 <= error.code <= 599
    if isinstance(error, ssl.SSLError):
        return False
    if isinstance(error, urllib.error.URLError):
        return isinstance(error.reason, Exception) and is_outage(error.reason)
    return isinstance(error, (TimeoutError, ConnectionError, socket.gaierror))


class LocalObserver:
    """Exact-content-only fallback; lifecycle metadata remains independently checked."""

    def __init__(self, register: dict, policy: dict, root: Path = model.ROOT,
                 fetcher=network.fetch_exact):
        self.fetcher = fetcher
        self.documents: dict[str, tuple[dict, bytes]] = {}
        self.offline: dict[str, dict] = {}
        self.lock = threading.Lock()
        maximum = policy["monitor"]["document_max_bytes"]
        for row in register["authorities"]:
            data = read_verified(cache_path(root, row), row["content_sha256"], maximum)
            url = row["content_url"]
            if url in self.documents:
                raise model.LifecycleError("ambiguous local authority URL")
            self.documents[url] = (row, data)

    def fetch(self, url: str, maximum: int) -> bytes:
        try:
            return self.fetcher(url, maximum)
        except Exception as error:
            if url not in self.documents or not is_outage(error):
                raise
            row, data = self.documents[url]
            if len(data) > maximum:
                raise model.LifecycleError("local authority exceeds request bound") from error
            with self.lock:
                self.offline[row["id"]] = {
                    "authority": row["id"], "content_url": url,
                    "local_sha256": row["content_sha256"], "error": str(error),
                    "remote_freshness": "unverified", "basis": "verified-local-document",
                }
            return data

    def annotate(self, result: dict) -> dict:
        result = {**result, "offline_documents": [self.offline[key] for key in sorted(self.offline)]}
        if self.offline and result["result"] == "PASS":
            result["result"] = "PASS WITH VERIFIED LOCAL DOCUMENTS"
        return result


def permits_release(result: dict) -> bool:
    return result["result"] in {"PASS", "PASS WITH VERIFIED LOCAL DOCUMENTS"}


def permits_freshness(result: dict) -> bool:
    return result["result"] == "PASS" and not result.get("offline_documents")
