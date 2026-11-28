"""Serial crates.io transport. Retry explicit rate limits, not ambiguous writes."""
import json
import math
import re
import subprocess
import sys
import time
from datetime import datetime
from email.utils import parsedate_to_datetime
from urllib.error import HTTPError
from urllib.request import Request, urlopen


UPDATE, INITIAL = 120, 660
AGENT = 'brynja-release (https://github.com/valkyoth/brynja)'


def delay(seconds, reason):
    seconds = math.ceil(seconds)
    if seconds > 3600:
        raise RuntimeError(f'{reason}: wait requested exceeds one hour; rerun later to resume')
    if seconds > 0:
        print(f'{reason}: waiting {seconds}s (safe to interrupt and rerun).', flush=True)
        time.sleep(seconds)


def retry_seconds(hint, minimum):
    if not hint:
        return minimum
    if hint.strip().isascii() and hint.strip().isdigit():
        return max(minimum, int(hint.strip()))
    try:
        when = parsedate_to_datetime(hint)
        if when.tzinfo is not None:
            return max(minimum, math.ceil(when.timestamp() - time.time()))
    except (ValueError, OverflowError, TypeError):
        pass
    raise ValueError('unrecognized registry retry time; rerun later to resume')


def read(url, decode):
    request = Request(url, headers={'User-Agent': AGENT})
    for attempt in range(4):
        try:
            with urlopen(request, timeout=20) as response:
                return decode(response)
        except HTTPError as exc:
            if exc.code == 404:
                return None
            if exc.code != 429 or attempt == 3:
                raise
            delay(retry_seconds(exc.headers.get('Retry-After'), 60), 'Registry read limited')


class Pace:
    def __init__(self):
        self.next_upload = self.next_new = 0.0

    def recorded(self, initial, created=None):
        # On restart, count time since the actual registry publication, not
        # since this process discovered it.
        age = 0
        if created is not None:
            stamp = datetime.fromisoformat(created.replace('Z', '+00:00'))
            if stamp.tzinfo is None:
                raise ValueError('registry publication timestamp lacks timezone')
            age = max(0, time.time() - stamp.timestamp())
        at = time.monotonic() - age
        self.next_upload = max(self.next_upload, at + UPDATE)
        if initial:
            self.next_new = max(self.next_new, at + INITIAL)

    def wait(self, initial):
        deadline = max(self.next_upload, self.next_new if initial else 0)
        delay(deadline - time.monotonic(), 'Publication pacing')


class UploadLimited(RuntimeError):
    def __init__(self, hint):
        super().__init__('crates.io rate-limited this upload')
        self.hint = hint


def upload(command, root):
    print(f"+ {' '.join(command)}", flush=True)
    result = subprocess.run(command, cwd=root, stderr=subprocess.PIPE, text=True)
    print(result.stderr, end='', file=sys.stderr, flush=True)
    if result.returncode == 0:
        return
    # Do not resubmit for a dependency fetch, indexing failure, timeout or
    # generic Cargo error. Those can occur after the server accepted a write.
    error = result.stderr
    if (re.search(r'(?im)^error: failed to publish[^\n]*registry at https://crates\.io(?:/|\s|$)', error)
            and re.search(r'(?im)^\s*(?:failed to get a 200 OK response, got 429\b|'
                          r'the remote server responded with an error \(status 429\b)', error)):
        header = re.search(r'(?im)^\s*retry-after:\s*([^\r\n]+)', error)
        body = re.search(r'(?i)try again after ([A-Za-z]{3}, [^"\n]+? GMT)', error)
        raise UploadLimited((header or body)[1] if header or body else None)
    raise subprocess.CalledProcessError(result.returncode, command)


def wait_index(name, version, *, expected=None):
    # All Brynja package names have four or more characters.
    url = f'https://index.crates.io/{name[:2]}/{name[2:4]}/{name}'
    def active(stream):
        for line in stream:
            row = json.loads(line)
            if row['name'] != name:
                raise ValueError(f'unexpected index entry for {name}')
            if row['vers'] == version:
                if row['yanked'] is not False:
                    raise ValueError(f'{name} {version} is yanked')
                if expected is not None and row.get('cksum') != expected:
                    raise ValueError(f'{name} {version}: registry checksum differs from freshly packaged '
                                     'candidate or is missing; stop and reconcile the release')
                return True
        return False
    for attempt in range(31):
        if read(url, active):
            return
        if attempt < 30:
            delay(10, f'Waiting for {name} {version} in Cargo index')
    raise RuntimeError(f'{name} {version} not visible in Cargo index; rerun to resume')
