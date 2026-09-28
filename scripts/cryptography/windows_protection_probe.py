#!/usr/bin/env python3
"""Synthetic Windows OS experiment; never strict-profile qualification."""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys


class ProbeError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise ProbeError(message)


@dataclass(frozen=True)
class Layout:
    page: int
    payload: int
    reserved: int


def layout(page, granularity, requested):
    require(type(page) is int and 4096 <= page <= 65536 and page & (page - 1) == 0,
            'unsupported page geometry')
    require(type(granularity) is int and page <= granularity <= 1048576
            and granularity % page == 0, 'unsupported reservation geometry')
    require(type(requested) is int and 0 < requested <= 1048576,
            'probe payload must be between one byte and one MiB')
    payload = ((requested + page - 1) // page) * page
    reserved = ((payload + 2 * page + granularity - 1) // granularity) * granularity
    require(payload <= 0xffffffff and reserved <= 4 * 1048576, 'bounded OS sizes')
    return Layout(page, payload, reserved)


def locked_pages(flags):
    # PSAPI_WORKING_SET_EX_BLOCK: Valid bit 0; Locked bit 22.
    require(bool(flags), 'empty working-set observation')
    require(all(value & 1 and value & (1 << 22) for value in flags),
            'every payload page must be valid and locked')


def experiment(api):
    page, granularity = api.geometry()
    shape = layout(page, granularity, page + 1)
    base = api.reserve(shape.reserved)
    data = base + shape.page
    committed = locked = registered = False
    observations = None
    try:
        api.commit(data, shape.payload)
        committed = True
        api.check_regions(base, data, shape)
        api.lock(data, shape.payload)
        locked = True
        flags = api.working_set(data, shape)
        require(len(flags) == shape.payload // shape.page, 'complete page observation')
        locked_pages(flags)
        api.register(data, shape.payload)
        registered = True
        api.fill(data, shape.payload, 0xa5)
        require(api.matches(data, shape.payload, 0xa5), 'synthetic payload round-trip')
        # Re-observe after writes, not merely before touching the pages.
        after = api.working_set(data, shape)
        require(len(after) == len(flags), 'complete post-write page observation')
        locked_pages(after)
        observations = {'page_size': page, 'allocation_granularity': granularity,
                        'payload_bytes': shape.payload, 'reserved_bytes': shape.reserved,
                        'locked_pages_before': len(flags), 'locked_pages_after': len(after),
                        'reserved_guards_observed': True, 'wer_registration_succeeded': True}
    finally:
        # If clearing or exclusion removal fails, do not release/reuse the range.
        # This short-lived synthetic-only process will terminate; no retry/fallback.
        if committed:
            api.fill(data, shape.payload, 0)
            require(api.matches(data, shape.payload, 0), 'full payload clearing readback')
        if registered:
            api.unregister(data)
        if locked:
            api.unlock(data, shape.payload)
        api.release(base)
    return dict(observations, clearing_readback=True, release_succeeded=True)


def record(observations, identity):
    return {'schema': 1, 'kind': 'windows-protection-experiment',
            'status': 'OBSERVATIONS_ONLY', 'strict_qualified': False,
            'dump_exclusion_verified': False, 'protected_worker_stack_verified': False,
            'identity': identity, 'observations': observations}


def main():
    from windows_protection_api import Windows
    api = Windows()  # Reject other OSes/emulated process architectures before allocation.
    root = Path(__file__).resolve().parents[2]
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    dirty = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=root))
    sources = {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
               for name in ('windows_protection_probe.py', 'windows_protection_api.py')}
    identity = {'commit': commit, 'dirty': dirty, 'sources': sources,
                'python': sys.version, 'platform': platform.platform(),
                'native_machine': api.native_machine}
    result = record(experiment(api), identity)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print('WINDOWS_PROTECTION_PROBE: FAILED: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
