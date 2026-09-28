#!/usr/bin/env python3
"""Synthetic host-side enclave locking experiment, not residency qualification."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from windows_enclave_dump import region, SIZE, SOURCES as DUMP_SOURCES
from windows_enclave_lifecycle import Native
from windows_protection_api import Windows, MemoryInfo, WorkingSet
from windows_protection_probe import require, layout
from windows_wer_probe import mapping

SOURCES = DUMP_SOURCES + ('scripts/cryptography/windows_enclave_residency.py',
                          'scripts/cryptography/test-windows-enclave-residency.py')


def pages(address, size, page):
    require(type(address) is int and type(size) is int and type(page) is int and
            0 < address <= (1 << 64) - size and size == SIZE and
            0 < page <= 65536 and page & (page - 1) == 0, 'bounded page geometry')
    first = address // page * page
    end = (address + size + page - 1) // page * page
    require(0 < (end - first) // page <= 16, 'bounded page count')
    return list(range(first, end, page))


def page_status(flags):
    require(type(flags) is int and 0 <= flags < 1 << 64, 'working-set flag bounds')
    valid = bool(flags & 1)
    # Locked is only meaningful in the Valid layout of the OS union.
    return {'raw_flags': flags, 'valid': valid,
            'locked': bool(flags & (1 << 22)) if valid else None}


class Host(Windows):
    def snapshot(self, address):
        page, _ = self.geometry()
        addresses = pages(address, SIZE, page)
        entries = (WorkingSet * len(addresses))()
        regions = []
        for entry, value in zip(entries, addresses):
            entry.address = value
            info = MemoryInfo()
            c.set_last_error(0)
            size = self.dll.VirtualQuery(value, c.byref(info), c.sizeof(info))
            error = c.get_last_error()
            require(size in (0, c.sizeof(info)), 'partial VirtualQuery result')
            regions.append({'success': bool(size), 'error': error if not size else 0,
                            'state': info.state if size else None,
                            'protect': info.protect if size else None})
        c.set_last_error(0)
        success = bool(self.dll.K32QueryWorkingSetEx(self.dll.GetCurrentProcess(), entries, c.sizeof(entries)))
        error = c.get_last_error()
        return {'page_count': len(addresses), 'regions': regions,
                'working_set_success': success, 'working_set_error': error if not success else 0,
                'pages': [page_status(entry.flags) for entry in entries] if success else []}

    def attempt_lock(self, address):
        c.set_last_error(0)
        success = bool(self.dll.VirtualLock(address, SIZE))
        return {'success': success, 'error': c.get_last_error() if not success else 0}


def inspect_candidate(api, address):
    before = api.snapshot(address)
    result = api.attempt_lock(address)
    require(type(result) is dict and type(result.get('success')) is bool and
            type(result.get('error')) is int and 0 <= result['error'] <= 0xffffffff,
            'complete lock result')
    try:
        after = api.snapshot(address)
    finally:
        if result['success']:
            api.unlock(address, SIZE)
    return {'before': before, 'lock': result, 'after': after,
            'unlock_succeeded': True if result['success'] else None}


def exercise(image):
    api = Host()
    page, granularity = api.geometry()
    shape = layout(page, granularity, SIZE)
    require(shape.payload == SIZE, 'exact control size')
    with mapping(api, shape, 0x5a, False) as control:
        snapshot = api.snapshot(control)
        require(snapshot['working_set_success'] and len(snapshot['pages']) == SIZE // page
                and all(p['valid'] and p['locked'] for p in snapshot['pages']),
                'complete ordinary locked positive control required')
        with region(Native(), image) as address:
            candidate = inspect_candidate(api, address)
    return {'strict_qualified': False, 'production_signed': False, 'synthetic_only': True,
            'native_machine': api.native_machine, 'deleted': True,
            'ordinary_control': snapshot, 'enclave': candidate,
            'internal_marker_and_clear_preflight': True, 'normal_return_clearing': True}


def bounded(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 8192,
            'bounded clean residency child required: ' + result.stderr[-2048:])
    value = json.loads(result.stdout)
    require(type(value) is dict and value.get('strict_qualified') is False and
            value.get('production_signed') is False and value.get('synthetic_only') is True
            and value.get('deleted') is True, 'completed nonqualifying observation required')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    require(image.suffix.lower() == '.dll' and 0 < image.stat().st_size <= 4 * 1024 * 1024,
            'bounded existing synthetic image required')
    if args.child:
        print(json.dumps(exercise(image), sort_keys=True))
        return
    source = Path(__file__).resolve()
    root = source.parents[2]
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'clean checkout required')
    hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCES}
    image_hash = hashlib.sha256(image.read_bytes()).hexdigest()
    record = bounded([sys.executable, str(source), str(image), '--child'])
    require(image_hash == hashlib.sha256(image.read_bytes()).hexdigest(), 'image changed')
    require(hashes == {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCES},
            'sources changed')
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'checkout became dirty')
    record.update(schema=1, kind='windows-enclave-host-lock-experiment', status='OBSERVATIONS_ONLY',
                  commit=commit, source_sha256=hashes, image_sha256=image_hash,
                  os=sys.getwindowsversion().build)
    print(json.dumps(record, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
