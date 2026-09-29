#!/usr/bin/env python3
"""Opt-in active Rust-host WER experiment. Public data; not qualification."""
import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone

import windows_enclave_native_host_run as host
import windows_minidump as dump
import windows_wer_probe as wer
from windows_protection_probe import require


def validate_target(value, pid, event):
    require(type(value) is dict and set(value) == {'pid', 'base', 'window', 'control', 'staging',
                                                'event', 'locked_pages', 'epoch'}, 'exact checkpoint fields')
    require(all(type(v) is int for v in value.values()), 'integer checkpoint fields')
    require(pid > 0 and value['pid'] == pid and event in (2, 3) and value['event'] == event
            and value['locked_pages'] == 16 and value['epoch'] == 1, 'checkpoint identity/phase/locks')
    base, window, control, staging = (value[k] for k in ('base', 'window', 'control', 'staging'))
    require(0 < base <= 2**64 - 0x10000000 and base % 65536 == 0, 'bounded enclave base')
    require(base + 4096 <= window <= base + 0x10000000 - 65536 - 4096 and window % 4096 == 0,
            'complete guarded window')
    require(0 < control <= 2**64 - 8192 and 0 < staging <= 2**64 - 32, 'bounded host controls')
    for address, size in ((control, 8192), (staging, 32)):
        require(address + size <= base or address >= base + 0x10000000, 'control must be outside enclave')
    require(control + 8192 <= staging or staging + 32 <= control, 'disjoint host controls')


def analyze(blob, target):
    validate_target(target, target.get('pid'), target.get('event'))
    ranges = dump.memory_ranges(blob)
    control = dump.observe(blob, target['control'], 8192, 0x5a)
    require(control['complete_marker'], 'complete ordinary positive control required; otherwise inconclusive')
    expected = bytes(32) if target['event'] == 2 else hashlib.sha256(b'').digest()
    staging = bytearray(32)
    covered = 0
    for start, size, offset in ranges:
        low, high = max(start, target['staging']), min(start + size, target['staging'] + 32)
        if low < high:
            staging[low-target['staging']:high-target['staging']] = blob[offset+low-start:offset+high-start]
            covered += high-low
    require(covered == 32 and bytes(staging) == expected, 'public Rust staging control absent or wrong')
    window_bytes = 0
    enclave_bytes = 0
    for start, size, _ in ranges:
        window_bytes += max(0, min(start+size, target['window']+65536)-max(start, target['window']))
        enclave_bytes += max(0, min(start+size, target['base']+0x10000000)-max(start, target['base']))
    return {'ordinary_control': control, 'public_staging_complete': True,
            'window_included_bytes': window_bytes, 'enclave_reservation_included_bytes': enclave_bytes,
            'window_absent_in_this_dump': window_bytes == 0,
            'enclave_reservation_absent_in_this_dump': enclave_bytes == 0}


def child(executable, image, event):
    names = {'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE', 'LOCALAPPDATA',
             'APPDATA', 'PROGRAMDATA', 'SYSTEMDRIVE'}
    environment = {k: v for k, v in os.environ.items() if k.upper() in names}
    with subprocess.Popen([str(executable), str(image), str(event)], env=environment,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
        try:
            output, errors = process.communicate(timeout=90)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=10)
            raise RuntimeError('owned dump child exceeded 90 seconds') from None
        require(process.returncode is not None and process.returncode & 0xffffffff == 0xc0000602,
                'expected fail-fast exit required')
        require(not errors and len(output) < 4096, 'checkpoint output bounded and clean')
        value = json.loads(output)
        validate_target(value, process.pid, event)
        return value, process.returncode


def run(executable, image, event):
    import winreg
    root = Path(__file__).resolve().parents[2]
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'clean source required')
    records = {}
    for name in ('host-build.json', 'dump-build.json'):
        records[name] = json.loads((executable.parent / name).read_text())
    sources = records['host-build.json']['source_sha256'] | records['dump-build.json']['source_sha256']
    for path, expected in sources.items():
        require(hashlib.sha256((root / path).read_bytes()).hexdigest() == expected, 'source binding: ' + path)
    for name, expected in records['host-build.json']['archives'].items():
        require(hashlib.sha256((executable.parent / name).read_bytes()).hexdigest() == expected, 'archive binding')
    require(hashlib.sha256((executable.parent / 'native_host_transport.c').read_bytes()).hexdigest()
            == records['dump-build.json']['instrumented_transport_sha256'], 'instrumented callback binding')
    require(hashlib.sha256(image.read_bytes()).hexdigest() == host.IMAGE_SHA256, 'unchanged enclave image')
    executable_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='brynja-active-host-dump-') as temporary:
        folder = Path(temporary)
        copied = folder / ('brynja-wer-' + uuid.uuid4().hex + '.exe')
        with copied.open('xb') as output, executable.open('rb') as original:
            shutil.copyfileobj(original, output)
        with wer.application_policy(winreg, copied.name, folder):
            target, exitcode = child(copied, image, event)
        files = list(folder.glob(copied.name + '.' + str(target['pid']) + '.dmp'))
        require(len(files) == 1, 'exactly one child dump; absence is inconclusive')
        size = files[0].stat().st_size
        require(32 <= size <= dump.LIMIT, 'bounded full dump')
        with files[0].open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as blob:
            observation = analyze(blob, target)
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'source checkout changed')
    for path, expected in sources.items():
        require(hashlib.sha256((root / path).read_bytes()).hexdigest() == expected, 'source changed: ' + path)
    require(hashlib.sha256(image.read_bytes()).hexdigest() == host.IMAGE_SHA256, 'enclave image changed')
    require(hashlib.sha256(executable.read_bytes()).hexdigest() == executable_hash, 'host executable changed')
    return {'synthetic_only': True, 'strict_qualified': False, 'destructor_cleanup_claimed': False,
            'commit': commit, 'captured_at': datetime.now(timezone.utc).isoformat(),
            'event': event, 'exit_code': exitcode, 'dump_size': size, 'observations': observation,
            'app_policy_removed': True, 'raw_dump_removed': True, 'copied_executable_removed': True,
            'image_sha256': host.IMAGE_SHA256, 'executable_sha256': executable_hash,
            'build_records': records}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable', type=Path)
    parser.add_argument('image', type=Path)
    parser.add_argument('event', type=int, choices=(2, 3))
    parser.add_argument('--allow-app-local-dump', action='store_true')
    args = parser.parse_args()
    require(args.allow_app_local_dump, 'explicit --allow-app-local-dump required')
    print(json.dumps(run(args.executable.resolve(), args.image.resolve(), args.event), indent=2, sort_keys=True))
