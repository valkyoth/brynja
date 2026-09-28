#!/usr/bin/env python3
"""Disposable Windows enclave/full-WER-dump experiment; public markers only."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import mmap
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid

import windows_enclave_lifecycle as enclave
import windows_minidump as dump
import windows_wer_probe as wer
from windows_protection_api import Windows, PTR, U32
from windows_protection_probe import ProbeError, layout, require

SIZE = 8192
ENCLAVE_SIZE = 0x10000000
SOURCES = ('assurance/windows-enclave-probe/synthetic.c',
           'assurance/windows-enclave-probe/dump.c',
           'scripts/cryptography/windows_enclave_dump.py',
           'scripts/cryptography/test-windows-enclave-dump.py',
           'scripts/cryptography/windows_enclave_lifecycle.py',
           'scripts/cryptography/windows_wer_probe.py',
           'scripts/cryptography/windows_minidump.py',
           'scripts/cryptography/windows_protection_api.py',
           'scripts/cryptography/windows_protection_probe.py')


@contextmanager
def region(api, image):
    base = api.create()
    initialized = False
    try:
        loaded, error = api.load(base, image)
        require(loaded, f'enclave image load: Windows error {error}')
        api.initialize(base)
        initialized = True
        routine = api.check(api.GetProcAddress(base, b'PublicRegion'), 'region export')
        address = api.call(routine, 1)
        require(base <= address <= base + ENCLAVE_SIZE - SIZE, 'region outside enclave')
        require(api.call(routine, 2) == SIZE, 'enclave internal marker verification')
        require(api.call(routine, 3) == SIZE, 'enclave clear/readback preflight')
        require(api.call(routine, 1) == address, 'enclave region identity changed')
        require(api.call(routine, 2) == SIZE, 'enclave refill verification')
        yield address
        require(api.call(routine, 3) == SIZE, 'enclave normal-return clearing')
    finally:
        try:
            if initialized:
                api.terminate(base)
        finally:
            api.delete(base)


def validate_target(target, pid):
    require(type(target) is dict and type(pid) is int and pid > 0 and target.get('pid') == pid,
            'child identity mismatch')
    require(target.get('size') == SIZE and target.get('internal_verification') is True,
            'complete internal verification required')
    require(target.get('clear_preflight') is True, 'clear/readback preflight required')
    require(target.get('native_machine') in ('0x8664', '0xaa64'), 'native machine required')
    for key in ('control', 'enclave'):
        address = target.get(key)
        require(type(address) is int and 0 < address <= (1 << 64) - SIZE, 'bounded address')
    require(abs(target['control'] - target['enclave']) >= SIZE, 'distinct positive control required')


def child(image):
    require(wer.APP.fullmatch(Path(sys.executable).name.lower()) is not None,
            'crash child must use its unique disposable executable')
    api = Windows()
    api.bind('RaiseFailFastException', None, [PTR, PTR, U32])
    page, granularity = api.geometry()
    shape = layout(page, granularity, SIZE)
    require(shape.payload == SIZE, 'exact synthetic payload size')
    with wer.mapping(api, shape, 0x5a, False) as control:
        with region(enclave.Native(), image) as address:
            target = {'pid': os.getpid(), 'enclave': address, 'control': control,
                      'size': SIZE, 'internal_verification': True, 'clear_preflight': True,
                      'native_machine': api.native_machine}
            validate_target(target, os.getpid())
            print(json.dumps(target), flush=True)
            api.dll.RaiseFailFastException(None, None, 0)
            raise ProbeError('RaiseFailFastException unexpectedly returned')


def analyze(blob, target):
    validate_target(target, target.get('pid'))
    control = dump.observe(blob, target['control'], SIZE, 0x5a)
    require(control['complete_marker'], 'positive control absent/corrupt: inconclusive')
    observation = dump.observe(blob, target['enclave'], SIZE, 0xa5)
    return {'control': control, 'enclave_region': observation,
            'enclave_region_absent_in_this_dump': observation['included_bytes'] == 0}


def run_child(executable, source, image):
    names = {'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE', 'LOCALAPPDATA',
             'APPDATA', 'PROGRAMDATA', 'SYSTEMDRIVE'}
    environment = {key: value for key, value in os.environ.items() if key.upper() in names}
    with subprocess.Popen([str(executable), str(source), str(image), '--synthetic-crash-child'],
                          env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True) as process:
        try:
            output, errors = process.communicate(timeout=90)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=10)
            raise ProbeError('synthetic enclave crash child exceeded 90 seconds') from None
        # STATUS_FAIL_FAST_EXCEPTION, not an arbitrary setup or loader failure.
        require(process.returncode is not None and
                process.returncode & 0xffffffff == 0xc0000602, 'expected fail-fast exit required')
        require(not errors and len(output) < 4096, 'child setup/diagnostic failure')
        target = json.loads(output)
        validate_target(target, process.pid)
        return target, process.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--allow-app-local-dump', action='store_true')
    parser.add_argument('--synthetic-crash-child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    image = args.image.resolve()
    require(image.suffix.lower() == '.dll' and image.is_file() and
            0 < image.stat().st_size <= 4 * 1024 * 1024, 'bounded existing enclave DLL required')
    if args.synthetic_crash_child:
        child(image)
        return
    require(args.allow_app_local_dump, 'explicit --allow-app-local-dump approval required')
    Windows()
    import winreg
    source = Path(__file__).resolve()
    root = source.parents[2]
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'clean checkout required')
    image_hash = hashlib.sha256(image.read_bytes()).hexdigest()
    sources = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCES}
    executable = Path(sys.executable).with_name('brynja-wer-' + uuid.uuid4().hex + '.exe')
    output = executable.open('xb')
    try:
        with output, open(sys.executable, 'rb') as original:
            shutil.copyfileobj(original, output)
        with tempfile.TemporaryDirectory(prefix='brynja-enclave-dump-') as directory:
            folder = Path(directory)
            with wer.application_policy(winreg, executable.name, folder):
                target, exitcode = run_child(executable, source, image)
            files = list(folder.glob(executable.name + '.' + str(target['pid']) + '.dmp'))
            require(len(files) == 1, 'exactly one child dump required; no dump is inconclusive')
            require(32 <= files[0].stat().st_size <= dump.LIMIT, 'bounded dump size')
            dump_size = files[0].stat().st_size
            with files[0].open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as blob:
                observation = analyze(blob, target)
    finally:
        executable.unlink()
    require(image_hash == hashlib.sha256(image.read_bytes()).hexdigest(), 'image changed during experiment')
    require(sources == {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCES},
            'sources changed during experiment')
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'checkout became dirty')
    print(json.dumps({'schema': 1, 'kind': 'windows-enclave-full-local-dump-experiment',
                      'status': 'OBSERVATIONS_ONLY', 'strict_qualified': False,
                      'production_signed': False, 'synthetic_only': True,
                      'commit': commit, 'source_sha256': sources, 'image_sha256': image_hash,
                      'native_machine': target['native_machine'], 'os': sys.getwindowsversion().build,
                      'internal_verification': True, 'clear_preflight': True,
                      'child_exit_code': exitcode, 'dump_size': dump_size,
                      'app_policy_removed': True, 'raw_dump_removed': True,
                      'copied_executable_removed': True, 'observations': observation},
                     indent=2, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('WINDOWS_ENCLAVE_DUMP: FAILED: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
