"""Public-only overlapping VBS entry probe; not ParallelHash qualification."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time

from windows_enclave_lifecycle import InitInfo, Native
from windows_protection_probe import require

ROOT = Path(__file__).resolve().parents[2]
INVALID = (1 << 64) - 1
SOURCES = ('assurance/windows-enclave-probe/concurrent_entry.c',
           'scripts/cryptography/windows_enclave_concurrent.py',
           'scripts/cryptography/test-windows-enclave-concurrent.py',
           'scripts/cryptography/test-windows-enclave-concurrent-c.py',
           'scripts/cryptography/windows_enclave_lifecycle.py',
           'scripts/cryptography/windows_protection_api.py',
           'scripts/cryptography/windows_protection_probe.py')


class ConcurrentNative(Native):
    def initialize(self, base):
        info = InitInfo(8, 5)
        self.check(self.InitializeEnclave(self.GetCurrentProcess(), base,
                                         c.byref(info), 8, None), 'initialize five threads')
        return info.threads

    def export(self, base, name):
        return self.check(self.GetProcAddress(base, name), 'concurrent export')


def exercise(api, image, deadline_seconds=10):
    base = api.create()
    initialized = False
    workers = []
    control = None
    results = [None] * 4
    failures = [None] * 4

    def worker(lane):
        try:
            results[lane] = api.call(entry, lane)
        except Exception as error:
            failures[lane] = str(error)

    try:
        loaded, error = api.load(base, image)
        require(loaded, f'concurrent image load: {error}')
        count = api.initialize(base)
        initialized = True
        require(count == 5, 'exactly five initialized enclave threads required')
        entry = api.export(base, b'PublicConcurrentWorker')
        control = api.export(base, b'PublicConcurrentControl')
        require(api.call(entry, INVALID) == INVALID, 'invalid worker lane must reject')
        require(api.call(control, INVALID) == INVALID, 'invalid control query must reject')
        for lane in range(4):
            thread = threading.Thread(target=worker, args=(lane,), daemon=True)
            thread.start()
            workers.append(thread)
        deadline = time.monotonic() + deadline_seconds
        while True:
            mask = api.call(control, 0)
            require(mask & ~15 == 0, 'invalid active worker mask')
            if mask == 15:
                break
            require(time.monotonic() < deadline and not any(failures),
                    'four live enclave entries did not overlap')
            time.sleep(0.01)
        require(api.call(entry, 0) == INVALID, 'duplicate live lane must reject')
        require(api.call(control, 2) == 0, 'workers returned before controller release')
        require(api.call(control, 1) == 1, 'controller release acknowledgement')
        for thread in workers:
            thread.join(max(0, deadline - time.monotonic()))
        require(not any(thread.is_alive() for thread in workers), 'workers did not join')
        require(not any(failures) and results == [100, 101, 102, 103], 'worker results')
        require(api.call(control, 0) == 0 and api.call(control, 2) == 15
                and api.call(control, 3) == 0, 'complete non-exhausted worker accounting')
        require(api.call(entry, 0) == INVALID, 'completed lane replay must reject')
    finally:
        try:
            if control is not None:
                api.call(control, 1)
        finally:
            deadline = time.monotonic() + deadline_seconds
            for thread in workers:
                thread.join(max(0, deadline - time.monotonic()))
            # Never unmap an image while a host call is still inside it. The
            # bounded parent kills a failed child with live daemon workers.
            require(not any(thread.is_alive() for thread in workers),
                    'live workers: refusing unsafe enclave deletion')
            try:
                if initialized:
                    api.terminate(base)
            finally:
                api.delete(base)
    return dict(initialized_threads=count, overlapping_worker_mask=mask,
                results=results, joined=True, deleted=True, synthetic_only=True,
                production_qualified=False, cryptographic_execution_tested=False)


def build(directory):
    directory.mkdir()
    shutil.copyfile(ROOT / SOURCES[0], directory / 'concurrent_entry.c')
    (directory / 'link.cmd').write_text('@echo off\nsetlocal\n'
        'if "%VCToolsInstallDir%"=="" exit /b 90\ncd /d "%~dp0"\n'
        'cl /nologo /std:c11 /LD /O2 /W4 /WX /MT /guard:cf /Foconcurrent.obj '
        '/Fenormal.dll concurrent_entry.c /link /ENCLAVE /NODEFAULTLIB '
        '/INCREMENTAL:NO /INTEGRITYCHECK /GUARD:MIXED '
        '/LIBPATH:"%VCToolsInstallDir%lib\\x64\\enclave" '
        '/LIBPATH:"%WindowsSdkDir%Lib\\%WindowsSDKVersion%ucrt_enclave\\x64" '
        'libcmt.lib libvcruntime.lib ucrt.lib vertdll.lib\n'
        'if errorlevel 1 exit /b 1\n'
        '"%WindowsSdkDir%bin\\%WindowsSDKVersion%x64\\veiid.exe" normal.dll\n'
        'exit /b %ERRORLEVEL%\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--build', action='store_true')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(not (args.build and args.child), 'separate build and capture')
    if args.build:
        build(args.image.resolve())
        return
    image = args.image.resolve(strict=True)
    require(image.suffix.lower() == '.dll' and 0 < image.stat().st_size < 4 * 1024 * 1024,
            'bounded diagnostic DLL required')
    if args.child:
        api = ConcurrentNative()
        require(api.machine == '0x8664', 'native x64 probe only')
        print(json.dumps(exercise(api, image)))
        return
    before = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    result = subprocess.run([sys.executable, str(Path(__file__).resolve()), str(image), '--child'],
                            capture_output=True, text=True, timeout=45)
    require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) < 4096,
            'clean bounded concurrency child required: ' + result.stderr[-2048:])
    record = json.loads(result.stdout)
    require(record == dict(initialized_threads=5, overlapping_worker_mask=15,
                           results=[100, 101, 102, 103], joined=True, deleted=True,
                           synthetic_only=True, production_qualified=False,
                           cryptographic_execution_tested=False), 'complete concurrency record')
    require(before == {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}
            and digest == hashlib.sha256(image.read_bytes()).hexdigest(), 'probe inputs changed')
    record.update(schema=1, status='OBSERVATIONS_ONLY', source_sha256=before,
                  image_sha256=digest, windows_build=sys.getwindowsversion().build)
    print(json.dumps(record, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
