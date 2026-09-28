#!/usr/bin/env python3
"""Opt-in disposable-host WER crash experiment. Synthetic data ONLY.

Creates a unique copy of python.exe and its own LocalDumps application subkey.
Never modifies global settings or an existing application key. Raw dumps stay
in a temporary local directory and are deleted, not printed or collected.
"""
import argparse
from contextlib import contextmanager, ExitStack
import ctypes as c
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import uuid

import windows_minidump as dump
from windows_protection_api import Windows, PTR, U32
from windows_protection_probe import ProbeError, layout, locked_pages, require

APP = re.compile(r'brynja-wer-[0-9a-f]{32}\.exe')
REGISTRY = r'SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'


@contextmanager
def application_policy(registry, name, folder):
    require(APP.fullmatch(name) is not None, 'unique probe application name required')
    path = REGISTRY + '\\' + name
    try:
        existing = registry.OpenKey(registry.HKEY_LOCAL_MACHINE, path)
    except FileNotFoundError:
        pass
    else:
        registry.CloseKey(existing)
        raise ProbeError('refusing to replace existing LocalDumps application policy')
    key = registry.CreateKeyEx(registry.HKEY_LOCAL_MACHINE, path, 0, registry.KEY_WRITE)
    try:
        registry.SetValueEx(key, 'DumpFolder', 0, registry.REG_EXPAND_SZ, str(folder))
        registry.SetValueEx(key, 'DumpType', 0, registry.REG_DWORD, 2)
        registry.SetValueEx(key, 'DumpCount', 0, registry.REG_DWORD, 1)
        yield
    finally:
        registry.CloseKey(key)
        registry.DeleteKey(registry.HKEY_LOCAL_MACHINE, path)


@contextmanager
def mapping(api, shape, value, excluded):
    base = api.reserve(shape.reserved)
    address = base + shape.page
    committed = locked = registered = False
    try:
        api.commit(address, shape.payload)
        committed = True
        api.check_regions(base, address, shape)
        api.lock(address, shape.payload)
        locked = True
        flags = api.working_set(address, shape)
        require(len(flags) == shape.payload // shape.page, 'complete locked-page observation')
        locked_pages(flags)
        if excluded:
            api.register(address, shape.payload)
            registered = True
        api.fill(address, shape.payload, value)
        require(api.matches(address, shape.payload, value), 'synthetic marker readback')
        yield address
    finally:
        # Reached for setup errors/normal return, deliberately not on fail-fast.
        if committed:
            api.fill(address, shape.payload, 0)
            require(api.matches(address, shape.payload, 0), 'full synthetic mapping cleared')
        if registered:
            api.unregister(address)
        if locked:
            api.unlock(address, shape.payload)
        api.release(base)


def child():
    require(APP.fullmatch(Path(sys.executable).name.lower()) is not None,
            'crash child must use its unique disposable executable')
    api = Windows()
    api.bind('RaiseFailFastException', None, [PTR, PTR, U32])
    page, granularity = api.geometry()
    shape = layout(page, granularity, page + 1)
    with ExitStack() as stack:
        excluded = stack.enter_context(mapping(api, shape, 0xa5, True))
        control = stack.enter_context(mapping(api, shape, 0x5a, False))
        print(json.dumps({'pid': os.getpid(), 'excluded': excluded, 'control': control,
                          'size': shape.payload, 'native_machine': api.native_machine}), flush=True)
        api.dll.RaiseFailFastException(None, None, 0)
        raise ProbeError('RaiseFailFastException unexpectedly returned')


def analyze(blob, target):
    control = dump.observe(blob, target['control'], target['size'], 0x5a)
    require(control['complete_marker'], 'positive control absent/corrupt: exclusion is inconclusive')
    excluded = dump.observe(blob, target['excluded'], target['size'], 0xa5)
    return {'control': control, 'wer_registered_region': excluded,
            'registered_region_absent_in_this_dump': excluded['included_bytes'] == 0}


def run_child(executable, source):
    # Avoid inheriting unrelated tool credentials into the synthetic process dump.
    names = {'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE', 'LOCALAPPDATA',
             'APPDATA', 'PROGRAMDATA', 'SYSTEMDRIVE'}
    environment = {key: value for key, value in os.environ.items() if key.upper() in names}
    with subprocess.Popen([str(executable), str(source), '--synthetic-crash-child'],
                          env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True) as process:
        try:
            output, errors = process.communicate(timeout=90)
        except subprocess.TimeoutExpired:
            process.kill()  # Only the child created by this experiment.
            process.communicate(timeout=10)
            raise ProbeError('synthetic WER child exceeded 90 seconds') from None
        require(process.returncode != 0, 'expected deliberate crash did not occur')
        require(not errors and len(output) < 4096, 'child setup/diagnostic failure')
        target = json.loads(output)
        require(target['pid'] == process.pid, 'child identity mismatch')
        return target, process.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-app-local-dump', action='store_true')
    parser.add_argument('--synthetic-crash-child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.synthetic_crash_child:
        child()
        return
    require(args.allow_app_local_dump, 'explicit --allow-app-local-dump approval required')
    Windows()  # Reject unsupported hosts before copying files or changing registry.
    import winreg
    source = Path(__file__).resolve()
    root = source.parents[2]
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'clean checkout required')
    executable = Path(sys.executable).with_name('brynja-wer-' + uuid.uuid4().hex + '.exe')
    # Exclusive creation, adjacent to Python's DLL/stdlib; never overwrite an executable.
    output = executable.open('xb')
    try:
        with output, open(sys.executable, 'rb') as original:
            shutil.copyfileobj(original, output)
        with tempfile.TemporaryDirectory(prefix='brynja-wer-dump-') as directory:
            folder = Path(directory)
            with application_policy(winreg, executable.name, folder):
                target, exitcode = run_child(executable, source)
            files = list(folder.glob(executable.name + '.' + str(target['pid']) + '.dmp'))
            require(len(files) == 1, 'exactly one child crash dump required; no dump is not exclusion')
            require(32 <= files[0].stat().st_size <= dump.LIMIT, 'bounded dump size')
            with files[0].open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as blob:
                observation = analyze(blob, target)
    finally:
        executable.unlink()
    sources = {name: hashlib.sha256(source.with_name(name).read_bytes()).hexdigest()
               for name in ('windows_wer_probe.py', 'windows_minidump.py',
                            'windows_protection_api.py', 'windows_protection_probe.py')}
    print(json.dumps({'schema': 1, 'kind': 'windows-wer-local-dump-experiment',
                      'status': 'OBSERVATIONS_ONLY', 'strict_qualified': False,
                      'commit': commit, 'source_sha256': sources,
                      'native_machine': target['native_machine'], 'os': sys.getwindowsversion().build,
                      'child_exit_code': exitcode, 'app_policy_removed': True,
                      'raw_dump_removed': True, 'copied_executable_removed': True,
                      'observations': observation}, indent=2, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('WINDOWS_WER_PROBE: FAILED: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
