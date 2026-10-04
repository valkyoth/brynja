"""Opt-in current scheduler WER observations. Raw dumps never leave the guest.

Source-bound overlay diagnostic; does not claim a clean Git checkout, signature
qualification, secret absence elsewhere in the process, or fatal-path cleanup.
"""
import argparse
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

import windows_enclave_scheduler_dump_model as model
from windows_enclave_scheduler_dump_child import child
import windows_enclave_parallel_scheduler_native as scheduler
import windows_minidump as dump
import windows_wer_probe as wer
from windows_protection_api import Windows
from windows_protection_probe import require

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_child(executable, image, phase):
    names = {'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE', 'LOCALAPPDATA',
             'APPDATA', 'PROGRAMDATA', 'SYSTEMDRIVE'}
    environment = {key: value for key, value in os.environ.items() if key.upper() in names}
    with subprocess.Popen([str(executable), str(Path(__file__).resolve()), str(image), '--child', phase],
                          env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
        try:
            output, errors = process.communicate(timeout=90)
        except subprocess.TimeoutExpired:
            process.kill()  # Only our uniquely named disposable child.
            process.communicate(timeout=10)
            raise RuntimeError('scheduler crash child exceeded 90 seconds') from None
        require(process.returncode is not None and process.returncode & 0xffffffff == 0xc0000602,
                'exact deliberate fail-fast exit required: ' + errors[-1500:])
        require(not errors and len(output) < 16384, 'bounded clean checkpoint output')
        target = json.loads(output)
        model.validate(target, process.pid, phase)
        return target, process.returncode


def run(image, phase, expected_output):
    import winreg
    executable = Path(sys.executable).with_name('brynja-wer-' + uuid.uuid4().hex + '.exe')
    # Keep beside the interpreter DLL/stdlib. Never replace an existing file.
    output = executable.open('xb')
    try:
        with output, open(sys.executable, 'rb') as original:
            shutil.copyfileobj(original, output)
        with tempfile.TemporaryDirectory(prefix='brynja-scheduler-dump-') as directory:
            folder = Path(directory)
            with wer.application_policy(winreg, executable.name, folder):
                target, exitcode = run_child(executable, image, phase)
            files = list(folder.glob(executable.name + '.' + str(target['pid']) + '.dmp'))
            require(len(files) == 1, 'exactly one owned dump required; missing is not exclusion')
            require(32 <= files[0].stat().st_size <= dump.LIMIT, 'bounded owned dump')
            size = files[0].stat().st_size
            with files[0].open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as blob:
                observations = model.analyze(blob, target, expected_output)
    finally:
        executable.unlink()
    return dict(target=target, child_exit_code=exitcode, dump_bytes=size, observations=observations,
                app_policy_removed=True, raw_dump_removed=True, copied_executable_removed=True)


def sources():
    # These modules use spec.loader.exec_module without registering in
    # sys.modules. Bind the three-layer oracle explicitly; an import-table walk
    # alone misses ParallelHash, cSHAKE and its underlying Keccak permutation.
    result = {name: digest(ROOT / name) for name in (
        'scripts/parallelhash/check-parallelhash-differential.py',
        'scripts/sha3/check-cshake-differential.py',
        'scripts/sha3/check-sha3-bit-differential.py')}
    for module in tuple(sys.modules.values()):
        file = getattr(module, '__file__', None)
        if file:
            path = Path(file).resolve()
            if path.is_relative_to(ROOT) and path.suffix == '.py':
                result[path.relative_to(ROOT).as_posix()] = digest(path)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('output', type=Path, nargs='?')
    parser.add_argument('--image-sha256')
    parser.add_argument('--allow-app-local-dump', action='store_true')
    parser.add_argument('--child', choices=model.PHASES, help=argparse.SUPPRESS)
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    if args.child:
        child(image, args.child)
        return
    require(args.allow_app_local_dump and args.output is not None and not args.output.exists(),
            'explicit dump approval and fresh output required')
    Windows()
    require(image.suffix.lower() == '.dll' and 0 < image.stat().st_size <= 16 * 1024 * 1024,
            'bounded enclave image')
    expected_hash = digest(image)
    require(args.image_sha256 == expected_hash, 'explicit reviewed-image identity required')
    expected_output = scheduler.Fixture(scheduler.cases()[4]).expected
    before = sources()
    interpreter = digest(Path(sys.executable))
    records = []
    for phase in model.PHASES:
        for repeat in range(2):
            record = run(image, phase, expected_output)
            records.append(record | dict(repeat=repeat))
            print('SCHEDULER_WER: ' + phase + '; repeat=' + str(repeat) + '; observed', flush=True)
    require(expected_hash == digest(image) and interpreter == digest(Path(sys.executable)), 'binary drift')
    require(all(digest(ROOT / name) == value for name, value in before.items()), 'source drift')
    args.output.write_text(json.dumps(dict(schema=1, status='OBSERVATIONS_ONLY',
        source_binding='loaded Python sources from development overlay; no clean-commit claim',
        source_sha256=before, image_sha256=expected_hash, interpreter_sha256=interpreter,
        windows_build=sys.getwindowsversion().build, records=records,
        whole_image_cleanup_qualified=False, production_qualified=False), indent=2) + '\n')


if __name__ == '__main__': main()
