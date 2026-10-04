"""Opt-in dump observations of unchanged sequential images; no new gate."""
import argparse
import json
import mmap
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid

import windows_enclave_image_dump_model as model
from windows_enclave_image_dump_child import child
import windows_enclave_scheduler_dump as shared
import windows_minidump as dump
import windows_wer_probe as wer
from windows_protection_probe import require


def run_child(executable, image, phase):
    names = {'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE', 'LOCALAPPDATA',
             'APPDATA', 'PROGRAMDATA', 'SYSTEMDRIVE'}
    env = {k:v for k,v in os.environ.items() if k.upper() in names}
    with subprocess.Popen([str(executable), str(Path(__file__).resolve()), str(image), '--child', phase],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
        try:
            output, errors = process.communicate(timeout=90)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=10)
            raise RuntimeError('image dump child exceeded 90 seconds') from None
        require(process.returncode is not None and process.returncode & 0xffffffff == 0xc0000602,
                'exact deliberate fail-fast exit: '+errors[-1500:])
        require(not errors and 0 < len(output) < 8192, 'clean bounded checkpoint output')
        value = json.loads(output)
        model.validate(value, process.pid, phase)
        return value


def run(image, phase):
    import winreg
    executable = Path(sys.executable).with_name('brynja-wer-'+uuid.uuid4().hex+'.exe')
    output = executable.open('xb')
    try:
        with output, open(sys.executable, 'rb') as original: shutil.copyfileobj(original, output)
        with tempfile.TemporaryDirectory(prefix='brynja-image-dump-') as directory:
            folder = Path(directory)
            with wer.application_policy(winreg, executable.name, folder):
                value = run_child(executable, image, phase)
            files = list(folder.glob(executable.name+'.'+str(value['pid'])+'.dmp'))
            require(len(files) == 1 and 32 <= files[0].stat().st_size <= dump.LIMIT,
                    'one bounded dump; absence is not exclusion')
            size = files[0].stat().st_size
            with files[0].open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as blob:
                observed = model.analyze(blob, value)
    finally:
        executable.unlink()
    return dict(checkpoint=value, dump_bytes=size, observations=observed,
                app_policy_removed=True, raw_dump_removed=True, copied_executable_removed=True)


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
            'explicit dump approval and fresh output')
    require(image.suffix.lower() == '.dll' and 0 < image.stat().st_size <= 16*1024*1024,
            'bounded existing image')
    identity = shared.digest(image)
    require(identity == args.image_sha256, 'explicit image hash')
    before = shared.sources()
    interpreter = shared.digest(Path(sys.executable))
    records = []
    for phase in model.PHASES:
        for repeat in range(2):
            records.append(run(image, phase) | dict(phase=phase, repeat=repeat))
            print('IMAGE_WER: '+phase+'; repeat='+str(repeat)+'; observed', flush=True)
    require(shared.digest(image) == identity and shared.digest(Path(sys.executable)) == interpreter
            and all(shared.digest(shared.ROOT/p) == h
            for p,h in before.items()), 'image/source drift')
    args.output.write_text(json.dumps(dict(schema=1, status='OBSERVATIONS_ONLY',
        image_sha256=identity, interpreter_sha256=interpreter, source_sha256=before, records=records,
        windows_build=sys.getwindowsversion().build, whole_image_qualified=False,
        production_qualified=False, secret_material_used=False), indent=2)+'\n')


if __name__ == '__main__': main()
