#!/usr/bin/env python3
"""Development-only file pinning around a reviewed native facade executable."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

IMAGE = 'a2a31eebf042e310a76b363eb0fa3bf24cd7d9fe81bcdec0353b95f4392de8cc'
CHILD = 'fac5f442fbc4a49a5c5a269f98ad22bcfe0f713fbe970b46c09e0961eb215de9'
EXPECTED = {'normal': (0, 0), 'allow-write': (97, 11), 'skip-hash': (97, 10)}
FIELDS = {'kind', 'result', 'child_completed', 'write_denied', 'delete_denied', 'rename_denied', 'parent_rename_error'}


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(value, exit_code, expected):
    if set(value) != FIELDS or value['kind'] != 'image-pin': raise ValueError('Invalid result schema')
    if any(type(value[k]) is not int for k in FIELDS-{'kind'}): raise ValueError('Invalid result types')
    if (exit_code, value['result']) != expected: raise ValueError('Unexpected child result')
    normal = expected == (0, 0)
    if any(value[k] != int(normal) for k in ('child_completed', 'write_denied', 'delete_denied', 'rename_denied')):
        raise ValueError('Invalid admission/lifetime checks')
    if value['parent_rename_error'] not in ((5, 32) if normal else (0,)):
        raise ValueError('Unexpected rename error')


def run(directory, image, child, label):
    if digest(image) != IMAGE or digest(child) != CHILD: raise ValueError('Wrong reviewed image/facade executable')
    build = json.loads((directory/'image-pin-build.json').read_text())
    for name, expected in build['artifact_sha256'].items():
        if digest(directory/name) != expected: raise ValueError('Changed build artifact: '+name)
    destination = directory/label; destination.mkdir(); records = []
    for name, expected in EXPECTED.items():
        scratch = destination/name; scratch.mkdir()
        candidate = scratch/'candidate.dll'; changed = scratch/'changed.dll'
        shutil.copyfile(image, candidate)
        bytes_ = bytearray(image.read_bytes()); bytes_[0] ^= 1; changed.write_bytes(bytes_)
        executable = directory/(name+'.exe'); before = digest(executable)
        command = [str(executable), str(candidate), str(changed), str(child), str(destination/(name+'-moved'))]
        result = subprocess.run(command, capture_output=True, text=True, timeout=45)
        (destination/(name+'.stdout')).write_text(result.stdout)
        (destination/(name+'.stderr')).write_text(result.stderr)
        print(name, result.returncode, flush=True)
        if result.stderr or not 0 < len(result.stdout) <= 8192: raise ValueError('Invalid output: '+result.stderr[-2000:])
        lines = result.stdout.splitlines(); value = json.loads(lines[-1]); validate(value, result.returncode, expected)
        if len(lines) > 2: raise ValueError('Unexpected child output')
        if len(lines) == 2:
            if name != 'normal' or json.loads(lines[0]) != {'result':0, 'created':14, 'deleted':14,
                    'calls':281, 'retained':0, 'cleanup_errors':0}: raise ValueError('Wrong facade result')
        if digest(candidate) != IMAGE or digest(changed) != hashlib.sha256(bytes_).hexdigest():
            raise ValueError('Copied artifact changed')
        if digest(executable) != before or digest(image) != IMAGE or digest(child) != CHILD:
            raise ValueError('Reviewed artifact changed')
        records.append({'variant':name, 'exit_code':result.returncode, 'result':value,
            'executable_sha256':before, 'changed_image_sha256':digest(changed),
            'facade_stdout_present':len(lines)==2})
    record = {'schema':1, 'status':'OBSERVATIONS_ONLY', 'native_executed':True,
        'strict_qualified':False, 'signature_verified':False, 'public_artifacts_only':True,
        'captured_at':datetime.now(timezone.utc).isoformat(), 'image_sha256':IMAGE,
        'facade_sha256':CHILD, 'build':build, 'records':records}
    (destination/'image-pin-run.json').write_text(json.dumps(record, indent=2)+'\n')
    print('Native development artifact pin: PASS; production/signature qualification: NO')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('directory', 'image', 'child'): parser.add_argument(name, type=Path)
    parser.add_argument('label', choices=('first', 'repeat')); args = parser.parse_args()
    run(args.directory.resolve(), args.image.resolve(), args.child.resolve(), args.label)
