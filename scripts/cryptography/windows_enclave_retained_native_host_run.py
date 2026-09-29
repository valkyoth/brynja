#!/usr/bin/env python3
"""Bounded actual-resource host campaign; fixed public vectors, no strict admission."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess

IMAGE = '0837e6253d503affabd2d7e3a588c43e2279a595cadfed2a4ab1b54bbfefb48e'
EXPECTED = {
    'normal': (0, 0, 7, 7, 178, 0, 0),
    'fail-create': (0, 10, 1, 1, 0, 0, 0),
    'fail-load': (0, 10, 1, 1, 0, 0, 0),
    'fail-init': (0, 10, 1, 1, 0, 0, 0),
    'fail-delete': (0, 15, 1, 0, 160, 1, 3),
    'early': (97, 32, 4, 4, 170, 0, 0),
    'reopen': (97, 22, 2, 2, 163, 0, 0),
    'receipt': (97, 32, 6, 6, 178, 0, 0),
}
FIELDS = ('result', 'created', 'deleted', 'calls', 'retained', 'cleanup_errors')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(value, name, code):
    expected = EXPECTED[name]
    if code != expected[0] or type(value) is not dict or set(value) != set(FIELDS) or any(
        type(value[k]) is not int or value[k] != v for k, v in zip(FIELDS, expected[1:])
    ):
        raise ValueError(f'incomplete or unexpected native retained-host result: {name}: {code}: {value}')


def run(directory, image, label):
    if digest(image) != IMAGE:
        raise ValueError('must use unchanged signed retained-worker image')
    destination = directory / label
    destination.mkdir()  # Never overwrite an earlier campaign.
    build = json.loads((directory / 'retained-native-host-build.json').read_text())
    for section in ('generated_sha256', 'archives'):
        for name, expected in build[section].items():
            if digest(directory / name) != expected:
                raise ValueError('cross-build binding changed: ' + name)
    records=[]
    for name in EXPECTED:
        executable=directory / (name+'.exe')
        before=digest(executable)
        result=subprocess.run([str(executable),str(image)],capture_output=True,text=True,timeout=90)
        (destination/(name+'.stdout')).write_text(result.stdout)
        (destination/(name+'.stderr')).write_text(result.stderr)
        if result.stderr or not 0 < len(result.stdout) <= 8192:
            raise ValueError('native host diagnostic/oversized result: '+name)
        value=json.loads(result.stdout)
        validate(value,name,result.returncode)
        if digest(executable)!=before:
            raise ValueError('executable changed during capture')
        records.append({'variant':name,'exit_code':result.returncode,'result':value,'executable_sha256':before})
    if digest(image)!=IMAGE:
        raise ValueError('enclave image changed during capture')
    record={'schema':1,'kind':'windows-enclave-retained-host-experiment','status':'OBSERVATIONS_ONLY',
            'public_vectors_only':True,'strict_qualified':False,'native_executed':True,
            'synthetic_transport':False,'captured_at':datetime.now(timezone.utc).isoformat(),
            'platform':platform.platform(),'image_sha256':IMAGE,
            'image_source_commit':'e1190ac8a690f61475f4b353ffb5652e16f9f300','build':build,'records':records}
    (destination/'retained-host-run.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Native affine retained host: PASS; 178 calls; startup/teardown controls; three mutants rejected; strict qualification: NO')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('image',type=Path)
    parser.add_argument('label',choices=('first','repeat'))
    args=parser.parse_args()
    run(args.directory.resolve(),args.image.resolve(),args.label)
