#!/usr/bin/env python3
"""Bounded native injected-copy capture, with exact control outcomes."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess

EXPECTED = {'normal': (0, 0, 1, 1, 4236, 0, 0),
            'skip-copy': (97, 22, 1, 0, 6, 1, 0),
            'ignore-failure': (97, 22, 1, 0, 2, 1, 0)}
FIELDS = ('result','created','deleted','calls','retained','cleanup_errors')


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(result, code, expected):
    if code != expected[0] or type(result) is not dict or set(result) != set(FIELDS) or any(
        type(result[k]) is not int or result[k] != value for k,value in zip(FIELDS,expected[1:])):
        raise ValueError(f'Unexpected partial-copy result: {code}: {result}; expected {expected}')


def run(directory, label, image_hash):
    image = directory/'image/normal.dll'
    if len(image_hash) != 64 or digest(image) != image_hash: raise ValueError('Image identity mismatch')
    build = json.loads((directory/'retained-partial-build.json').read_text())
    for section in ('generated_sha256','archives'):
        for name, expected in build[section].items():
            if digest(directory/name) != expected: raise ValueError('Changed build input: '+name)
    destination = directory/label; destination.mkdir()
    records = []; executable = directory/'host/partial.exe'; executable_hash = digest(executable)
    for name, expected in EXPECTED.items():
        selected = directory/'image'/(name+'.dll'); before = digest(selected)
        result = subprocess.run([str(executable),str(selected)],capture_output=True,text=True,timeout=180)
        (destination/(name+'.stdout')).write_text(result.stdout)
        (destination/(name+'.stderr')).write_text(result.stderr)
        print(name, result.returncode, flush=True)
        if result.stderr or not 0 < len(result.stdout) <= 8192: raise ValueError('Invalid capture: '+result.stderr[-4000:])
        value = json.loads(result.stdout); validate(value,result.returncode,expected)
        if digest(selected) != before or digest(executable) != executable_hash: raise ValueError('Artifact changed')
        records.append({'variant':name,'exit_code':result.returncode,'result':value,'image_sha256':before})
    record = {'schema':1,'kind':'windows-enclave-injected-partial-copy-experiment',
        'status':'OBSERVATIONS_ONLY','public_vectors_only':True,'strict_qualified':False,
        'native_executed':True,'os_partial_failure_claim':False,
        'header_boundaries':33,'payload_boundaries':1025,
        'captured_at':datetime.now(timezone.utc).isoformat(),'platform':platform.platform(),
        'executable_sha256':executable_hash,'build':build,'records':records}
    (destination/'retained-partial-run.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Native injected prefix-copy: PASS; 1058 boundaries; two mutants rejected; strict qualification: NO')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path); parser.add_argument('label',choices=('first','repeat'))
    parser.add_argument('--image-sha256',required=True); args = parser.parse_args()
    run(args.directory.resolve(),args.label,args.image_sha256)
