#!/usr/bin/env python3
"""Bounded native borrowed-input host campaign; development observations only."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import subprocess
from windows_enclave_retained_native_host_run import digest, FIELDS

IMAGE='e947aeeb45ca6dce2339f0c7545b4e1609b6d5d172ee7b17f17fd6090fc68879'
EXPECTED={
    'normal':(0,0,9,9,184,0,0),
    'fail-create':(0,10,1,1,0,0,0),
    'fail-load':(0,10,1,1,0,0,0),
    'fail-init':(0,10,1,1,0,0,0),
    'fail-delete':(0,15,1,0,160,1,3),
    'early':(97,32,4,4,170,0,0),
    'reopen':(97,22,2,2,163,0,0),
    'receipt':(97,32,6,6,178,0,0),
}


def validate(value,name,code):
    expected=EXPECTED[name]
    if code!=expected[0] or type(value) is not dict or set(value)!=set(FIELDS) or any(
        type(value[key]) is not int or value[key]!=wanted for key,wanted in zip(FIELDS,expected[1:])
    ): raise ValueError(f'unexpected borrowed retained-host result: {name}: {code}: {value}')


def run(directory,image,label):
    if digest(image)!=IMAGE: raise ValueError('requires unchanged signed borrowed-input worker')
    destination=directory/label;destination.mkdir()
    build=json.loads((directory/'retained-borrowed-host-build.json').read_text())
    for section in ('generated_sha256','archives'):
        for name,expected in build[section].items():
            if digest(directory/name)!=expected:raise ValueError('changed build input: '+name)
    records=[]
    for name in EXPECTED:
        executable=directory/(name+'.exe');before=digest(executable)
        result=subprocess.run([str(executable),str(image)],capture_output=True,text=True,timeout=90)
        (destination/(name+'.stdout')).write_text(result.stdout)
        (destination/(name+'.stderr')).write_text(result.stderr)
        print(name,result.returncode,flush=True)
        if result.stderr or not 0<len(result.stdout)<=8192:
            raise ValueError('diagnostic/oversized capture: '+name+': '+result.stderr[-4000:])
        value=json.loads(result.stdout);validate(value,name,result.returncode)
        if digest(executable)!=before:raise ValueError('executable changed during capture')
        records.append({'variant':name,'exit_code':result.returncode,'result':value,'executable_sha256':before})
    if digest(image)!=IMAGE:raise ValueError('image changed during capture')
    record={'schema':1,'kind':'windows-enclave-retained-borrowed-host-experiment','status':'OBSERVATIONS_ONLY',
            'public_vectors_only':True,'strict_qualified':False,'native_executed':True,'synthetic_transport':False,
            'captured_at':datetime.now(timezone.utc).isoformat(),'platform':platform.platform(),
            'image_sha256':IMAGE,'image_source_commit':'e88a7f6be397d69c350101bd6969721cfd8bc0b3',
            'build':build,'records':records}
    (destination/'retained-borrowed-host-run.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Native borrowed retained host: PASS; 184 calls; three mutants; strict qualification: NO')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path);parser.add_argument('image',type=Path)
    parser.add_argument('label',choices=('first','repeat'))
    args=parser.parse_args();run(args.directory.resolve(),args.image.resolve(),args.label)
