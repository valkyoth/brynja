#!/usr/bin/env python3
"""Source-bound native retained-output facade capture; no image/strict qualification."""
import argparse
from datetime import datetime,timezone
import json
from pathlib import Path
import platform
import subprocess
from windows_enclave_retained_partial_run import digest,validate,FIELDS

IMAGE='a2a31eebf042e310a76b363eb0fa3bf24cd7d9fe81bcdec0353b95f4392de8cc'
EXPECTED={'normal':(0,0,14,14,281,0,0),'fail-create':(0,10,1,1,0,0,0),
    'fail-load':(0,10,1,1,0,0,0),'fail-init':(0,10,1,1,0,0,0),'fail-delete':(0,15,1,0,230,1,3),
    'early':(97,32,4,4,242,0,0),'reopen':(97,22,2,2,234,0,0),'receipt':(97,32,6,6,250,0,0),
    'recycled':(97,70,11,11,261,0,0)}


def run(directory,image,label):
    if digest(image)!=IMAGE:raise ValueError('Use the reviewed unchanged cross-instance image')
    build=json.loads((directory/'retained-facade-build.json').read_text())
    for section in ('generated_sha256','archives'):
        for name,expected in build[section].items():
            if digest(directory/name)!=expected:raise ValueError('Changed build input: '+name)
    destination=directory/label;destination.mkdir();records=[]
    for name,expected in EXPECTED.items():
        executable=directory/(name+'.exe');before=digest(executable)
        result=subprocess.run([str(executable),str(image)],capture_output=True,text=True,timeout=90)
        (destination/(name+'.stdout')).write_text(result.stdout);(destination/(name+'.stderr')).write_text(result.stderr)
        print(name,result.returncode,flush=True)
        if result.stderr or not 0<len(result.stdout)<=8192:raise ValueError('Invalid capture: '+result.stderr[-4000:])
        value=json.loads(result.stdout);validate(value,result.returncode,expected)
        if digest(executable)!=before or digest(image)!=IMAGE:raise ValueError('Artifact changed')
        records.append({'variant':name,'exit_code':result.returncode,'result':value,'executable_sha256':before})
    record={'schema':1,'kind':'windows-enclave-host-facade-experiment','status':'OBSERVATIONS_ONLY',
        'native_executed':True,'strict_qualified':False,'public_vectors_only':True,
        'captured_at':datetime.now(timezone.utc).isoformat(),'platform':platform.platform(),
        'image_sha256':IMAGE,'image_source_commit':'bce5cd2a9a76fb3908e421b0c8ed06d7b22de18e',
        'build':build,'records':records}
    (destination/'retained-facade-run.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Native retained-output facade: PASS; 281 normal calls; four mutants rejected; strict qualification: NO')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path)
    parser.add_argument('image',type=Path);parser.add_argument('label',choices=('first','repeat'))
    args=parser.parse_args();run(args.directory.resolve(),args.image.resolve(),args.label)
