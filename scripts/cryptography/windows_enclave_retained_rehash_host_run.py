#!/usr/bin/env python3
"""Bounded composition host/native image capture; never strict qualification."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import subprocess
from windows_enclave_retained_native_host_run import digest, FIELDS

EXPECTED={'normal':(0,0,10,10,261,0,0),'fail-create':(0,10,1,1,0,0,0),
          'fail-load':(0,10,1,1,0,0,0),'fail-init':(0,10,1,1,0,0,0),
          'fail-delete':(0,15,1,0,230,1,3),'early':(97,32,4,4,242,0,0),
          'reopen':(97,22,2,2,234,0,0),'receipt':(97,32,6,6,250,0,0)}
IMAGES={'scratch':(97,60,1,0,3,1,0),'token':(97,66,9,8,260,1,0),
        'commit':(97,12,1,1,5,0,0),'generation':(97,60,1,0,3,1,0)}


def validate(value,expected,code):
    if code!=expected[0] or type(value) is not dict or set(value)!=set(FIELDS) or any(
        type(value[k]) is not int or value[k]!=wanted for k,wanted in zip(FIELDS,expected[1:])
    ):raise ValueError(f'unexpected composition result: {code}: {value}; expected {expected}')


def run(directory,images,label,image_hash):
    image=images/'normal.dll'
    if len(image_hash)!=64 or digest(image)!=image_hash:raise ValueError('signed image binding mismatch')
    destination=directory/label;destination.mkdir()
    build=json.loads((directory/'retained-rehash-host-build.json').read_text())
    image_build=json.loads((images/'retained-rehash-worker-build.json').read_text())
    for root,record in [(directory,build),(images,image_build)]:
        for section in ('generated_sha256','archives'):
            for name,expected in record[section].items():
                if digest(root/name)!=expected:raise ValueError('changed build input: '+name)
    records=[]
    for name,expected in list(EXPECTED.items())+[('image-'+n,e) for n,e in IMAGES.items()]:
        executable=directory/('normal.exe' if name.startswith('image-') else name+'.exe')
        selected=images/(name[6:]+'.dll') if name.startswith('image-') else image
        before=digest(executable);selected_hash=digest(selected)
        result=subprocess.run([str(executable),str(selected)],capture_output=True,text=True,timeout=90)
        (destination/(name+'.stdout')).write_text(result.stdout);(destination/(name+'.stderr')).write_text(result.stderr)
        print(name,result.returncode,flush=True)
        if result.stderr or not 0<len(result.stdout)<=8192:raise ValueError('invalid capture: '+result.stderr[-4000:])
        value=json.loads(result.stdout);validate(value,expected,result.returncode)
        if digest(executable)!=before or digest(selected)!=selected_hash:raise ValueError('artifact changed during capture')
        records.append({'variant':name,'exit_code':result.returncode,'result':value,
                        'executable_sha256':before,'image_sha256':selected_hash})
    if digest(image)!=image_hash:raise ValueError('image changed during campaign')
    record={'schema':1,'kind':'windows-enclave-retained-rehash-experiment','status':'OBSERVATIONS_ONLY',
            'public_vectors_only':True,'native_executed':True,'strict_qualified':False,
            'captured_at':datetime.now(timezone.utc).isoformat(),'platform':platform.platform(),
            'build':build,'image_build':image_build,'records':records}
    (destination/'retained-rehash-run.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Native retained composition: PASS; 261 normal calls; seven mutants rejected; strict qualification: NO')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path)
    parser.add_argument('images',type=Path);parser.add_argument('label',choices=('first','repeat'))
    parser.add_argument('--image-sha256',required=True);args=parser.parse_args()
    run(args.directory.resolve(),args.images.resolve(),args.label,args.image_sha256)
