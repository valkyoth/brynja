#!/usr/bin/env python3
"""Bounded two-live-enclave diagnostic, not persistent identity qualification."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import subprocess
from windows_enclave_retained_partial_run import digest,validate,FIELDS

EXPECTED={'normal':(0,0,2,2,45,0,0),'token':(97,21,2,0,5,2,0),'identity':(97,13,2,0,4,2,0)}


def run(directory,label,image_hash):
    if len(image_hash)!=64 or digest(directory/'image/normal.dll')!=image_hash:raise ValueError('Image mismatch')
    build=json.loads((directory/'retained-cross-build.json').read_text())
    for section in ('generated_sha256','archives'):
        for name,expected in build[section].items():
            if digest(directory/name)!=expected:raise ValueError('Changed build input: '+name)
    destination=directory/label;destination.mkdir();records=[]
    executable=directory/'host/cross.exe';executable_hash=digest(executable)
    for name,expected in EXPECTED.items():
        image=directory/('identity/normal.dll' if name=='identity' else 'image/'+name+'.dll')
        before=digest(image)
        result=subprocess.run([str(executable),str(image)],capture_output=True,text=True,timeout=90)
        (destination/(name+'.stdout')).write_text(result.stdout);(destination/(name+'.stderr')).write_text(result.stderr)
        print(name,result.returncode,flush=True)
        if result.stderr or not 0<len(result.stdout)<=8192:raise ValueError('Invalid capture: '+result.stderr[-4000:])
        value=json.loads(result.stdout);validate(value,result.returncode,expected)
        if digest(image)!=before or digest(executable)!=executable_hash:raise ValueError('Artifact changed')
        records.append({'variant':name,'exit_code':result.returncode,'result':value,'image_sha256':before})
    record={'schema':1,'kind':'windows-enclave-live-cross-instance-experiment','status':'OBSERVATIONS_ONLY',
        'native_executed':True,'strict_qualified':False,'public_vectors_only':True,'persistent_identity_claim':False,
        'captured_at':datetime.now(timezone.utc).isoformat(),'platform':platform.platform(),
        'executable_sha256':executable_hash,'build':build,'records':records}
    (destination/'retained-cross-run.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Native two-live-instance routing: PASS; 45 calls; two mutants rejected; strict qualification: NO')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path)
    parser.add_argument('label',choices=('first','repeat'));parser.add_argument('--image-sha256',required=True)
    args=parser.parse_args();run(args.directory.resolve(),args.label,args.image_sha256)
