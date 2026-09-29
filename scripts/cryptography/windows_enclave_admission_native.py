#!/usr/bin/env python3
"""Bounded native development admission/rejection campaign, not qualification."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

FIELDS={'profile','stage','trust_status','os_error','loaded','called','cleanup'}


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(value, code, profile, stage):
    if set(value)!=FIELDS or value['profile']!=profile or value['cleanup'] is not True:
        raise ValueError('Invalid admission result schema')
    if any(type(value[k]) is not int for k in ('stage','trust_status','os_error','loaded','called')):
        raise ValueError('Invalid integer results')
    if value['stage']!=stage or code!=(0 if stage==0 else 97): raise ValueError('Unexpected admission outcome')
    success=int(stage==0)
    if value['loaded']!=success or value['called']!=success or value['os_error']!=0:
        raise ValueError('Unexpected execution before/after rejection')
    if profile=='production' and stage==0 and value['trust_status']!=0:
        raise ValueError('Production bypassed trust failure')
    if stage==2 and value['trust_status']==0: raise ValueError('Missing trust rejection')


def run(root, image, old_image, label):
    destination=root/label; destination.mkdir()
    source_hash=digest(image); old_hash=digest(old_image)
    builds={}
    for profile in ('development','production'):
        directory=root/profile; build=json.loads((directory/'admission-build.json').read_text())
        if build['profile']!=profile: raise ValueError('Wrong build profile')
        for name,expected in build['artifact_sha256'].items():
            if digest(directory/name)!=expected: raise ValueError('Changed build artifact: '+name)
        builds[profile]=build
    data=image.read_bytes()
    if not 512<=len(data)<=16*1024*1024: raise ValueError('Image bounds')
    changed=bytearray(data); changed[0]^=1
    (destination/'changed.dll').write_bytes(changed)
    cases=[('development',image,'reviewed',0),('production',image,'test-signature',2),
        ('development',destination/'changed.dll','changed',1),('development',old_image,'old-import-policy',1)]
    records=[]
    for profile,candidate,name,stage in cases:
        executable=root/profile/'admission.exe'; before=digest(executable)
        result=subprocess.run([str(executable),str(candidate)],capture_output=True,text=True,timeout=45)
        (destination/(name+'.stdout')).write_text(result.stdout)
        (destination/(name+'.stderr')).write_text(result.stderr)
        if result.stderr or not 0<len(result.stdout)<4096: raise ValueError('Invalid capture output')
        value=json.loads(result.stdout); validate(value,result.returncode,profile,stage)
        if digest(executable)!=before: raise ValueError('Executable changed')
        records.append({'case':name,'profile':profile,'exit_code':result.returncode,'result':value,
                        'executable_sha256':before,'image_sha256':digest(candidate)})
        print(name,result.returncode,flush=True)
    # A separately compiled removed-chain-check mutant must not pass validation.
    executable=root/'trust-mutant.exe'
    result=subprocess.run([str(executable),str(image)],capture_output=True,text=True,timeout=45)
    (destination/'trust-mutant.stdout').write_text(result.stdout)
    (destination/'trust-mutant.stderr').write_text(result.stderr)
    if result.stderr or not 0<len(result.stdout)<4096: raise ValueError('Invalid mutant capture')
    value=json.loads(result.stdout)
    if result.returncode!=0 or value.get('stage')!=0 or value.get('trust_status')==0:
        raise ValueError('Trust mutant did not reach the intended bypass')
    try: validate(value,0,'production',0)
    except ValueError: pass
    else: raise ValueError('Trust mutant escaped validator')
    mutant={'exit_code':result.returncode,'result':value,'executable_sha256':digest(executable),
            'rejected_by_validator':True}
    # Failed guard cleanup must abort, never emit a clean rejection/cleanup record.
    executable=root/'close-failure.exe'
    result=subprocess.run([str(executable),str(destination/'changed.dll')],capture_output=True,text=True,timeout=45)
    (destination/'close-failure.stdout').write_text(result.stdout)
    (destination/'close-failure.stderr').write_text(result.stderr)
    if result.returncode in (0,97) or result.stdout: raise ValueError('Failed cleanup falsely reported success')
    close={'exit_code':result.returncode,'executable_sha256':digest(executable),
           'aborted_without_success_record':True}
    if digest(image)!=source_hash or digest(old_image)!=old_hash: raise ValueError('Original image changed')
    record={'schema':1,'status':'OBSERVATIONS_ONLY','captured_at':datetime.now(timezone.utc).isoformat(),
        'native_executed':True,'strict_qualified':False,'production_signed':False,'builds':builds,
        'records':records,'trust_mutant':mutant,'close_failure':close}
    (destination/'admission-run.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Native development admission campaign: PASS; production qualification: NO')


def prepare_controls(root):
    # Isolated generated native controls, never edits the reviewed originals.
    source=(root/'production'/'image_admission_main.c').read_text()
    token='if (trust != ERROR_SUCCESS) { goto done; }'
    if source.count(token)!=1: raise ValueError('Trust check changed')
    (root/'trust_mutant.c').write_text(source.replace(token,'/* Deliberate trust-check deletion mutant. */'))
    source=(root/'development'/'image_pin.c').read_text()
    token='if (CloseHandle(pin->file))'
    if source.count(token)!=1: raise ValueError('Close check changed')
    (root/'close_failure.c').write_text(source.replace(token,'if (pin->count == PIN_PARENTS + 1)'))
    for profile in ('development','production'):
        if not (root/profile/'admission.lib').is_file(): raise ValueError('Build missing')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('root',type=Path)
    parser.add_argument('--prepare-controls',action='store_true')
    parser.add_argument('--image',type=Path); parser.add_argument('--old-image',type=Path)
    parser.add_argument('--label',choices=('first','repeat')); args=parser.parse_args()
    if args.prepare_controls: prepare_controls(args.root.resolve())
    elif not all((args.image,args.old_image,args.label)): parser.error('Capture arguments required')
    else: run(args.root.resolve(),args.image.resolve(),args.old_image.resolve(),args.label)
