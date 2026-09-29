#!/usr/bin/env python3
"""Inspect an enclave; compile a separate owner-reviewed deployment policy.

Inspection NEVER approves an image. Policy is a trusted build input, not an
image sidecar discovered by the runtime. Production signing remains external.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import windows_enclave_image_pin_build as pin

ROOT = pin.ROOT
SOURCE = ROOT/'assurance/windows-enclave-probe'
FILES = ('image_admission.rs', 'image_admission_cli.rs', 'image_admission_adapter.rs',
         'image_admission_main.c', 'image_pin.c', 'image_pin.h')
FIELDS = {'status', 'sha256', 'family', 'image', 'version', 'security', 'policy',
          'size', 'threads', 'minimum_import_security'}
SOURCES = tuple(sorted(set(pin.SOURCES) | {
    *('assurance/windows-enclave-probe/'+p for p in FILES),
    'scripts/cryptography/windows_enclave_admission.py',
    'scripts/cryptography/windows_enclave_admission_native.py',
    'scripts/cryptography/test-windows-enclave-admission.py',
    'assurance/windows-enclave-probe/image_admission_tests.rs'}))


def checked_policy(value, profile):
    if set(value) != FIELDS | {'schema', 'profile', 'reviewer', 'source_commit'}:
        raise ValueError('Exact policy schema required')
    if value['status'] != 'OWNER_REVIEWED' or type(value['schema']) is not int or value['schema'] != 1:
        raise ValueError('Inspection is not approval')
    if value['profile'] != profile or profile not in ('development', 'production'):
        raise ValueError('Policy/build profile mismatch')
    if not isinstance(value['reviewer'], str) or not 1 <= len(value['reviewer']) <= 200:
        raise ValueError('Reviewer required')
    commit = value['source_commit']
    if not isinstance(commit, str) or len(commit) != 40 or any(c not in '0123456789abcdef' for c in commit):
        raise ValueError('Reviewed image source commit required')
    for key, length in (('sha256',32),('family',16),('image',16),('minimum_import_security',2)):
        maximum = 0xffffffff if key == 'minimum_import_security' else 255
        if (type(value[key]) is not list or len(value[key]) != length
                or any(type(x) is not int or not 0 <= x <= maximum for x in value[key])):
            raise ValueError('Invalid policy array: '+key)
    for key in ('version','security','policy','size','threads'):
        if type(value[key]) is not int or not 0 <= value[key] <= 0xffffffff:
            raise ValueError('Invalid policy integer: '+key)
    if (value['version']==0 or value['security']==0 or value['policy'] not in (0,2)
            or value['size']!=0x10000000 or value['threads']!=1
            or not any(value['sha256']) or not any(value['family']) or not any(value['image'])):
        raise ValueError('Unsupported identity/configuration')
    return value


def inspect(image, prepared_output=None):
    target = subprocess.check_output(['rustc','+1.98.1','-vV'],text=True).split('host: ')[1].splitlines()[0]
    with tempfile.TemporaryDirectory(prefix='enclave-inspect-') as tmp:
        directory=Path(tmp); pin.dependencies(directory,target,testing=True)
        command=['rustc','+1.98.1','--edition=2024','-D','warnings','-C','opt-level=2',
                 '-L','dependency='+str(directory),'--extern',
                 'brynja_hash_sha2='+str(directory/'libbrynja_hash_sha2.rlib'),
                 str(SOURCE/'image_admission_cli.rs'),'-o',str(directory/'inspect')]
        subprocess.run(command,check=True,capture_output=True,timeout=120)
        operation=['inspect',str(image)] if prepared_output is None else ['prepare',str(image),str(prepared_output)]
        result=subprocess.run([str(directory/'inspect'),*operation],capture_output=True,text=True,timeout=30)
        if result.returncode: raise ValueError(result.stderr)
        return json.loads(result.stdout) if prepared_output is None else result.stdout.strip()


def policy_source(value):
    # Only validated integer arrays are emitted; no raw text/code from reviewer fields.
    checked_policy(value,value['profile'])
    identity=',\n'.join(key+': '+repr(value[key]) for key in
        ('family','image','version','security','policy','size','threads','minimum_import_security'))
    return ('const TRUSTED_POLICY: image_admission::Policy = image_admission::Policy {\n'
            'digest: '+repr(value['sha256'])+',\nidentity: image_admission::Identity {\n'+identity+'\n}};\n')


def build(image, policy_path, directory, profile):
    raw=policy_path.read_bytes()
    if len(raw)>16384: raise ValueError('Oversized policy')
    def pairs(items):
        result={}
        for key,value in items:
            if key in result: raise ValueError('Duplicate policy key')
            result[key]=value
        return result
    policy=checked_policy(json.loads(raw,object_pairs_hook=pairs),profile)
    actual=inspect(image)
    if {k:actual[k] for k in FIELDS-{'status'}} != {k:policy[k] for k in FIELDS-{'status'}}:
        raise ValueError('Reviewed policy does not match image')
    directory=directory.resolve(); directory.mkdir()  # Never overwrite evidence.
    commands=pin.dependencies(directory,'x86_64-pc-windows-msvc')
    for name in FILES: shutil.copyfile(SOURCE/name,directory/name)
    (directory/'trusted_policy.rs').write_text(policy_source(policy))
    (directory/'reviewed-policy.json').write_bytes(raw)
    command=['rustc','+1.98.1','--edition=2024','--target','x86_64-pc-windows-msvc',
        '--crate-type','staticlib','-D','warnings','-C','panic=abort','-C','opt-level=2',
        '-C','overflow-checks=yes','-L','dependency='+str(directory),'--extern',
        'brynja_hash_sha2='+str(directory/'libbrynja_hash_sha2.rlib'),
        str(directory/'image_admission_adapter.rs'),'-o',str(directory/'admission.lib')]
    subprocess.run(command,check=True,capture_output=True,timeout=120); commands.append(command)
    (directory/'link.cmd').write_text('@echo off\nsetlocal\n'
        'if "%VCToolsInstallDir%"=="" exit /b 90\n'
        'cd /d "%~dp0"\n'
        'cl /nologo /std:c11 /O2 /W4 /WX /MT /guard:cf /DBRYNJA_ADMISSION_'+profile.upper()+
        ' /Feadmission.exe image_admission_main.c image_pin.c admission.lib '
        '/link /INCREMENTAL:NO onecore.lib wintrust.lib\nexit /b %ERRORLEVEL%\n')
    record={'schema':1,'profile':profile,'native_executed':False,'strict_qualified':False,
        'signature_verified':False,'commands':commands,'policy_sha256':hashlib.sha256(raw).hexdigest(),
        'source_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES},
        'artifact_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(directory.iterdir()) if p.is_file()}}
    (directory/'admission-build.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Admission cross-build: PASS; native/signature/production qualification: NOT ESTABLISHED')


def main():
    parser=argparse.ArgumentParser(description=__doc__); sub=parser.add_subparsers(dest='operation',required=True)
    show=sub.add_parser('inspect'); show.add_argument('image',type=Path)
    prepare=sub.add_parser('prepare-system-imports'); prepare.add_argument('image',type=Path); prepare.add_argument('output',type=Path)
    make=sub.add_parser('build')
    for name in ('image','policy','directory'): make.add_argument(name,type=Path)
    make.add_argument('--profile',choices=('development','production'),required=True)
    args=parser.parse_args()
    if args.operation=='inspect': print(json.dumps(inspect(args.image),indent=2))
    elif args.operation=='prepare-system-imports': print(inspect(args.image,args.output))
    else: build(args.image,args.policy,args.directory,args.profile)


if __name__=='__main__': main()
