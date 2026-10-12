"""Separate resident-staging canary; preserve the original 08A image inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

import windows_enclave_isolated_build as original


def build(directory, sdk, dirty=False):
    original.build(directory, 'x86_64-pc-windows-msvc', saved=sdk)
    names = ('isolated_resident.c', 'isolated_retire_x64.asm')
    for name in names:
        shutil.copyfile(original.SOURCE/name, directory/name)
    command = (directory/'link.cmd').read_text()
    anchor = 'cl /nologo /std:c11'
    if command.count(anchor) != 1:
        raise ValueError('one original compiler command')
    assembly = 'ml64 /nologo /c'+(' /DBRYNJA_PROBE_SKIP_STAGE_CLEAR' if dirty else '')
    command = command.replace(anchor, assembly+' /Foretire.obj isolated_retire_x64.asm\n'
                              'if errorlevel 1 exit /b 1\n'+anchor)
    command = command.replace('isolated_sha256.c window.obj normal_rust.lib',
                              'isolated_resident.c window.obj retire.obj normal_rust.lib')
    (directory/'link.cmd').write_text(command)
    record = json.loads((directory/'build.json').read_text())
    paths = ['assurance/windows-enclave-probe/'+n for n in names]
    paths += ['scripts/cryptography/windows_enclave_resident_build.py']
    record['source_sha256'].update({p:hashlib.sha256((original.ROOT/p).read_bytes()).hexdigest()
                                    for p in paths})
    record.update(status='PUBLIC_RESIDENT_CANARY_BUILD_ONLY', dirty_staging_mutant=dirty)
    record['generated_sha256'] = {p.name:hashlib.sha256(p.read_bytes()).hexdigest()
        for p in directory.iterdir() if p.is_file() and p.name != 'build.json'}
    (directory/'build.json').write_text(json.dumps(record,indent=2)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    parser.add_argument('--sdk',required=True,type=Path)
    parser.add_argument('--dirty-stage',action='store_true')
    args = parser.parse_args()
    build(args.output.resolve(),args.sdk,args.dirty_stage)
