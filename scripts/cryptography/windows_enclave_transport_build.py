"""Build a separate resident canary with loaded status-data identity checks."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

import windows_enclave_resident_build as resident
import windows_enclave_transport_data as data


def header(parts):
    data.check(parts)
    text = 'typedef struct { SIZE_T rva, size; const unsigned char* bytes; } SdkDataExpected;\n'
    for name,raw in parts.items():
        text += 'static const unsigned char sdk_'+name+'[] = {\n'
        text += '\n'.join(','.join(map(str,raw[i:i+32]))+',' for i in range(0,len(raw),32))+'\n};\n'
    text += 'static const SdkDataExpected sdk_data[] = {\n'
    text += ''.join('{'+str(data.SPECS[n][0])+',sizeof(sdk_'+n+'),sdk_'+n+'},\n' for n in parts)
    return text+'};\n'


def build(directory,sdk):
    parts = data.reference(sdk.read_bytes())
    resident.build(directory,sdk)
    source = directory/'isolated_resident.c'
    text = source.read_text()
    anchor = '#include "isolated_sdk.h"'
    if text.count(anchor)!=1: raise ValueError('unique identity include')
    text = text.replace(anchor,'#include "isolated_transport_sdk.h"')
    # Public diagnostic only; the actual request entry also uses the same check
    # before admitting input, through isolated_sdk above.
    text += '\n__declspec(dllexport) void* CALLBACK PublicTransportIdentity(void* context) {\n'
    text += '    if (busy || active || stage_region) { return 0; }\n'
    text += '    return (void*)(ULONG_PTR)transport_identity((ULONG_PTR)context);\n}\n'
    source.write_text(text)
    root = resident.original.ROOT
    name = 'assurance/windows-enclave-probe/isolated_transport_sdk.h'
    shutil.copyfile(root/name,directory/'isolated_transport_sdk.h')
    (directory/'sdk_data_expected.h').write_text(header(parts))
    record = json.loads((directory/'build.json').read_text())
    paths = [name,'scripts/cryptography/windows_enclave_transport_build.py',
             'scripts/cryptography/windows_enclave_transport_data.py',
             'scripts/cryptography/windows_enclave_sdk_diagnostic.py',
             'scripts/cryptography/windows_enclave_sdk_return.py']
    record['source_sha256'].update({p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in paths})
    record['status'] = 'PUBLIC_TRANSPORT_DATA_CANARY_BUILD_ONLY'
    record['generated_sha256'] = {p.name:hashlib.sha256(p.read_bytes()).hexdigest()
        for p in directory.iterdir() if p.is_file() and p.name!='build.json'}
    record['sdk_data'] = data.inspect(sdk.read_bytes())
    (directory/'build.json').write_text(json.dumps(record,indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    parser.add_argument('--sdk',type=Path,required=True)
    args=parser.parse_args()
    build(args.output.resolve(),args.sdk)
