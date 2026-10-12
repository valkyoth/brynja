"""Native loaded SDK code/data identity controls in the resident canary image."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import windows_enclave_resident_probe as resident

require = resident.require
QUERIES = (0,1,2,3,4,5,0)


def validate(samples):
    require(type(samples) is list and len(samples)==3,'three complete identity repetitions')
    require(all(type(row) is list and len(row)==7 and all(type(v) is int for v in row)
        and row==[1,0,0,0,0,0,1] for row in samples),'match/drift/unknown/reuse outcomes')


def exercise(image):
    api = resident.original.Native()
    base,initialized = api.create(),False
    try:
        loaded,error = api.load(base,image)
        require(loaded,'transport canary load: '+str(error))
        api.initialize(base)
        initialized=True
        routine = api.check(api.GetProcAddress(base,b'PublicTransportIdentity'),'identity export')
        samples = [[api.call(routine,q) for q in QUERIES] for _ in range(3)]
        validate(samples)
    finally:
        try:
            if initialized: api.terminate(base)
        finally: api.delete(base)
    # Same signed image and real request entry, including the new code/data
    # check before every payload admission; separate fresh enclave instance.
    record = resident.exercise(image)
    record.update(status='PUBLIC_TRANSPORT_CODE_AND_DATA_NATIVE_ONLY',identity_samples=samples,
        identity_and_compute_use_separate_instances=True,
        os_return_registers_qualified=False,formatter_transitive_payload_proof=False)
    return record


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image',type=Path)
    parser.add_argument('--child',action='store_true')
    args=parser.parse_args()
    image=args.image.resolve(strict=True)
    if args.child:
        print(json.dumps(exercise(image)))
    else:
        before=hashlib.sha256(image.read_bytes()).hexdigest()
        result=subprocess.run([sys.executable,__file__,str(image),'--child'],
            capture_output=True,text=True,timeout=90)
        require(result.returncode==0 and not result.stderr and 0<len(result.stdout)<100000,
                'clean bounded transport child: '+result.stderr[-5000:])
        record=json.loads(result.stdout)
        validate(record['identity_samples'])
        resident.validate(record['cases'])
        require(before==hashlib.sha256(image.read_bytes()).hexdigest(),'same signed image')
        record.update(image_sha256=before,windows_build=sys.getwindowsversion().build,python=sys.version,
            source_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(
                {Path(m.__file__) for n,m in sys.modules.items()
                 if n.startswith(('windows_enclave_','windows_protection_'))}|{Path(__file__)})})
        print(json.dumps(record,indent=2))
