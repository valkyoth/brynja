#!/usr/bin/env python3
"""Native Apple startup quarantine/admission controls on reviewed temporary copies.

Requires a trusted native capture hash. Ad-hoc signatures are test machinery,
not release signing. Original executables are never modified.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('apple_control_review',HERE/'aes_apple_startup_static.py')
review=importlib.util.module_from_spec(spec);spec.loader.exec_module(review)
hosted_spec=importlib.util.spec_from_file_location('apple_hosted_control_review',HERE/'aes_apple_startup_hosted.py')
hosted=importlib.util.module_from_spec(hosted_spec);hosted_spec.loader.exec_module(hosted)
require=review.require
ROOT=HERE.parents[1]
CODESIGN=Path('/usr/bin/codesign')
PASS='AES_ARM_STARTUP_PASS'
QUARANTINED='AES_ARM_STARTUP_QUARANTINED'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def signature(image):
    # First validate bounded mappings/commands; accept only the existing terminal
    # signature representation. Runtime tables must end before the signature.
    _,_,_,layout=review.mapping.parse(image,include_layout=True)
    found=[];tables=[];cursor=32
    for _ in range(struct.unpack_from('<I',image,16)[0]):
        cmd,size=struct.unpack_from('<II',image,cursor)
        if cmd==0x1d:
            require(size==16,'invalid code signature command')
            offset,length=struct.unpack_from('<II',image,cursor+8)
            found.append((offset,length))
        elif cmd==0x80000022:
            require(size==48,'invalid dyld info command')
            fields=struct.unpack_from('<10I',image,cursor+8)
            tables.extend(zip(fields[::2],fields[1::2]))
        elif cmd==0xb:
            require(size==80,'invalid dynamic symbol command')
            fields=struct.unpack_from('<18I',image,cursor+8)
            for index,width in ((6,8),(8,56),(10,4),(12,4),(14,8),(16,8)):
                tables.append((fields[index],fields[index+1]*width))
        elif cmd in (0x26,0x29,0x80000033):
            require(size==16,'invalid linkedit data command')
            tables.append(struct.unpack_from('<2I',image,cursor+8))
        cursor+=size
    require(len(found)==1,'missing/duplicate code signature')
    offset,length=found[0]
    link=next(s for s in layout['segments'] if s['name']=='__LINKEDIT')
    require(length>=12 and link['pos']<=offset and offset+length==len(image)
            and offset+length==link['pos']+link['filesz'],'signature is not terminal linkedit data')
    symoff,nsym,stroff,strsize=layout['commands'][2]
    funoff,funsize=layout['commands'][0x26]
    require(max(symoff+16*nsym,stroff+strsize,funoff+funsize)<=offset,'signature overlaps reviewed tables')
    require(all(n==0 or (link['pos']<=p and p+n<=offset) for p,n in tables),
            'signature overlaps runtime linkedit tables')
    magic,blobsize=struct.unpack_from('>II',image,offset)
    require(magic==0xfade0cc0 and 12<=blobsize<=length,'invalid embedded signature container')
    return offset,length


def signed_copy_matches(expected,signed):
    offset,_=signature(expected)
    signed_offset,_=signature(signed)
    require(signed_offset==offset,'signing moved signature')
    # Native codesign may resize the terminal signature. Permit only its length
    # and the enclosing __LINKEDIT file size to reflect that; offsets, VM size,
    # permissions, all other metadata, code and runtime tables stay identical.
    # signature() independently checks both sizes against the actual file end.
    prefix=bytearray(signed[:offset]);cursor=32
    for _ in range(struct.unpack_from('<I',expected,16)[0]):
        cmd,size=struct.unpack_from('<II',expected,cursor)
        if cmd==0x1d:
            prefix[cursor+12:cursor+16]=expected[cursor+12:cursor+16]
        elif cmd==0x19 and expected[cursor+8:cursor+24].rstrip(b'\0')==b'__LINKEDIT':
            prefix[cursor+48:cursor+56]=expected[cursor+48:cursor+56]
        cursor+=size
    require(prefix==expected[:offset],'signing changed bytes outside signature/size fields')


def corruption_cases(image,report):
    refs={}
    for row in report['references']:
        role=row['role']
        if role not in ('plain','cipher128','cipher192','cipher256','schedule128','schedule192','schedule256'):
            continue
        require(role not in refs or refs[role]==row,'inconsistent repeated startup reference')
        refs[role]=row
    expected={r for r in review.REFERENCE if r not in ('key16','tail8','tail16')}
    require(set(refs)==expected,'startup corruption reference population changed')
    signature_offset,_=signature(image)
    for role in sorted(refs):
        row=refs[role];offset,size=row['offset'],row['size']
        require(type(offset) is int and type(size) is int and offset>=0
                and size==len(review.REFERENCE[role]) and offset+size<=signature_offset
                and image[offset:offset+size]==review.REFERENCE[role],'invalid startup corruption reference')
        for i in range(size if role.startswith('schedule') else 1):
            changed=bytearray(image);changed[offset+i]^=1
            yield f'{role}:{i}',offset+i,bytes(changed)


def run(command,directory,env):
    result=subprocess.run(command,cwd=directory,env=env,capture_output=True,text=True,timeout=30,check=False)
    require(result.returncode==0,'native control command failed: '+str(command[0])+
            f' (exit {result.returncode}): '+result.stderr[:2000])
    return result


def execute(binary,directory,env,quarantined,admission='static',unavailable=False):
    require(admission in ('static','hosted') and not (quarantined and unavailable)
            and (not unavailable or admission=='hosted'),'invalid native control state')
    argument='expect-unavailable' if unavailable else 'expect-quarantined' if quarantined else None
    prefix='AES_ARM_HOSTED_STARTUP' if admission=='hosted' else 'AES_ARM_STARTUP'
    marker=prefix+('_UNAVAILABLE' if unavailable else '_QUARANTINED' if quarantined else '_PASS')
    result=run([str(binary),*([argument] if argument else [])],directory,env)
    require(not result.stderr and result.stdout.splitlines()==[marker],
            'native startup control output/state changed')
    return result.stdout


def sign(binary,expected,directory,env):
    result=run([str(CODESIGN),'--force','--sign','-','--timestamp=none',str(binary)],directory,env)
    signed=binary.read_bytes()
    signed_copy_matches(expected,signed)
    verified=run([str(CODESIGN),'--verify','--strict',str(binary)],directory,env)
    return signed,result.stdout+result.stderr+verified.stdout+verified.stderr


def check(binary,expected,compiler,panic,admission='static'):
    require(platform.system()=='Darwin' and platform.machine()=='arm64','requires native Apple ARM64 host')
    require(compiler in ('1.90.0','1.99.1') and panic in ('abort','unwind')
            and admission in ('static','hosted'),'unsupported startup control profile')
    require(re.fullmatch('[0-9a-f]{64}',expected) is not None,'invalid captured binary SHA-256')
    for name in os.environ:
        require(not name.startswith('DYLD_') and name not in ('LD_PRELOAD','LD_LIBRARY_PATH','PYTHONPATH','PYTHONOPTIMIZE'),
                'remove ambient '+name)
    binary=Path(binary).absolute()
    require(binary.is_file() and not any(p.is_symlink() for p in (binary,*binary.parents)),
            'missing/nonregular/symlinked captured executable')
    with binary.open('rb') as stream:image=stream.read(review.mapping.LIMIT+1)
    require(len(image)<=review.mapping.LIMIT and digest(image)==expected,'capture hash mismatch')
    report=(hosted if admission=='hosted' else review).inspect(image,compiler,panic)
    signature(image)
    require(CODESIGN.is_file() and not CODESIGN.is_symlink(),'missing native codesign tool')
    signer_hash=digest(CODESIGN.read_bytes())
    # A small explicit environment prevents injected dyld/runtime configuration.
    env={'PATH':'/usr/bin:/bin','LC_ALL':'C'}
    base=ROOT/'target/aes-apple-startup-controls';base.mkdir(parents=True,exist_ok=True)
    retained=Path(tempfile.mkdtemp(prefix=f'{compiler}-{admission}-{panic}-',dir=base))
    print(f'Artifacts: {retained}',flush=True)
    (retained/'baseline.log').write_text(execute(binary,retained,env,False,admission))
    cases=[];admission_results=[]
    with tempfile.TemporaryDirectory(prefix='executables-',dir=retained) as temporary:
        directory=Path(temporary)
        # Also run an identically re-signed positive copy, separating signing or
        # path effects from corrupted-answer behavior.
        positive=directory/'positive.macho';positive.write_bytes(image);positive.chmod(0o700)
        signed,log=sign(positive,image,directory,env)
        (retained/'positive-signing.log').write_text(log)
        (retained/'positive.log').write_text(execute(positive,directory,env,False,admission))
        positive_hash=digest(signed)
        with (retained/'cases.jsonl').open('x') as output:
            for case,offset,changed in corruption_cases(image,report):
                # Distinct inodes avoid reusing macOS executable signature cache.
                negative=directory/(case.replace(':','-')+'.macho')
                negative.write_bytes(changed);negative.chmod(0o700)
                signed,log=sign(negative,changed,directory,env)
                observed=execute(negative,directory,env,True,admission)
                require(negative.read_bytes()==signed,'executed control changed')
                row=dict(case=case,offset=offset,mutation_mask=1,
                         unsigned_sha256=digest(changed),signed_sha256=digest(signed),
                         signing_output=log,output=observed)
                output.write(json.dumps(row,sort_keys=True)+'\n');output.flush()
                cases.append(case)
                if len(cases)%100==0:print(f'{len(cases)}/628 corrupted answers quarantined',flush=True)
        if admission=='hosted':
            with (retained/'admission.jsonl').open('x') as output:
                for case,changed in hosted.admission_cases(image,compiler,panic):
                    negative=directory/(case+'.macho');negative.write_bytes(changed);negative.chmod(0o700)
                    signed,log=sign(negative,changed,directory,env)
                    observed=execute(negative,directory,env,False,admission,unavailable=True)
                    require(negative.read_bytes()==signed,'executed admission control changed')
                    row=dict(case=case,unsigned_sha256=digest(changed),signed_sha256=digest(signed),
                             signing_output=log,output=observed)
                    output.write(json.dumps(row,sort_keys=True)+'\n');output.flush();admission_results.append(case)
            require(admission_results==['warm-aes-absent','cold-aes-absent',
                                        'warm-pmull-absent','cold-pmull-absent'],
                    'native admission population changed')
    require(len(cases)==len(set(cases))==628,'native quarantine population changed')
    require(digest(binary.read_bytes())==expected and digest(CODESIGN.read_bytes())==signer_hash,
            'original binary or signing tool changed')
    result=dict(compiler=compiler,panic=panic,admission=admission,execution='native',
        host=dict(system=platform.system(),machine=platform.machine(),release=platform.release()),
        binary=str(binary),binary_sha256=expected,review=report,
        signing_tool=dict(path=str(CODESIGN),sha256=signer_hash),
        signing_policy='same signature offset; only terminal signature payload and its two file-size fields may change',
        positive_copy_sha256=positive_hash,executed_quarantine_cases=cases,
        case_log_sha256=digest((retained/'cases.jsonl').read_bytes()),
        executed_admission_cases=admission_results,
        admission_log_sha256=digest((retained/'admission.jsonl').read_bytes()) if admission_results else None,
        runner_sha256=digest(Path(__file__).read_bytes()),
        limits=['Ad-hoc signatures are temporary test machinery, not release signing.',
                'Public KAT data mutations only; not physical fault resistance.',
                'Detector observations are software controls, not hardware without AES.',
                'Not detector implementation, OS or platform lifetime qualification.'])
    (retained/'report.json').write_text(json.dumps(result,indent=2)+'\n')
    print(f'APPLE_{admission.upper()}_STARTUP_CONTROLS_PASS: {compiler} {panic}; 628 corrupted answers quarantined; '
          f'{len(admission_results)} missing-feature controls',flush=True)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary',type=Path);parser.add_argument('--sha256',required=True)
    parser.add_argument('--compiler',choices=('1.90.0','1.99.1'),required=True)
    parser.add_argument('--panic',choices=('abort','unwind'),required=True)
    parser.add_argument('--admission',choices=('static','hosted'),default='static')
    args=parser.parse_args()
    try:check(args.binary,args.sha256,args.compiler,args.panic,args.admission)
    except (OSError,ValueError,subprocess.TimeoutExpired) as error:
        parser.exit(2,'Apple startup controls failed: '+str(error)+'\n')


if __name__=='__main__':main()
