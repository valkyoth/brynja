"""Isolated public-code runtime comparison; not attestation or a release gate."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import windows_enclave_sdk_frames as sdk
from windows_enclave_lifecycle import Native

ROOT = Path(__file__).resolve().parents[2]
MATCHED, REJECTED = 0x42525949, (1 << 64) - 1
SOURCES = ('assurance/windows-enclave-probe/sdk_identity.c',
           'assurance/windows-enclave-probe/synthetic.c',
           'scripts/cryptography/windows_enclave_sdk_identity.py',
           'scripts/cryptography/windows_enclave_sdk_frames.py',
           'scripts/cryptography/windows_enclave_wrapper_binding.py',
           'scripts/cryptography/windows_enclave_lifecycle.py',
           'scripts/cryptography/windows_protection_api.py',
           'scripts/cryptography/windows_protection_probe.py')


def reference(data):
    sdk.inspect(data)  # Exact reviewed file, architecture, selected body hashes.
    rows, _ = sdk.pe.linked(data)
    texts = [r for r in rows if r['name'] == b'.text']
    sdk.require(len(texts) == 1, 'unique SDK text')
    row = texts[0]
    sdk.require(row['rva'] == 0x1000 and row['virtual_size'] == 0x1dc4b
                and row['flags'] & 0x20000000 and not row['flags'] & 0x80000000
                and len(row['code']) >= row['virtual_size'], 'reviewed SDK text geometry')
    code = row['code'][:row['virtual_size']]
    return dict(rva=row['rva'], size=len(code), sha256=hashlib.sha256(code).hexdigest()), code


def build(saved, destination):
    description, code = reference(saved.read_bytes())
    destination.mkdir()  # Never overwrite a previous diagnostic.
    for name in ('sdk_identity.c', 'synthetic.c'):
        shutil.copyfile(ROOT / 'assurance/windows-enclave-probe' / name, destination / name)
    header = '#define SDK_IMAGE_SIZE 0x36000U\n#define SDK_TEXT_RVA 0x1000U\n'
    header += 'static const unsigned char sdk_expected[] = {\n'
    header += '\n'.join(','.join(str(b) for b in code[i:i+32])+',' for i in range(0, len(code), 32))
    (destination/'sdk_expected.h').write_text(header+'\n};\n')
    (destination/'link.cmd').write_text('@echo off\nsetlocal\n'
        'if "%VCToolsInstallDir%"=="" exit /b 90\ncd /d "%~dp0"\n'
        'cl /nologo /std:c11 /LD /O2 /W4 /WX /MT /guard:cf /Fosdk.obj /Fenormal.dll '
        'sdk_identity.c /link /ENCLAVE /NODEFAULTLIB /INCREMENTAL:NO /INTEGRITYCHECK /GUARD:MIXED '
        '/LIBPATH:"%VCToolsInstallDir%lib\\x64\\enclave" '
        '/LIBPATH:"%WindowsSdkDir%Lib\\%WindowsSDKVersion%ucrt_enclave\\x64" '
        'libcmt.lib libvcruntime.lib ucrt.lib vertdll.lib\nif errorlevel 1 exit /b 1\n'
        '"%WindowsSdkDir%bin\\%WindowsSDKVersion%x64\\veiid.exe" normal.dll\n'
        'exit /b %ERRORLEVEL%\n')
    (destination/'reference.json').write_text(json.dumps(dict(
        saved_file_sha256=sdk.IMAGE_SHA256, text=description,
        source_sha256={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES}), indent=2)+'\n')


def validate_samples(samples):
    sdk.require(type(samples) is list and len(samples) == 3, 'three complete repetitions')
    expected = [MATCHED, 0x1000, REJECTED, REJECTED]
    sdk.require(all(type(row) is list and len(row) == 4
        and all(type(v) is int for v in row) and row == expected for row in samples),
        'loaded text match, changed expectation, absent module and unknown query')


def exercise(api, image):
    base = api.create()
    initialized = False
    try:
        loaded, error = api.load(base, image)
        sdk.require(loaded, 'diagnostic image load: '+str(error))
        api.initialize(base)
        initialized = True
        routine = api.check(api.GetProcAddress(base, b'PublicSdkIdentity'), 'SDK identity export')
        samples = [[api.call(routine, q) for q in (0, 1, 2, 3)] for _ in range(3)]
        validate_samples(samples)
    finally:
        try:
            if initialized: api.terminate(base)
        finally:
            api.delete(base)
    return dict(schema=1, status='DEVELOPMENT_LOADED_TEXT_COMPARISON', samples=samples,
        terminated=True, deleted=True, loaded_text_matches_saved=True,
        whole_module_identity_proven=False, attestation_verified=False,
        all_existing_images_qualified=False, whole_image_qualified=False,
        production_qualified=False, saved_file_sha256=sdk.IMAGE_SHA256)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--build', type=Path, help='new build directory; image is saved SDK DLL')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.build:
        sdk.require(not args.child, 'separate build and execution')
        build(args.image, args.build)
    elif args.child:
        print(json.dumps(exercise(Native(), args.image.resolve(strict=True))))
    else:
        image = args.image.resolve(strict=True)
        before = hashlib.sha256(image.read_bytes()).hexdigest()
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), str(image), '--child'],
                                capture_output=True, text=True, timeout=45)
        sdk.require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) < 8192,
                    'clean bounded diagnostic child: '+result.stderr[-2048:])
        record = json.loads(result.stdout)
        validate_samples(record['samples'])
        sdk.require(record['terminated'] is True and record['deleted'] is True,
                    'completed diagnostic cleanup')
        sdk.require(before == hashlib.sha256(image.read_bytes()).hexdigest(), 'image changed')
        record.update(image_sha256=before, windows_build=sys.getwindowsversion().build,
                      source_sha256={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES})
        print(json.dumps(record, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
