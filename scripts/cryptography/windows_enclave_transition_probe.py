"""Build public-pattern callback-transition diagnostics, not shipping images."""
import argparse
import json
from pathlib import Path
import shutil

from windows_enclave_callback_stack import ROOT, SOURCE, digest, require, replace

FILES = ('transition_vectors.inc', 'transition_call_probe.asm', 'transition_host_probe.asm',
         'transition_enclave_probe.h', 'transition_host_probe.c')
VARIANTS = {'baseline': '', 'missing-poison': '/DTRANSITION_SKIP_POISON',
            'missing-before': '/DTRANSITION_SKIP_SNAPSHOT'}


def prepare(saved, destination, variant):
    require(variant in VARIANTS and not destination.exists(), 'fresh known transition variant')
    original = json.loads((saved / 'parallel-scheduler-image-build.json').read_text())
    for name, expected in original['source_sha256'].items():
        require(digest(ROOT / name) == expected, 'saved source drift: ' + name)
    for name, expected in original['generated_sha256'].items():
        require(Path(name).name == name and digest(saved / name) == expected, 'saved artifact drift: ' + name)
    destination.mkdir(parents=True)
    for name in original['generated_sha256']: shutil.copyfile(saved / name, destination / name)
    for name in FILES: shutil.copyfile(SOURCE / name, destination / name)
    source = (SOURCE / 'concurrent_stack.c').read_text()
    start, end = source.index('static BOOL notify('), source.index('\nULONG_PTR PublicStackAdmit')
    path = destination / 'concurrent_stack.c'
    path.write_text(replace(path.read_text(), source[start:end], '#include "transition_enclave_probe.h"\n'))
    path = destination / 'link.cmd'
    text = replace(path.read_text(), 'cl /nologo',
        f'ml64 /nologo /c {VARIANTS[variant]} /Fotransition.obj transition_call_probe.asm\n'
        'if errorlevel 1 exit /b 1\ncl /nologo')
    path.write_text(replace(text, 'frame.obj normal_rust.lib', 'frame.obj transition.obj normal_rust.lib'))
    host = ('@echo off\nsetlocal\ncd /d "%~dp0"\n'
        'ml64 /nologo /c /DTRANSITION_DIRECT /Fodirect.obj transition_call_probe.asm\n'
        'if errorlevel 1 exit /b 1\n'
        'ml64 /nologo /c /Fohost.obj transition_host_probe.asm\nif errorlevel 1 exit /b 1\n'
        'cl /nologo /LD /O2 /W4 /WX /MT /Fohost-main.obj /Fehost.dll transition_host_probe.c host.obj direct.obj /link /INCREMENTAL:NO\n'
        'if errorlevel 1 exit /b 1\n'
        'ml64 /nologo /c /DTRANSITION_SKIP_HOST /Fomissing-host.obj transition_host_probe.asm\n'
        'if errorlevel 1 exit /b 1\n'
        'cl /nologo /LD /O2 /W4 /WX /MT /Fomissing-host-main.obj /Femissing-host.dll transition_host_probe.c missing-host.obj direct.obj /link /INCREMENTAL:NO\n'
        'exit /b %ERRORLEVEL%\n')
    (destination / 'host.cmd').write_text(host)
    sources = [SOURCE / f for f in FILES] + [Path(__file__).resolve(),
        ROOT / 'scripts/cryptography/windows_enclave_transition_native.py',
        ROOT / 'scripts/cryptography/windows_enclave_transition_model.py',
        ROOT / 'scripts/cryptography/test-windows-enclave-transition.py']
    record = dict(schema=1, variant=variant, whole_image_qualified=False,
        original_build_sha256=digest(saved / 'parallel-scheduler-image-build.json'),
        source_sha256={p.relative_to(ROOT).as_posix(): digest(p) for p in sources},
        generated_sha256={p.name: digest(p) for p in destination.iterdir() if p.is_file()})
    (destination / 'transition-build.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('saved', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--variant', choices=VARIANTS, default='baseline')
    args = parser.parse_args()
    prepare(args.saved.resolve(strict=True), args.destination.resolve(), args.variant)
