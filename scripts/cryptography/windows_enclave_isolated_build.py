"""Build the separate 08A public-vector canary, never a release qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import windows_enclave_sha256_build as sha
import windows_enclave_sdk_identity as sdk

ROOT = sha.ROOT
SOURCE = ROOT / 'assurance/windows-enclave-probe'
FILES = ('isolated_sha256.rs', 'isolated_sha256.c', 'isolated_sdk.h',
         'window_guard.c', 'window_lock.c', 'synthetic.c', 'window_rust_x64.asm')


def wrapper(text):
    old = 'guarded_dirty:\n    xor eax, eax\nguarded_restore:'
    if text.count(old) != 1:
        raise ValueError('unique dirty cleanup branch required')
    # This canary must not call SDK guard restoration with a dirty compute
    # window. Fatal termination is deliberate, not successful error cleanup.
    return text.replace(old, 'guarded_dirty:\n    mov ecx, 7\n    int 29h\n'
                        '    jmp guarded_dirty\nguarded_restore:')


def build(directory, target, testing=False, saved=None, dirty=False):
    sha.check_graph()
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    common = ['rustc', '+1.98.1', '--edition=2024', '--target', target, '-D', 'warnings',
              '-C', 'opt-level=2', '-C', 'overflow-checks=yes', '-C', 'codegen-units=1',
              '-C', 'force-unwind-tables=yes', '-C', 'embed-bitcode=yes',
              '-C', 'panic=' + ('unwind' if testing else 'abort'),
              '-L', 'dependency=' + str(directory)]
    commands = []
    def run(args):
        command = common + args
        subprocess.run(command, cwd=ROOT, check=True, timeout=120)
        commands.append(command)
    for name in sha.CRATES:
        crate = name.replace('-', '_')
        args = ['--crate-type', 'rlib', '--crate-name', crate,
                str(ROOT/'crates'/name/'src/lib.rs'), '-o', str(directory/('lib'+crate+'.rlib'))]
        if name == 'brynja-hash-sha2':
            for dep in ('brynja_core', 'brynja_hash_core'):
                args += ['--extern', dep+'='+str(directory/('lib'+dep+'.rlib'))]
        run(args)
    args = [str(SOURCE/'isolated_sha256.rs'), '--crate-name', 'isolated_sha256']
    for dep in ('brynja_core', 'brynja_hash_sha2'):
        args += ['--extern', dep+'='+str(directory/('lib'+dep+'.rlib'))]
    if testing:
        executable = directory / ('test.exe' if 'windows' in target else 'test')
        run(args + ['--test', '-o', str(executable)])
        subprocess.run([str(executable)], check=True, timeout=60)
    else:
        if saved is None or target != 'x86_64-pc-windows-msvc':
            raise ValueError('explicit reviewed SDK and Windows x64 required')
        run(args + ['--crate-type', 'staticlib', '-C', 'lto=fat', '--emit=' + ','.join(
            kind+'='+str(directory/('normal_rust.'+suffix))
            for kind, suffix in [('link', 'lib'), ('asm', 's'), ('llvm-ir', 'll')])])
        _, code = sdk.reference(saved.read_bytes())
        header = '#define SDK_IMAGE_SIZE 0x36000U\n#define SDK_TEXT_RVA 0x1000U\n'
        header += 'static const unsigned char sdk_expected[] = {\n'
        header += '\n'.join(','.join(map(str, code[i:i+32]))+',' for i in range(0, len(code), 32))
        (directory/'sdk_expected.h').write_text(header+'\n};\n')
        for name in FILES:
            shutil.copyfile(SOURCE/name, directory/name)
        (directory/'window_rust_x64.asm').write_text(wrapper((SOURCE/'window_rust_x64.asm').read_text()))
        define = ' /DBRYNJA_PROBE_SKIP_GUARDED_CLEAR' if dirty else ''
        (directory/'link.cmd').write_text('@echo off\nsetlocal\n'
            'if "%VCToolsInstallDir%"=="" exit /b 90\ncd /d "%~dp0"\n'
            'ml64 /nologo /c'+define+' /Fowindow.obj window_rust_x64.asm\nif errorlevel 1 exit /b 1\n'
            'cl /nologo /std:c11 /LD /O2 /W4 /WX /MT /guard:cf /Fonormal.obj /Fenormal.dll '
            'isolated_sha256.c window.obj normal_rust.lib /link /ENCLAVE /NODEFAULTLIB '
            '/INCREMENTAL:NO /INTEGRITYCHECK /GUARD:MIXED /MAP:normal.map '
            '/LIBPATH:"%VCToolsInstallDir%lib\\x64\\enclave" '
            '/LIBPATH:"%WindowsSdkDir%Lib\\%WindowsSDKVersion%ucrt_enclave\\x64" '
            'libcmt.lib libvcruntime.lib ucrt.lib vertdll.lib bcrypt.lib\n'
            'if errorlevel 1 exit /b 1\n'
            '"%WindowsSdkDir%bin\\%WindowsSDKVersion%x64\\veiid.exe" normal.dll\nexit /b %ERRORLEVEL%\n')
    paths = [*sha.source_files(), *('assurance/windows-enclave-probe/'+n for n in FILES),
             'scripts/cryptography/windows_enclave_isolated_build.py',
             'scripts/cryptography/windows_enclave_sha256_build.py',
             'scripts/cryptography/windows_enclave_sdk_identity.py',
             'scripts/cryptography/windows_enclave_sdk_frames.py',
             'scripts/cryptography/windows_enclave_wrapper_binding.py']
    record = dict(schema=1, status='PUBLIC_CANARY_BUILD_ONLY', production_qualified=False,
                  target=target, commands=commands, dirty_cleanup_mutant=dirty,
                  source_sha256={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in paths},
                  generated_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                                    for p in directory.iterdir() if p.is_file()})
    (directory/'build.json').write_text(json.dumps(record, indent=2)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--target', default='x86_64-pc-windows-msvc')
    parser.add_argument('--test', action='store_true')
    parser.add_argument('--sdk', type=Path)
    parser.add_argument('--dirty', action='store_true')
    args = parser.parse_args()
    build(args.output, args.target, args.test, args.sdk, args.dirty)
