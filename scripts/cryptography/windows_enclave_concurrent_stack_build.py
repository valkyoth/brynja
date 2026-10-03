"""Build public-only concurrent stack probes; signing is a separate explicit step."""
import argparse
from pathlib import Path
import shutil

from windows_enclave_concurrent import ROOT


def build(directory, mutant):
    directory.mkdir()
    for name in ('concurrent_entry.c', 'concurrent_stack.c', 'concurrent_stack_x64.asm'):
        shutil.copyfile(ROOT / 'assurance/windows-enclave-probe' / name, directory / name)
    define = '/DBRYNJA_PROBE_SKIP_CONCURRENT_CLEAR ' if mutant else ''
    (directory / 'link.cmd').write_text('@echo off\nsetlocal\n'
        'if "%VCToolsInstallDir%"=="" exit /b 90\ncd /d "%~dp0"\n'
        'ml64 /nologo /c '+define+'/Foframe.obj concurrent_stack_x64.asm\n'
        'if errorlevel 1 exit /b 1\n'
        'cl /nologo /std:c11 /LD /O2 /W4 /WX /MT /guard:cf /Foconcurrent.obj '
        '/Fenormal.dll concurrent_stack.c frame.obj /link /ENCLAVE /NODEFAULTLIB '
        '/INCREMENTAL:NO /INTEGRITYCHECK /GUARD:MIXED '
        '/LIBPATH:"%VCToolsInstallDir%lib\\x64\\enclave" '
        '/LIBPATH:"%WindowsSdkDir%Lib\\%WindowsSDKVersion%ucrt_enclave\\x64" '
        'libcmt.lib libvcruntime.lib ucrt.lib vertdll.lib\n'
        'if errorlevel 1 exit /b 1\n'
        '"%WindowsSdkDir%bin\\%WindowsSDKVersion%x64\\veiid.exe" normal.dll\n'
        'exit /b %ERRORLEVEL%\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--missing-clear-mutant', action='store_true')
    args = parser.parse_args()
    build(args.directory.resolve(), args.missing_clear_mutant)
