"""Build the private bounded three-wave native VBS PUBLIC-fixture image."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

import windows_enclave_parallel_wave_bridge_build as base
from windows_enclave_parallel_accelerated_worker_build import replace_exact
from windows_enclave_concurrent_stack import SOURCES as STACK_SOURCES

ROOT, SOURCE = base.ROOT, base.SOURCE
FILES = ('parallel_wave_native_gate.h', 'parallel_wave_image.h', 'parallel_wave_body.h',
         'parallel_wave_entry.h', 'concurrent_stack.c', 'concurrent_stack_x64.asm',
         'cpu_inventory.c', 'parallel_accelerated_gate.h')


def sources(directory):
    for name in FILES: shutil.copyfile(SOURCE / name, directory / name)
    text = (SOURCE / 'concurrent_stack.c').read_text()
    text = replace_exact(text, '#include "concurrent_entry.c"', '#include "parallel_wave_image.h"')
    text = replace_exact(text, 'static STACK_SLOT slots[4];', 'static STACK_SLOT slots[13];')
    start = text.index('__declspec(noinline) ULONG_PTR PublicStackBody')
    end = text.index('ULONG_PTR PublicStackFinish', start)
    text = text[:start] + '#include "parallel_wave_body.h"\n\n' + text[end:]
    start = text.index('__declspec(dllexport) void* CALLBACK PublicStackWorker')
    end = text.index('/* Query only after', start)
    text = text[:start] + '#include "parallel_wave_entry.h"\n\n' + text[end:]
    text = replace_exact(text, 'if (lane >= 4)', 'if (lane >= 13)')
    (directory / 'concurrent_stack.c').write_text(text)
    text = (SOURCE / 'cpu_inventory.c').read_text()
    (directory / 'cpu_inventory.c').write_text(replace_exact(text, '#include "synthetic.c"', '#include <winenclave.h>'))
    text = (SOURCE / 'parallel_accelerated_gate.h').read_text()
    text = replace_exact(text, 'static BOOL accelerated_rejected;', 'static volatile LONG accelerated_rejected;')
    text = replace_exact(text, 'if (accelerated_rejected)', 'if (InterlockedCompareExchange(&accelerated_rejected, 0, 0))')
    text = replace_exact(text, 'accelerated_rejected = TRUE;', 'InterlockedExchange(&accelerated_rejected, 1);')
    (directory / 'parallel_accelerated_gate.h').write_text(text)


def build(directory):
    base.build(directory, 'x86_64-pc-windows-msvc')
    record = json.loads((directory / 'parallel-wave-bridge-build.json').read_text())
    previous = record['commands'][-1]
    common = [word.replace('panic=unwind', 'panic=abort') for word in previous[:previous.index('--crate-name')]]
    deps = previous[previous.index('--extern'):]
    command = common + ['--crate-name', 'parallel_wave_bridge', '--crate-type', 'staticlib',
        '-C', 'lto=fat', str(directory / 'parallel_wave_bridge.rs'), '--emit=' + ','.join(
            kind + '=' + str(directory / ('normal_rust.' + extension))
            for kind, extension in (('link', 'lib'), ('asm', 's'), ('llvm-ir', 'll')))] + deps
    base.base.base.base.run(command)
    sources(directory)
    (directory / 'link.cmd').write_text('@echo off\nsetlocal\n'
        'if "%VCToolsInstallDir%"=="" exit /b 90\ncd /d "%~dp0"\n'
        'ml64 /nologo /c /Foframe.obj concurrent_stack_x64.asm\nif errorlevel 1 exit /b 1\n'
        'cl /nologo /std:c11 /LD /O2 /W4 /WX /MT /guard:cf /Foconcurrent.obj '
        '/Fenormal.dll concurrent_stack.c frame.obj normal_rust.lib /link /ENCLAVE /NODEFAULTLIB '
        '/INCREMENTAL:NO /INTEGRITYCHECK /GUARD:MIXED '
        '/LIBPATH:"%VCToolsInstallDir%lib\\x64\\enclave" '
        '/LIBPATH:"%WindowsSdkDir%Lib\\%WindowsSDKVersion%ucrt_enclave\\x64" '
        'libcmt.lib libvcruntime.lib ucrt.lib vertdll.lib bcrypt.lib\nif errorlevel 1 exit /b 1\n'
        '"%WindowsSdkDir%bin\\%WindowsSDKVersion%x64\\veiid.exe" normal.dll\nexit /b %ERRORLEVEL%\n')
    record['commands'].append(command)
    record.update(status='PRIVATE_MULTI_WAVE_IMAGE_BUILD_ONLY', production_qualified=False)
    paths = [SOURCE / name for name in FILES] + [ROOT / name for name in STACK_SOURCES]
    paths += [Path(__file__).resolve(), ROOT / 'scripts/cryptography/windows_enclave_parallel_wave_native.py',
              ROOT / 'scripts/cryptography/windows_enclave_parallel_wave_validate.py',
              ROOT / 'scripts/cryptography/test-windows-enclave-parallel-wave-native.py',
              ROOT / 'scripts/cryptography/test-windows-enclave-wave-native-gate.py',
              ROOT / 'scripts/cryptography/test-windows-enclave-concurrent-c.py']
    record['source_sha256'].update({p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    record['generated_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir()
                                 if p.suffix in ('.rs', '.c', '.h', '.asm', '.cmd', '.s', '.ll', '.lib')}
    (directory / 'parallel-wave-image-build.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    build(parser.parse_args().directory.resolve())
