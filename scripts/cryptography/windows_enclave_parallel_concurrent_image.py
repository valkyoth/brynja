"""Build a private one-shot guarded ParallelHash root/four-leaf experiment."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

import windows_enclave_parallel_concurrent_build as base
from windows_enclave_parallel_accelerated_worker_build import replace_exact
from windows_enclave_concurrent_stack import SOURCES as STACK_SOURCES

ROOT, SOURCE = base.ROOT, base.SOURCE
FILES = ('parallel_concurrent_bridge.rs', 'parallel_concurrent_gate.rs',
         'parallel_concurrent_bridge_tests.rs', 'parallel_concurrent_image.h',
         'parallel_concurrent_body.h', 'concurrent_stack.c', 'concurrent_stack_x64.asm',
         'cpu_inventory.c', 'parallel_accelerated_gate.h')


def expected():
    spec = importlib.util.spec_from_file_location('oracle', ROOT / 'scripts/parallelhash/check-parallelhash-differential.py')
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    rows = [list(oracle.parallel_hash(168 if identity % 2 else 136,
            oracle.oracle.byte_bits(bytes(range(128))), 32, [], 512, identity > 2))
            for identity in range(1, 5)]
    return 'pub const EXPECTED: [[u8; 64]; 4] = ' + repr(rows) + ';\n'


def image_sources(directory):
    text = (SOURCE / 'concurrent_stack.c').read_text()
    text = replace_exact(text, '#include "concurrent_entry.c"', '#include "parallel_concurrent_image.h"')
    text = replace_exact(text, 'static STACK_SLOT slots[4];', 'static STACK_SLOT slots[5];')
    # Both worker and diagnostic queries now include the separate root frame.
    if text.count('lane >= 4') != 2:
        raise ValueError('stack lane bounds changed')
    text = text.replace('lane >= 4', 'lane >= 5')
    start = text.index('__declspec(noinline) ULONG_PTR PublicStackBody')
    end = text.index('ULONG_PTR PublicStackFinish', start)
    text = text[:start] + '#include "parallel_concurrent_body.h"\n\n' + text[end:]
    (directory / 'concurrent_stack.c').write_text(text)
    text = (SOURCE / 'cpu_inventory.c').read_text()
    (directory / 'cpu_inventory.c').write_text(replace_exact(text, '#include "synthetic.c"', '#include <winenclave.h>'))
    text = (SOURCE / 'parallel_accelerated_gate.h').read_text()
    text = replace_exact(text, 'static BOOL accelerated_rejected;', 'static volatile LONG accelerated_rejected;')
    text = replace_exact(text, 'if (accelerated_rejected)', 'if (InterlockedCompareExchange(&accelerated_rejected, 0, 0))')
    text = replace_exact(text, 'accelerated_rejected = TRUE;', 'InterlockedExchange(&accelerated_rejected, 1);')
    (directory / 'parallel_accelerated_gate.h').write_text(text)


def build(directory, target, image):
    base.build(directory, target)
    for name in FILES:
        shutil.copyfile(SOURCE / name, directory / name)
    (directory / 'parallel_concurrent_expected.rs').write_text(expected())
    record = json.loads((directory / 'parallel-concurrent-build.json').read_text())
    common = record['commands'][-1][:record['commands'][-1].index('--crate-name')]
    deps = [part for name in ('brynja_core', 'brynja_crypto_cpu', 'brynja_hash_sha3', 'parallel_concurrent')
            for part in ('--extern', name + '=' + str(directory / ('lib' + name + '.rlib')))]
    binary = directory / ('bridge-test.exe' if 'windows' in target else 'bridge-test')
    command = common + ['--crate-name', 'parallel_concurrent_bridge', '--test',
        str(directory / 'parallel_concurrent_bridge.rs'), '-o', str(binary)] + deps
    base.base.run(command)
    record['commands'].append(command)
    if image:
        if target != 'x86_64-pc-windows-msvc':
            raise ValueError('Windows MSVC required')
        command = [word.replace('panic=unwind', 'panic=abort') for word in common] + [
            '--crate-name', 'parallel_concurrent_bridge', '--crate-type', 'staticlib', '-C', 'lto=fat',
            str(directory / 'parallel_concurrent_bridge.rs'), '--emit=' + ','.join(
                kind + '=' + str(directory / ('normal_rust.' + ext))
                for kind, ext in (('link', 'lib'), ('asm', 's'), ('llvm-ir', 'll')))] + deps
        base.base.run(command)
        record['commands'].append(command)
        image_sources(directory)
        (directory / 'link.cmd').write_text('@echo off\nsetlocal\n'
            'if "%VCToolsInstallDir%"=="" exit /b 90\ncd /d "%~dp0"\n'
            'ml64 /nologo /c /Foframe.obj concurrent_stack_x64.asm\nif errorlevel 1 exit /b 1\n'
            'cl /nologo /std:c11 /LD /O2 /W4 /WX /MT /guard:cf /Foconcurrent.obj '
            '/Fenormal.dll concurrent_stack.c frame.obj normal_rust.lib /link /ENCLAVE /NODEFAULTLIB '
            '/INCREMENTAL:NO /INTEGRITYCHECK /GUARD:MIXED '
            '/LIBPATH:"%VCToolsInstallDir%lib\\x64\\enclave" '
            '/LIBPATH:"%WindowsSdkDir%Lib\\%WindowsSDKVersion%ucrt_enclave\\x64" '
            'libcmt.lib libvcruntime.lib ucrt.lib vertdll.lib bcrypt.lib\n'
            'if errorlevel 1 exit /b 1\n'
            '"%WindowsSdkDir%bin\\%WindowsSDKVersion%x64\\veiid.exe" normal.dll\nexit /b %ERRORLEVEL%\n')
    record.update(status='PRIVATE_CONCURRENT_IMAGE_BUILD_ONLY', production_qualified=False)
    record['source_sha256'].update({path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in [SOURCE / name for name in FILES] + [ROOT / name for name in STACK_SOURCES] + [Path(__file__).resolve(),
            ROOT / 'scripts/cryptography/test-windows-enclave-parallel-bridge.py',
            ROOT / 'scripts/cryptography/test-windows-enclave-parallel-concurrent-native.py',
            ROOT / 'scripts/cryptography/windows_enclave_parallel_concurrent_native.py']})
    record['generated_sha256'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in directory.iterdir() if path.suffix in ('.rs', '.c', '.h', '.asm', '.cmd', '.s', '.ll', '.lib')}
    (directory / 'parallel-concurrent-image-build.json').write_text(json.dumps(record, indent=2) + '\n')
    return binary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--image', action='store_true')
    args = parser.parse_args()
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    build(args.directory.resolve(), target, args.image)
