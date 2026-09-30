#!/usr/bin/env python3
"""Bounded public in-enclave CPU inventory; never cryptographic admission."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

from windows_enclave_lifecycle import Native
from windows_protection_probe import require

ROOT = Path(__file__).resolve().parents[2]
INVALID = (1 << 64) - 1
FIELDS = ('magic', 'version', 'windows_features', 'max_leaf', 'leaf1_edx',
          'leaf1_ecx', 'leaf7_ebx', 'max_subleaf7', 'leaf71_eax', 'xcr0_low', 'xcr0_high')
KERNEL_CASES = {'sha256_sha_ni': 32, 'keccak_avx2': 16, 'sha256_batch_avx2': 256,
                'sha512_batch_avx2': 128, 'keccak_batch_avx2': 64}
SOURCES = ('assurance/windows-enclave-probe/cpu_inventory.c',
           'assurance/windows-enclave-probe/synthetic.c',
           'scripts/cryptography/windows_enclave_cpu_inventory.py',
           'scripts/cryptography/test-windows-enclave-cpu-inventory.py',
           'scripts/cryptography/windows_enclave_lifecycle.py',
           'scripts/cryptography/windows_protection_api.py',
           'scripts/cryptography/windows_protection_probe.py')
KERNEL_SOURCES = ('assurance/windows-enclave-probe/cpu_kernels.rs',
                  'assurance/windows-enclave-probe/cpu_kernel_entry.c',
                  'scripts/cryptography/windows_enclave_cpu_kernels_build.py',
                  'scripts/cryptography/test-windows-enclave-cpu-kernels.py',
                  'scripts/sha3/check-sha3-bit-differential.py')


def interpret(words):
    require(type(words) is list and len(words) == len(FIELDS)
            and all(type(word) is int and 0 <= word <= 0xffffffff for word in words),
            'complete nonfaulting 32-bit inventory required')
    data = dict(zip(FIELDS, words))
    require(data['magic'] == 0x42525943 and data['version'] == 1, 'CPU inventory identity')
    pf = data['windows_features']
    require(pf & ~15 == 0, 'unknown Windows feature bits')
    one = data['max_leaf'] >= 1
    seven = data['max_leaf'] >= 7
    sse2 = one and bool(data['leaf1_edx'] & (1 << 26)) and bool(pf & 1)
    xsave = one and data['leaf1_ecx'] & 0x0c000000 == 0x0c000000
    avx = (sse2 and xsave and bool(data['leaf1_ecx'] & (1 << 28))
           and pf & 6 == 6 and data['xcr0_low'] & 6 == 6)
    avx2 = avx and seven and bool(data['leaf7_ebx'] & (1 << 5)) and bool(pf & 8)
    # These are prerequisite observations, NOT permits, KATs or deployment proof.
    return {'raw': data, 'observed_prerequisites': {
        'sha256_sha_ni': sse2 and seven and bool(data['leaf7_ebx'] & (1 << 29)),
        'sha512_dedicated': avx2 and data['max_subleaf7'] >= 1
        and bool(data['leaf71_eax'] & 1),
        'avx2_batch_or_keccak': avx2},
        'cryptographic_execution_tested': False, 'production_qualified': False,
        'authorizes_execution': False}


def exercise(api, image, kernels=False):
    base = api.create()
    initialized = False
    try:
        loaded, error = api.load(base, image)
        require(loaded, f'CPU inventory load: {error}')
        api.initialize(base)
        initialized = True
        routine = api.check(api.GetProcAddress(base, b'PublicCpuInventory'), 'CPU inventory export')
        for value in (11, INVALID):
            require(api.call(routine, value) == INVALID, 'unknown CPU inventory query must reject')
        samples = [interpret([api.call(routine, i) for i in range(len(FIELDS))]) for _ in range(3)]
        require(all(item == samples[0] for item in samples), 'CPU inventory changed across calls')
        if kernels:
            features = samples[0]['observed_prerequisites']
            require(features['sha256_sha_ni'] and features['avx2_batch_or_keccak'],
                    'complete specialized-image bundle required')
            entry = api.check(api.GetProcAddress(base, b'PublicCpuKernelProbe'), 'CPU kernel export')
            for route in (0, 6, INVALID):
                require(api.call(entry, route) == 0, 'unknown kernel route must reject')
            for route, (name, count) in enumerate(KERNEL_CASES.items(), 1):
                require(api.call(entry, route) == count, 'native kernel differential/quarantine: '+name)
    finally:
        try:
            if initialized:
                api.terminate(base)
        finally:
            api.delete(base)
    return dict(samples[0], deleted=True, repeated_samples=3, native_machine=api.machine,
                public_kernel_cases=KERNEL_CASES if kernels else {},
                cryptographic_execution_tested=kernels)


def bounded(command, kernels=False):
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) < 16384,
            'clean bounded CPU inventory child required: ' + result.stderr[-2048:])
    value = json.loads(result.stdout)
    require(type(value) is dict and type(value.get('raw')) is dict
            and set(value['raw']) == set(FIELDS), 'complete CPU inventory child record')
    checked = interpret([value['raw'][name] for name in FIELDS])
    checked['cryptographic_execution_tested'] = kernels
    checked['public_kernel_cases'] = KERNEL_CASES if kernels else {}
    require(all(type(value.get(key)) is type(item) and value[key] == item for key, item in checked.items())
            and value.get('deleted') is True and value.get('repeated_samples') == 3
            and value.get('native_machine') == '0x8664', 'nonqualifying completed inventory')
    return value


def build(directory):
    directory.mkdir()  # Preserve previous images and observations.
    for name in ('cpu_inventory.c', 'synthetic.c'):
        shutil.copyfile(ROOT / 'assurance/windows-enclave-probe' / name, directory / name)
    (directory / 'link.cmd').write_text('@echo off\nsetlocal\n'
        'if "%VCToolsInstallDir%"=="" exit /b 90\ncd /d "%~dp0"\n'
        'cl /nologo /std:c11 /LD /O2 /W4 /WX /MT /guard:cf /Focpu.obj /Fenormal.dll '
        'cpu_inventory.c /link /ENCLAVE /NODEFAULTLIB /INCREMENTAL:NO /INTEGRITYCHECK /GUARD:MIXED '
        '/LIBPATH:"%VCToolsInstallDir%lib\\x64\\enclave" '
        '/LIBPATH:"%WindowsSdkDir%Lib\\%WindowsSDKVersion%ucrt_enclave\\x64" '
        'libcmt.lib libvcruntime.lib ucrt.lib vertdll.lib\n'
        'if errorlevel 1 exit /b 1\n'
        '"%WindowsSdkDir%bin\\%WindowsSDKVersion%x64\\veiid.exe" normal.dll\n'
        'exit /b %ERRORLEVEL%\n')
    (directory / 'sources.json').write_text(json.dumps({
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--build', action='store_true', help='write diagnostic image build inputs')
    parser.add_argument('--kernels', action='store_true', help='also require five public-vector kernel campaigns')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(not (args.build and args.child), 'build and capture are separate operations')
    if args.build:
        build(args.image.resolve())
        return
    image = args.image.resolve(strict=True)
    require(image.suffix.lower() == '.dll' and 0 < image.stat().st_size <= 4 * 1024 * 1024,
            'bounded existing diagnostic image required')
    if args.child:
        api = Native()
        require(api.machine == '0x8664', 'native x86-64 inventory required')
        print(json.dumps(exercise(api, image, args.kernels)))
        return
    sources = set(SOURCES)
    if args.kernels:
        sources.update(KERNEL_SOURCES)
        for crate in ('brynja-core', 'brynja-crypto-cpu'):
            sources.add(f'crates/{crate}/Cargo.toml')
            sources.update(p.relative_to(ROOT).as_posix() for p in (ROOT/'crates'/crate/'src').rglob('*.rs'))
    before = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sorted(sources)}
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    command = [sys.executable, str(Path(__file__).resolve()), str(image), '--child']
    record = bounded(command + (['--kernels'] if args.kernels else []), args.kernels)
    require(before == {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sources}
            and digest == hashlib.sha256(image.read_bytes()).hexdigest(), 'inventory inputs changed')
    record.update(schema=1, status='OBSERVATIONS_ONLY', source_sha256=before,
                  image_sha256=digest, windows_build=sys.getwindowsversion().build)
    print(json.dumps(record, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
