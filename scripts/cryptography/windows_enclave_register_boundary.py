"""Test actual stack-wrapper register clearing with public Windows sentinels.

Not an enclave test: admission, finish and restore are assembly stubs. A surviving
sentinel proves the wrapper is not a register scrubber, NOT a shipped secret leak.
This proves the wrapper boundary only, never whole-image qualification.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import platform
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'assurance/windows-enclave-probe'
FILES = ('window_rust_x64.asm', 'concurrent_stack_x64.asm',
         'register_boundary_probe.asm', 'register_boundary_probe.c')
CASES = tuple(itertools.product(('sequential', 'concurrent'), ('sse2', 'avx'),
                               ('admit', 'deny'), (90, 165), ('restore-ok', 'restore-fail')))
FIELDS = {'wrapper', 'isa', 'admission', 'seed', 'result', 'body_calls',
          'finish_calls', 'finish', 'returned', 'body', 'restore_poison',
          'restore', 'nonvolatile', 'rbx', 'gpr'}


def validate(value, case):
    """Scope: XMM0..5, upper YMM0..15, return GPRs and preserved XMM6..15/RBX."""
    wrapper, isa, admission, seed, restore = case
    if type(value) is not dict or set(value) != FIELDS:
        raise ValueError('exact observation fields required')
    result = 91 if restore == 'restore-ok' else (0 if wrapper == 'sequential' else (1 << 64) - 1)
    expected = dict(wrapper=wrapper, isa=isa, admission=admission, seed=seed, restore=restore,
                    result=result, body_calls=int(admission == 'admit'), finish_calls=1,
                    rbx=int.from_bytes(bytes([seed] * 8), 'little'))
    if case not in CASES or any(type(value[k]) is not type(v) or value[k] != v
                               for k, v in expected.items()):
        raise ValueError('case identity or execution count mismatch')
    width = 32 if isa == 'avx' else 16
    vectors = {'body': [bytes([seed if admission == 'admit' else 0] * width).hex()] * 6,
               'restore_poison': [bytes([seed] * width).hex()] * 6,
               'finish': [bytes(width).hex()] * 6, 'returned': [bytes(width).hex()] * 6,
               'nonvolatile': [(bytes([seed] * 16) + bytes(width - 16)).hex()] * 10}
    for name, expected_vectors in vectors.items():
        if value[name] != expected_vectors:
            raise ValueError('register boundary mismatch: ' + name)
    if (type(value['gpr']) is not list or len(value['gpr']) != 6 or
            any(type(v) is not int or v != 0 for v in value['gpr'])):
        raise ValueError('register boundary mismatch: gpr')
    return value


def decode(result, case):
    if result.returncode or result.stderr or len(result.stdout) > 8192:
        raise ValueError('probe failed, unsupported, or oversized; not evidence')
    def unique(items):
        value = {}
        for key, entry in items:
            if key in value:
                raise ValueError('duplicate JSON key')
            value[key] = entry
        return value
    return validate(json.loads(result.stdout, object_pairs_hook=unique), case)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(directory):
    text = ('@echo off\nsetlocal\ncd /d "%~dp0"\n'
            'if "%VCToolsInstallDir%"=="" exit /b 90\n')
    for name in FILES[:3]:
        text += ('ml64 /nologo /c /Fo' + Path(name).stem + '.obj ' + name +
                 '\nif errorlevel 1 exit /b 1\n')
    text += ('cl /nologo /std:c11 /O2 /W4 /WX /MT /Foprobe-main.obj /Feprobe.exe register_boundary_probe.c '
             'window_rust_x64.obj concurrent_stack_x64.obj register_boundary_probe.obj '
             '/link /INCREMENTAL:NO\nexit /b %ERRORLEVEL%\n')
    (directory / 'build.cmd').write_text(text, encoding='utf-8')
    result = subprocess.run(['cmd', '/d', '/c', str(directory / 'build.cmd')],
                            capture_output=True, text=True, timeout=120)
    (directory / 'build.txt').write_text(result.stdout + result.stderr, encoding='utf-8')
    if result.returncode:
        raise RuntimeError('compilation must succeed: ' + result.stdout + result.stderr)


def execute(directory):
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    compiler = subprocess.run(['cl'], capture_output=True, text=True, timeout=10)
    compiler_identity = compiler.stdout + compiler.stderr
    if 'C/C++ Optimizing Compiler Version' not in compiler_identity or 'for x64' not in compiler_identity:
        raise RuntimeError('MSVC x64 compiler identity required')
    originals = {name: (SOURCE / name).read_text() for name in FILES}
    variants = {
        'baseline': None,
        'poison-omitted': ('probe', '    POISON_VECTORS\n    SNAPSHOT ProbeBody', '    SNAPSHOT ProbeBody'),
        'snapshot-omitted': ('probe', '    SNAPSHOT ProbeBody', '    ; no body snapshot'),
        'pre-clear-omitted': ('wrapper', '    BRYNJA_REGISTER_CLEAR 0, 1', '    ; missing pre-clear'),
        'return-clear-omitted': ('wrapper', '    BRYNJA_REGISTER_CLEAR 1, 0', '    ; missing return clear'),
        'xmm-clear-omitted': ('wrapper', '    pxor xmm3, xmm3', '    ; missing XMM clear'),
        'upper-clear-omitted': ('wrapper', '    vzeroupper', '    ; missing upper clear'),
        'gpr-clear-omitted': ('wrapper', '    xor r10d, r10d\n    xor r11d, r11d', '    xor r11d, r11d'),
        'rbx-preserve-omitted': ('wrapper', '    mov rbx, r10', '    ; missing RBX restore'),
        'force-baseline-state': ('wrapper', '    mov QWORD PTR [rbp + 32], 1', '    ; retain conservative baseline state'),
    }
    reports = {}
    for variant, mutation in variants.items():
        work = directory / variant
        work.mkdir()
        for name in FILES:
            shutil.copyfile(SOURCE / name, work / name)
        if mutation is not None:
            scope, before, after = mutation
            for name in (FILES[:2] if scope == 'wrapper' else (FILES[2],)):
                if originals[name].count(before) != 1:
                    raise AssertionError('mutation anchor: ' + name + ': ' + before)
                (work / name).write_text(originals[name].replace(before, after), encoding='utf-8')
        build(work)
        reports[variant] = []
        for case in CASES:
            result = subprocess.run([str(work / 'probe.exe'), *map(str, case)],
                                    capture_output=True, text=True, timeout=10)
            # Crashes/compiler failure/malformed output never count as detection.
            if result.returncode or result.stderr:
                raise RuntimeError('native probe execution failed: ' + result.stdout + result.stderr)
            rejected = False
            try:
                decode(result, case)
            except ValueError as error:
                if variant == 'baseline': raise
                if not str(error).startswith(('register boundary mismatch:', 'case identity or execution count mismatch')):
                    raise
                rejected = True
            wanted = variant != 'baseline'
            if variant in ('poison-omitted', 'snapshot-omitted', 'pre-clear-omitted'):
                wanted = case[2] == 'admit'
            if variant in ('upper-clear-omitted', 'force-baseline-state'): wanted = case[1] == 'avx'
            if rejected != wanted:
                raise AssertionError('measurement mutant escaped')
            reports[variant].append(dict(case=case, stdout=result.stdout, rejected=rejected))
        print('REGISTER_PROBE: ' + variant + '; 32 cases', flush=True)
    sources = [SOURCE / name for name in FILES] + [Path(__file__).resolve(),
        ROOT / 'scripts/cryptography/test-windows-enclave-register-boundary.py']
    record = dict(schema=2, status='WRAPPER_REGISTER_CLEANUP_PASS',
                  native_windows_process=True, platform=platform.platform(),
                  compiler_identity=compiler_identity,
                  enclave_execution=False, secret_material_used=False,
                  whole_image_qualified=False, production_qualified=False,
                  tested_vectors='XMM0..5 and upper YMM0..15 cleared; XMM6..15 and RBX preserved; return volatile GPRs cleared',
                  source_sha256={p.relative_to(ROOT).as_posix(): digest(p) for p in sources},
                  artifact_sha256={p.relative_to(directory).as_posix(): digest(p)
                                   for p in sorted(directory.rglob('*')) if p.is_file()},
                  reports=reports)
    (directory / 'register-boundary.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    print('Wrapper register cleanup: PASS; whole-image enclave qualification: NOT ESTABLISHED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    execute(parser.parse_args().directory)
