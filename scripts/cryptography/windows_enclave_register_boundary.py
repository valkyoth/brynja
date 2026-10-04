"""Characterize actual stack wrappers with public register sentinels on Windows.

Not an enclave test: admission, finish and restore are assembly stubs. A surviving
sentinel proves the wrapper is not a register scrubber, NOT a shipped secret leak.
This diagnostic intentionally records the current gap, never qualification PASS.
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
                               ('admit', 'deny'), (90, 165)))
FIELDS = {'wrapper', 'isa', 'admission', 'seed', 'result', 'body_calls',
          'finish_calls', 'finish', 'returned'}


def validate(value, case):
    """Exact characterization of the current unmodified wrapper, not a gate."""
    wrapper, isa, admission, seed = case
    if type(value) is not dict or set(value) != FIELDS:
        raise ValueError('exact observation fields required')
    expected = dict(wrapper=wrapper, isa=isa, admission=admission, seed=seed,
                    result=91, body_calls=int(admission == 'admit'), finish_calls=1)
    if case not in CASES or any(type(value[k]) is not type(v) or value[k] != v
                               for k, v in expected.items()):
        raise ValueError('case identity or execution count mismatch')
    width = 32 if isa == 'avx' else 16
    sentinel = bytes([seed if admission == 'admit' else 0] * width).hex()
    for name in ('finish', 'returned'):
        if value[name] != [sentinel] * 6:
            raise ValueError('register characterization changed: ' + name)
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
    original = (SOURCE / FILES[2]).read_text()
    # Mutate the measuring apparatus, never the wrappers. Missing poison and
    # missing snapshots must both invalidate the observation, not pass vacuously.
    variants = {'baseline': original,
                'poison-omitted': original.replace('ProbePoison', 'ProbeZero'),
                'snapshot-omitted': original.replace('SNAPSHOT ProbeFinish', '; omitted snapshot')}
    reports = {}
    for variant, asm in variants.items():
        work = directory / variant
        work.mkdir()
        for name in FILES:
            shutil.copyfile(SOURCE / name, work / name)
        (work / FILES[2]).write_text(asm, encoding='utf-8')
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
                if variant == 'baseline' or case[2] == 'deny':
                    raise
                if not str(error).startswith('register characterization changed:'):
                    raise
                rejected = True
            if rejected != (variant != 'baseline' and case[2] == 'admit'):
                raise AssertionError('measurement mutant escaped')
            reports[variant].append(dict(case=case, stdout=result.stdout, rejected=rejected))
        print('REGISTER_PROBE: ' + variant + '; 16 cases', flush=True)
    sources = [SOURCE / name for name in FILES] + [Path(__file__).resolve(),
        ROOT / 'scripts/cryptography/test-windows-enclave-register-boundary.py']
    record = dict(schema=1, status='WRAPPER_REGISTER_RESIDUE_OBSERVED',
                  native_windows_process=True, platform=platform.platform(),
                  compiler_identity=compiler_identity,
                  enclave_execution=False, secret_material_used=False,
                  whole_image_qualified=False, production_qualified=False,
                  tested_vectors='XMM0..5; YMM0..5 when OS AVX available',
                  source_sha256={p.relative_to(ROOT).as_posix(): digest(p) for p in sources},
                  artifact_sha256={p.relative_to(directory).as_posix(): digest(p)
                                   for p in sorted(directory.rglob('*')) if p.is_file()},
                  reports=reports)
    (directory / 'register-boundary.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    print('Wrapper register residue characterized; enclave qualification: NOT ESTABLISHED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    execute(parser.parse_args().directory)
