"""Public sentinels at actual VBS callbacks; no whole-image qualification."""
import argparse
import ctypes as c
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import windows_enclave_parallel_scheduler_native as scheduler
from windows_enclave_concurrent import ConcurrentNative, INVALID
from windows_enclave_callback_stack import ROOT, digest, require
from windows_enclave_transition_model import classify, validate, words


class Host:
    def __init__(self, path):
        self.dll = c.WinDLL(str(path.resolve(strict=True)))
        for name, restype, args in (
            ('TransitionConfigure', c.c_int, [c.c_void_p, c.c_uint32, c.c_uint32]),
            ('TransitionAddress', c.c_void_p, []),
            ('TransitionQuery', c.c_uint64, [c.c_uint64]),
            ('TransitionDirect', c.c_int, [c.c_uint64])):
            fn = getattr(self.dll, name)
            fn.restype, fn.argtypes = restype, args

    def configure(self, target, seed, avx):
        require(self.dll.TransitionConfigure(target, avx, seed) == 1, 'host CPU/OS admission')

    def snapshot(self): return [self.dll.TransitionQuery(i) for i in range(1, 76)]


def positive(path, seed, avx, missing=False):
    host = Host(path)
    callback = c.WINFUNCTYPE(c.c_void_p, c.c_void_p)(lambda word: 1)
    host.configure(c.cast(callback, c.c_void_p).value, seed, avx)
    require(host.dll.TransitionDirect(0x10042) == 1, 'ordinary direct control result')
    before = [host.dll.TransitionQuery(i) for i in range(77, 152)]
    require(before == words(seed, avx) and host.dll.TransitionQuery(76) == 1, 'direct poison proved')
    require(host.dll.TransitionQuery(0) == 1, 'direct capture entered')
    captured = host.snapshot()
    require(captured == ([0] * 75 if missing else words(seed, avx)), 'direct measurement control')
    return dict(native_vbs=False, seed=seed, avx=avx, missing_host_snapshot=missing,
                registers=classify(captured, seed, avx))


def exercise(image, directory, case, seed, avx):
    controls = [positive(directory / name, seed, avx, missing) for name, missing in
                (('host.dll', False), ('missing-host.dll', True))]
    host = Host(directory / 'host.dll')
    observed, before, counts = [], [], []

    class Dispatch(scheduler.Dispatch):
        def __call__(self, word):
            if word is not None and word & 255 in (0x42, 0x43, 0x44):
                observed.append(dict(event=word & 15, count=host.dll.TransitionQuery(0),
                                     registers=classify(host.snapshot(), seed, avx)))
            return super().__call__(word)

    class Native(ConcurrentNative):
        def initialize(self, base):
            count = super().initialize(base)
            self.register = super().export(base, b'PublicStackRegister')
            self.query = super().export(base, b'PublicTransitionQuery')
            configure = super().export(base, b'PublicTransitionConfigure')
            require(self.call(configure, seed | avx << 8) == 1 and self.call(configure, seed | avx << 8) == 0,
                    'one pre-execution configuration')
            require(self.call(self.query, 0) == INVALID, 'early observation rejected')
            return count

        def call(self, routine, value):
            if routine == getattr(self, 'register', None):
                host.configure(value, seed, avx)
                value = host.dll.TransitionAddress()
            return super().call(routine, value)

        def terminate(self, base):
            try:
                require(self.call(self.query, 76) == INVALID, 'invalid observation query')
                counts.append(self.call(self.query, 0))
                before.extend(self.call(self.query, i) for i in range(1, 76))
            finally: super().terminate(base)

    with patch.object(scheduler, 'ConcurrentNative', Native), patch.object(scheduler, 'Dispatch', Dispatch):
        record = scheduler.exercise(image, case)
    require(len(counts) == 1, 'one native result')
    return dict(measurement=dict(scheduler=record, before=before, count=counts[0], callbacks=observed),
                controls=controls)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--child', nargs=3, type=int, metavar=('CASE', 'SEED', 'AVX'))
    args = parser.parse_args()
    directory = args.directory.resolve(strict=True)
    image = directory / 'signed.dll'
    if args.child is not None:
        index, seed, avx = args.child
        words(seed, avx)
        require(0 <= index < len(scheduler.cases()), 'bounded case')
        print(json.dumps(exercise(image, directory, scheduler.cases()[index], seed, avx)))
        return
    output = directory / 'transition-observations.json'
    require(not output.exists(), 'fresh observations')
    build = json.loads((directory / 'transition-build.json').read_text())
    for name, expected in build['source_sha256'].items(): require(digest(ROOT / name) == expected, 'source drift: ' + name)
    for name, expected in build['generated_sha256'].items(): require(digest(directory / name) == expected, 'build drift: ' + name)
    sources = {p.relative_to(ROOT).as_posix(): digest(p)
               for pattern in ('windows_enclave*.py', 'windows_protection*.py')
               for p in (ROOT / 'scripts/cryptography').glob(pattern)}
    binaries = {name: digest(directory / name) for name in ('signed.dll', 'host.dll', 'missing-host.dll')}
    records = []
    indexes = (0, 4, 21, 26, 27) if build['variant'] == 'baseline' else (4,)
    for index in indexes:
        for seed in (90, 165):
            for avx in (0, 1):
                result = subprocess.run([sys.executable, __file__, str(directory), '--child',
                                         str(index), str(seed), str(avx)], capture_output=True, text=True, timeout=90)
                require(result.returncode == 0 and not result.stderr and len(result.stdout) < 2000000,
                        'child must complete: ' + result.stdout[-1000:] + result.stderr[-2700:])
                value = json.loads(result.stdout)
                require(value['measurement']['scheduler']['case'] == scheduler.cases()[index], 'case identity')
                scheduler.validate(value['measurement']['scheduler'])
                rejected = False
                try: validate(value['measurement'], seed, avx)
                except ValueError as error:
                    require(str(error) == 'callback stack: before-pattern measurement', 'specific measurement rejection')
                    rejected = True
                require(rejected == (build['variant'] != 'baseline'), 'compiled measurement mutation')
                records.append(dict(index=index, seed=seed, avx=avx, rejected=rejected, observation=value))
                print(f'TRANSITION_PROBE: {build["variant"]}; case={index}; seed={seed}; avx={avx}', flush=True)
    require(all(digest(ROOT / n) == h for n, h in sources.items()), 'unchanged runner closure')
    require(all(digest(directory / n) == h for n, h in binaries.items()), 'unchanged binaries')
    output.write_text(json.dumps(dict(schema=1, native_vbs=True, secret_material_used=False,
        whole_image_qualified=False, production_qualified=False, variant=build['variant'],
        windows_build=sys.getwindowsversion().build, source_sha256=sources, binaries=binaries,
        build_sha256=digest(directory / 'transition-build.json'), records=records), indent=2) + '\n')


if __name__ == '__main__': main()
