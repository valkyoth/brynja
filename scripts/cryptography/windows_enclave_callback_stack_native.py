"""Real VBS callback-frame observations in a separately instrumented image.

Uses public oracle inputs and the existing scheduler's complete functional and
lifetime validator. No assertion about register transitions or SDK stack depth.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import windows_enclave_parallel_scheduler_native as scheduler
from windows_enclave_callback_stack import ROOT, digest, require, validate, VARIANTS
from windows_enclave_concurrent import ConcurrentNative, INVALID


def exercise(image, case):
    observations = []

    class Observed(ConcurrentNative):
        def initialize(self, base):
            count = super().initialize(base)
            self.query = self.export(base, b'PublicCallbackFrameQuery')
            require(self.call(self.query, 0) == INVALID, 'early query rejected')
            return count

        def terminate(self, base):
            try:
                require(self.call(self.query, 21) == INVALID and
                        self.call(self.query, INVALID) == INVALID, 'invalid query rejected')
                rows = [[self.call(self.query, event * 7 + f) for f in range(7)] for event in range(3)]
                # Match the scheduler record's enclave-relative frame coordinates.
                for row in rows:
                    for f in (2, 3, 4, 5):
                        if row[f]: row[f] -= base
                observations.extend(rows)
            finally:
                super().terminate(base)

    with patch.object(scheduler, 'ConcurrentNative', Observed):
        record = scheduler.exercise(image, case)
    return dict(scheduler=record, callback_frames=observations)


def decode(result, case):
    require(result.returncode == 0 and not result.stderr and len(result.stdout) < 2000000,
            'child must complete normally: ' + result.stdout[-1000:] + result.stderr[-2000:])
    value = json.loads(result.stdout)
    require(type(value) is dict and set(value) == {'scheduler', 'callback_frames'}, 'exact child fields')
    require(value['scheduler']['case'] == case, 'case identity')
    scheduler.validate(value['scheduler'])
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('build', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--case', type=int)
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    if args.case is not None:
        require(0 <= args.case < len(scheduler.cases()), 'bounded child index')
        print(json.dumps(exercise(image, scheduler.cases()[args.case])))
        return
    require(not args.output.exists(), 'fresh observation file')
    build = json.loads(args.build.read_text())
    variant = build['variant']
    require(variant in VARIANTS, 'known variant')
    for name, expected in build['source_sha256'].items():
        require(digest(ROOT / name) == expected, 'source drift: ' + name)
    for name, expected in build['generated_sha256'].items():
        require(digest(args.build.parent / name) == expected, 'build-input drift: ' + name)
    sources = {p.relative_to(ROOT).as_posix(): digest(p)
               for pattern in ('windows_enclave*.py', 'windows_protection*.py')
               for p in (ROOT / 'scripts/cryptography').glob(pattern)}
    image_hash = digest(image)
    records = []
    # Baseline covers all 31 functional/lifetime cases. Mutants cover one empty
    # root (unaffected control) and one five-wave root (must reject observations).
    indexes = range(len(scheduler.cases())) if variant == 'baseline' else (0, 4)
    for index in indexes:
        case = scheduler.cases()[index]
        result = subprocess.run([sys.executable, __file__, str(image), str(args.build),
                                 str(args.output), '--case', str(index)],
                                capture_output=True, text=True, timeout=90)
        value = decode(result, case)
        rejected = False
        try:
            validate(value['callback_frames'], value['scheduler'])
        except ValueError as error:
            require(str(error).startswith('callback stack: '), 'expected measurement rejection')
            rejected = True
        require(rejected == (variant != 'baseline' and index == 4), 'nonvacuous compiled measurement control')
        records.append(dict(index=index, rejected=rejected, observation=value))
        print(f'ACTIVE_CALLBACK_STACK: {variant}; case={index}; expected outcome', flush=True)
    require(digest(image) == image_hash, 'unchanged signed image')
    require(all(digest(ROOT / name) == expected for name, expected in sources.items()), 'unchanged runner closure')
    output = dict(schema=1, variant=variant, native_vbs=True, whole_image_qualified=False,
                  production_qualified=False, secret_material_used=False,
                  image_sha256=image_hash, build_sha256=digest(args.build), source_sha256=sources,
                  windows_build=sys.getwindowsversion().build, records=records)
    args.output.write_text(json.dumps(output, indent=2) + '\n')


if __name__ == '__main__': main()
