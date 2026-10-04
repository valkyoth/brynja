"""Instrument a saved scheduler image build; diagnostic, never qualification.

No production source is patched. The new image retains the saved Rust archive
and stack wrapper, but adds address/count measurements to active C callbacks.
Signing uses the separate existing development-image workflow.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'assurance/windows-enclave-probe'
FILES = ('callback_stack_probe.h', 'callback_stack_probe.asm')
VARIANTS = ('baseline', 'missing-before', 'outside-reply')


def require(ok, message):
    if not ok: raise ValueError('callback stack: ' + message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace(text, before, after):
    require(text.count(before) == 1, 'unique instrumentation anchor')
    return text.replace(before, after)


def instrument(text):
    original = (SOURCE / 'concurrent_stack.c').read_text()
    start = original.index('static BOOL notify(')
    end = original.index('\nULONG_PTR PublicStackAdmit', start)
    return replace(text, original[start:end], '#include "callback_stack_probe.h"\n')


def header(variant):
    require(variant in VARIANTS, 'known compiled variant')
    text = (SOURCE / FILES[0]).read_text()
    if variant == 'missing-before':
        text = replace(text, '    row[after ? 1 : 0]++;', '    if (after) row[1]++;')
    if variant == 'outside-reply':
        text = replace(text, '    ULONG_PTR starts[3] = {frame, reply, stack};',
                       '    ULONG_PTR starts[3] = {frame, reply ^ (1ULL << 48), stack};')
    return text


def validate(rows, record):
    """Counts come from independently recorded host callback events, not rows."""
    require(type(rows) is list and len(rows) == 3, 'three callback rows')
    roots = [f for f in record['frames'] if f['generation'] == 0 and f['lane'] == 4]
    require(len(roots) == 1, 'one root frame')
    low, high = roots[0]['values'][:2]
    require(type(low) is int and type(high) is int and high == low + 65536, 'root bounds')
    for event, row in enumerate(rows, 2):
        require(type(row) is list and len(row) == 7 and
                all(type(v) is int and 0 <= v < 1 << 64 for v in row), 'bounded observation row')
        count = sum(lane == 4 and tag == event for _, lane, tag in record['events'])
        require(row[:2] == [count, count], 'before/after callback counts')
        if not count:
            require(row == [0] * 7, 'empty callback row')
            continue
        before, after, first, end, stack_low, stack_high, errors = row
        require(before == after and errors == 0, 'live admitted root frame')
        require(low <= first <= stack_low <= stack_high and stack_high + 40 <= end <= high,
                'callback frame/reply/shadow within root window')
        require(stack_low % 16 == stack_high % 16 == 8, 'call-entry stack alignment')
    return rows


def prepare(saved, destination, variant):
    saved = saved.resolve(strict=True)
    record = json.loads((saved / 'parallel-scheduler-image-build.json').read_text())
    for name, expected in record['source_sha256'].items():
        require(digest(ROOT / name) == expected, 'saved source drift: ' + name)
    for name, expected in record['generated_sha256'].items():
        require(Path(name).name == name and digest(saved / name) == expected, 'saved artifact drift: ' + name)
    require(not destination.exists(), 'fresh build directory')
    destination.mkdir(parents=True)
    for name in record['generated_sha256']: shutil.copyfile(saved / name, destination / name)
    path = destination / 'concurrent_stack.c'
    path.write_text(instrument(path.read_text()))
    (destination / FILES[0]).write_text(header(variant))
    shutil.copyfile(SOURCE / FILES[1], destination / FILES[1])
    path = destination / 'link.cmd'
    text = replace(path.read_text(), 'cl /nologo',
                   'ml64 /nologo /c /Focallback.obj callback_stack_probe.asm\nif errorlevel 1 exit /b 1\ncl /nologo')
    text = replace(text, 'frame.obj normal_rust.lib', 'frame.obj callback.obj normal_rust.lib')
    path.write_text(text)
    sources = [SOURCE / f for f in FILES] + [Path(__file__).resolve(),
        ROOT / 'scripts/cryptography/windows_enclave_callback_stack_native.py',
        ROOT / 'scripts/cryptography/test-windows-enclave-callback-stack.py']
    output = dict(schema=1, variant=variant, whole_image_qualified=False, production_qualified=False,
                  original_build_sha256=digest(saved / 'parallel-scheduler-image-build.json'),
                  source_sha256={p.relative_to(ROOT).as_posix(): digest(p) for p in sources},
                  generated_sha256={p.name: digest(p) for p in destination.iterdir() if p.is_file()})
    (destination / 'callback-stack-build.json').write_text(json.dumps(output, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('saved', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--variant', choices=VARIANTS, default='baseline')
    args = parser.parse_args()
    prepare(args.saved, args.destination, args.variant)
