"""Private real OS-copy experiment, three waves/ten leaves, PUBLIC oracle data."""
import argparse
import ctypes as c
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from collections import Counter

from windows_enclave_concurrent import ConcurrentNative, INVALID
from windows_enclave_concurrent_stack import working_set_budget
from windows_enclave_parallel_wave_native import Dispatch
from windows_enclave_parallel_wave_validate import validate as wave_validate, budget_check
from windows_enclave_window_lock import flags_check, geometry
from windows_protection_api import Windows
from windows_protection_probe import require

COPY_ERRORS = ('header-address', 'custom-address', 'input-address', 'output-address',
               'reserved', 'custom-tail', 'input-tail', 'shape')


def cases():
    normal = [dict(identity=i, block=b, tail=t, custom_bits=k, output_bits=o, mode='normal', fail_at=1)
              for i in range(1, 5) for b, t, k, o in ((7, 3, 17, 259), (168, 8, 0, 512))]
    normal += [dict(identity=2, block=1024, tail=1, custom_bits=8191, output_bits=8192, mode='normal', fail_at=1),
               dict(identity=3, block=1, tail=7, custom_bits=1, output_bits=0, mode='normal', fail_at=1)]
    template = normal[0]
    return normal + [dict(template, mode=mode) for mode in COPY_ERRORS] + [
        dict(template, mode=mode, fail_at=wave) for mode in ('deny', 'empty', 'partial', 'early') for wave in (1, 2, 3)
    ] + [dict(template, mode='root-deny')]


def oracle():
    path = Path(__file__).resolve().parents[1] / 'parallelhash/check-parallelhash-differential.py'
    spec = importlib.util.spec_from_file_location('input_oracle', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Fixture:
    def __init__(self, case):
        model = oracle()
        identity, block = case['identity'], case['block']
        total, custom_bits, output_bits = block * 9 * 8 + case['tail'], case['custom_bits'], case['output_bits']
        message = model.oracle.canonical(73 + total, total)
        custom = model.oracle.canonical(119, custom_bits)
        self.expected = model.parallel_hash(168 if identity % 2 else 136,
            model.oracle.byte_bits(message)[:total], block, model.oracle.byte_bits(custom)[:custom_bits],
            output_bits, identity > 2)
        self.message = (c.c_ubyte * len(message))(*message)
        self.custom = (c.c_ubyte * max(1, len(custom)))(*custom)
        self.output = (c.c_ubyte * max(1, len(self.expected)))(*([0xa5] * max(1, len(self.expected))))
        self.header = (c.c_uint64 * 16)(0x4252594e50485749, 1, identity, block, total,
            custom_bits, output_bits, c.addressof(self.message), c.addressof(self.custom) if custom_bits else 0,
            1, 0, 0, 0, 0, 0, 0)
        self.source, self.destination = c.addressof(self.header), c.addressof(self.output)
        mode = case['mode']
        if mode == 'header-address': self.source = 1
        elif mode == 'custom-address': self.header[8] = 1
        elif mode == 'input-address': self.header[7] = 1
        elif mode == 'output-address': self.destination = 1
        elif mode == 'reserved': self.header[10] = 1
        elif mode == 'custom-tail': self.custom[len(custom) - 1] |= 0x80
        elif mode == 'input-tail': self.message[len(message) - 1] |= 0x80
        elif mode == 'shape': self.header[4] = block * 8


def validate(record):
    case = record['case']
    require(case in cases(), 'exact known public case')
    mode = case['mode']
    success = mode in ('normal', 'early')
    require(record['enclave_execution'] is True and record['os_copy_executed'] is (mode != 'root-deny')
            and record['production_qualified'] is False and record['whole_image_cleanup_qualified'] is False,
            'honest native diagnostic scope')
    require(record['output_matches'] is success and record['output_unchanged'] is (not success or case['output_bits'] == 0),
            'oracle output or unchanged rejection sentinel')
    require(record['result'] == (1 if success else INVALID if mode == 'root-deny' else 0), 'fail-closed result')
    counts = record['copy_counts']
    require(type(counts) is list and len(counts) == 5 and all(type(v) is int for v in counts), 'copy counter shape')
    custom = int(case['custom_bits'] != 0)
    if success: expected = [1, custom, 3, 2, 0]
    elif mode == 'root-deny': expected = [0, 0, 0, 0, 0]
    elif mode == 'header-address': expected = [0, 0, 0, 0, 1]
    elif mode == 'custom-address': expected = [1, 0, 0, 0, 1]
    elif mode == 'input-address': expected = [1, custom, 0, 0, 1]
    elif mode == 'output-address': expected = [1, custom, 3, 1, 1]
    elif mode == 'reserved': expected = [1, 0, 0, 0, 0]
    elif mode in ('custom-tail', 'shape'): expected = [1, custom, 0, 0, 0]
    elif mode == 'input-tail': expected = [1, custom, 3, 0, 0]
    else: expected = [1, custom, case['fail_at'], 0, 0]
    require(counts == expected, 'exact OS-copy stage population')
    if mode not in COPY_ERRORS:
        wave_validate(record)
        return
    completed = 3 if mode == 'output-address' else 2 if mode == 'input-tail' else 0
    require(record['completed'] == completed and record['threads'] == 5
            and record['joined'] is True and record['root_stayed_live'] is True
            and record['public_fixture_only'] is True, 'copy-failure bounded lifetime')
    budget_check(record['working_set_budget'])
    expected_indices = {12} | set(range(4 * completed if completed < 3 else 10))
    frames = {f['index']: f for f in record['frames']}
    require(len(frames) == len(record['frames']) and set(frames) == expected_indices, 'copy failure frame population')
    events = record['events']
    expected_events = [[index, event] for index in expected_indices for event in (0, 1)]
    expected_events += [[12, offset + gen] for gen in range(1, completed + 1) for offset in (2, 6, 10)]
    require(events[0] == [12, 0] and events[-1] == [12, 1] and sorted(events) == sorted(expected_events),
            'exact events; root outlives copied staging and leaves')
    require({int(k): v for k, v in record['leaf_results'].items()} == {i: 1 for i in expected_indices - {12}},
            'exact completed leaf results')
    for gen in range(1, completed + 1):
        require(events.index([12, 2 + gen]) < events.index([12, 6 + gen]) < events.index([12, 10 + gen]),
                'native close before independent join')
        if gen > 1: require(events.index([12, 10 + gen - 1]) < events.index([12, 2 + gen]), 'join before reuse')
    areas = {}
    for index, frame in frames.items():
        low, high, marker, admitted, cleared, restored, body, changed = frame['values']
        geometry(low, 0)
        require(high == low + 65536 and low <= marker < high and
                [admitted, cleared, restored, body, changed] == [1, 1, 1, 1, 0], 'copy-failure frame cleared/restored')
        require(frame['trace'] == ['admit', 'lock', 'all-pages-locked', 'admit-ack', 'clear-confirmed',
                'still-locked', 'unlock', 'finish-ack'], 'copy failure clear before unlock')
        require(set(frame['snapshots']) == {'before', 'admitted', 'cleared'}, 'complete page evidence')
        for label, flags in frame['snapshots'].items(): flags_check(flags, 65536, label != 'before')
        require(len(frame['host_read_errors']) == (3 if completed else 0)
                and all(type(v) is int and v > 0 for v in frame['host_read_errors']), 'rejected live host reads')
        areas[index] = low - 4096, high + 4096
        if index != 12:
            gen = index // 4 + 1
            require(events.index([12, 2 + gen]) < events.index([index, 0]) < events.index([index, 1])
                    < events.index([12, 10 + gen]), 'worker contained by copy wave join')
    for left in expected_indices:
        for right in expected_indices:
            if left >= right or left != 12 and right != 12 and left // 4 != right // 4: continue
            a, b = areas[left], areas[right]
            require(a[1] <= b[0] or b[1] <= a[0], 'disjoint live root/worker windows')
    rejections = []
    for gen in range(1, completed + 1):
        for invalid in (0, gen - 1, gen + 1): rejections += [(gen, invalid * 16 + lane, INVALID) for lane in range(4)]
        lanes = 2 if gen == 3 else 4
        rejections += [(gen, gen * 16 + lane, INVALID) for lane in range(lanes, 5)]
        rejections += [(gen, INVALID, INVALID)] + [(gen, gen * 16 + lane, INVALID) for lane in range(lanes)]
    rejections += [(completed, gen * 16 + lane, INVALID) for gen in range(1, 4) for lane in range(4)]
    require(Counter(map(tuple, record['rejections'])) == Counter(rejections), 'exact stale/replay/closed probes')


def exercise(image, case):
    api, host = ConcurrentNative(), Windows()
    budget = working_set_budget(host)
    fixture = Fixture(case)
    base = api.create()
    initialized, dispatch, trampoline = False, None, None
    try:
        loaded, error = api.load(base, image)
        require(loaded, f'image load failed: {error}')
        threads = api.initialize(base)
        initialized = True
        require(threads == 5, 'five actual enclave threads')
        root, leaf, query, register, configure, copy_query = [api.export(base, name) for name in (
            b'PublicWaveRoot', b'PublicWaveWorker', b'PublicStackQuery', b'PublicStackRegister',
            b'PublicInputOutputSource', b'PublicInputQuery')]
        require(api.call(root, fixture.source) == 0, 'unconfigured root rejects without claim')
        dispatch = Dispatch(api, host, base, leaf, query, case['mode'], case['fail_at'])
        trampoline = c.WINFUNCTYPE(c.c_void_p, c.c_void_p)(dispatch)
        require(api.call(register, c.cast(trampoline, c.c_void_p).value) == 1, 'immutable callback registration')
        require(api.call(configure, fixture.destination) == 1 and api.call(configure, fixture.destination) == 0,
                'immutable public output registration')
        result = api.call(root, fixture.source)
        require(api.call(root, fixture.source) == 0, 'root replay rejects')
        require(not dispatch.errors and not dispatch.active, 'callbacks complete: ' + repr(dispatch.errors))
        dispatch.host_join()
        dispatch.collect(12)
        for index in range(13):
            if index not in dispatch.frames: require(api.call(query, index * 16) == INVALID, 'absent slot stays absent')
        for generation in range(1, 4):
            for lane in range(4): dispatch.reject(generation * 16 + lane)
        output = bytes(fixture.output)
        success = case['mode'] in ('normal', 'early')
        record = dict(case=case, identity=case['identity'], mode=case['mode'], fail_at=case['fail_at'],
            result=result, threads=threads, completed=dispatch.completed, leaf_results=dispatch.results,
            frames=list(dispatch.frames.values()), events=dispatch.events, rejections=dispatch.rejections,
            working_set_budget=budget, root_stayed_live=True, joined=True, public_fixture_only=True,
            production_qualified=False, whole_image_cleanup_qualified=False, enclave_execution=True,
            os_copy_executed=case['mode'] != 'root-deny', copy_counts=[api.call(copy_query, field) for field in range(5)],
            output_matches=success and output[:len(fixture.expected)] == fixture.expected,
            output_unchanged=output == bytes([0xa5]) * len(output))
        validate(record)
    finally:
        if dispatch is not None: dispatch.host_join()
        if initialized: api.terminate(base)
        api.delete(base)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--case', type=int)
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    if args.case is not None:
        print(json.dumps(exercise(image, cases()[args.case])))
        return
    require(not args.output.exists(), 'fresh output required')
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    records = []
    for index, case in enumerate(cases()):
        result = subprocess.run([sys.executable, __file__, str(image), str(args.output), '--case', str(index)],
            capture_output=True, text=True, timeout=90)
        require(result.returncode == 0 and not result.stderr and len(result.stdout) < 150000,
                f'bounded copied-input child {index}/{case}: {result.stdout[-1500:]} {result.stderr[-4500:]}')
        record = json.loads(result.stdout)
        validate(record)
        records.append(record)
        print(f'PRIVATE_COPIED_INPUT_VBS: case={index}; {case}; PASS', flush=True)
    require(digest == hashlib.sha256(image.read_bytes()).hexdigest(), 'unchanged image')
    args.output.write_text(json.dumps(dict(schema=1, image_sha256=digest, records=records,
        windows_build=sys.getwindowsversion().build, status='PRIVATE_PUBLIC_COPIED_INPUT_OBSERVATIONS_ONLY'), indent=2) + '\n')


if __name__ == '__main__': main()
