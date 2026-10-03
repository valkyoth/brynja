"""Validate exact private multi-wave observations; never promote qualification."""
from collections import Counter

from windows_enclave_concurrent import INVALID
from windows_enclave_window_lock import geometry, flags_check
from windows_protection_probe import require

MODES = ('normal', 'deny', 'empty', 'partial', 'early', 'root-deny')


def population(mode, fail_at):
    completed = 0 if mode == 'root-deny' else 3 if mode in ('normal', 'early') else fail_at
    indices = {12}
    for generation in range(1, completed + 1):
        if mode == 'empty' and generation == fail_at: continue
        for lane in range(2 if generation == 3 else 4):
            if mode == 'partial' and generation == fail_at and lane == 1: continue
            indices.add((generation - 1) * 4 + lane)
    return completed, indices


def budget_check(budget):
    require(budget['child_process_only'] is True, 'child-only working-set allowance')
    for name in ('before', 'requested', 'after'):
        bounds = budget[name]
        require(type(bounds) is list and len(bounds) == 2 and all(type(v) is int for v in bounds)
                and 0 < bounds[0] <= bounds[1] < 1 << 64, 'valid working-set bounds')
    require(budget['requested'] == [max(budget['before'][0], 8 * 1024 * 1024),
                                    max(budget['before'][1], 16 * 1024 * 1024)]
            and all(a >= r for a, r in zip(budget['after'], budget['requested'])), 'confirmed allowance')


def validate(record):
    mode, fail_at = record['mode'], record['fail_at']
    require(mode in MODES and type(fail_at) is int and fail_at in (1, 2, 3)
            and type(record['identity']) is int and record['identity'] in (1, 2, 3, 4), 'known case')
    completed, expected = population(mode, fail_at)
    require(record['completed'] == completed and record['result'] == (
        1 if mode in ('normal', 'early') else INVALID if mode == 'root-deny' else 0), 'exact completion/result')
    require(record['threads'] == 5 and record['root_stayed_live'] is True and record['joined'] is True
            and record['public_fixture_only'] is True and record['production_qualified'] is False
            and record['whole_image_cleanup_qualified'] is False, 'honest diagnostic scope')
    budget_check(record['working_set_budget'])
    frames = {frame['index']: frame for frame in record['frames']}
    require(len(frames) == len(record['frames']) and set(frames) == expected, 'complete unique frame population')
    events = record['events']
    expected_events = [[index, event] for index in expected for event in (0, 1)]
    expected_events += [[12, offset + generation] for generation in range(1, completed + 1) for offset in (2, 6, 10)]
    require(events and events[0] == [12, 0] and events[-1] == [12, 1]
            and sorted(events) == sorted(expected_events), 'exact lifecycle events; root outlives all waves')
    for generation in range(1, completed + 1):
        begin, close, join = [events.index([12, offset + generation]) for offset in (2, 6, 10)]
        require(begin < close < join, 'native close precedes native/host join')
        if generation > 1: require(events.index([12, 10 + generation - 1]) < begin, 'previous join before next wave')
        for index in expected - {12}:
            if index // 4 + 1 != generation: continue
            enter, finish = events.index([index, 0]), events.index([index, 1])
            require(begin < enter < finish < join, 'worker lifetime inside wave, clear before join')
            if mode == 'early' and generation == fail_at:
                require(enter < close < finish, 'early host return precedes worker cleanup')
            else:
                require(finish < close, 'normal host joins before native close')
    results = {int(key): value for key, value in record['leaf_results'].items()}
    require(len(results) == len(record['leaf_results']) and set(results) == expected - {12}, 'exact leaf result population')
    for index, result in results.items():
        denied = mode == 'deny' and index == (fail_at - 1) * 4 + 1
        require(result == (INVALID if denied else 1), 'exact leaf result')
    areas = {}
    for index, frame in frames.items():
        denied = mode == 'root-deny' or mode == 'deny' and index == (fail_at - 1) * 4 + 1
        expected_trace = ['admit', 'deny', 'clear-confirmed', 'finish-ack'] if denied else [
            'admit', 'lock', 'all-pages-locked', 'admit-ack', 'clear-confirmed', 'still-locked', 'unlock', 'finish-ack']
        require(frame['trace'] == expected_trace, 'complete clear-before-unlock trace')
        values = frame['values']
        require(type(values) is list and len(values) == 8 and all(type(v) is int and 0 <= v < 1 << 64 for v in values),
                'integer frame metadata')
        low, high, marker, admitted, cleared, restored, body, changed = values
        geometry(low, 0)
        require(low >= 4096 and low % 4096 == 0 and high == low + 65536 and admitted == body == int(not denied)
                and cleared == restored == 1 and changed == 0, 'admitted/cleared/restored frame')
        require(marker == 0 if denied else low <= marker <= high - 16, 'body marker inside window')
        areas[index] = low - 4096, high + 4096
        require(set(frame['snapshots']) == (set() if denied else {'before', 'admitted', 'cleared'}), 'all page snapshots')
        for name, flags in frame['snapshots'].items(): flags_check(flags, 65536, name != 'before')
        expected_reads = 0 if denied or index == 12 and expected == {12} else 3
        require(len(frame['host_read_errors']) == expected_reads
                and all(type(v) is int and v > 0 for v in frame['host_read_errors']), 'failed live host reads')
    # The OS may reuse worker stacks across waves; only concurrently live frames
    # must be disjoint. Event checks above require cleanup/join before such reuse.
    for left in expected:
        for right in expected:
            if left >= right or left != 12 and right != 12 and left // 4 != right // 4: continue
            a, b = areas[left], areas[right]
            require(a[1] <= b[0] or b[1] <= a[0], 'disjoint concurrently live windows/guards')
    rejections = []
    for generation in range(1, completed + 1):
        for invalid in (0, generation - 1, generation + 1):
            rejections += [(generation, invalid * 16 + lane, INVALID) for lane in range(4)]
        lanes = 2 if generation == 3 else 4
        rejections += [(generation, generation * 16 + lane, INVALID) for lane in range(lanes, 5)]
        rejections.append((generation, INVALID, INVALID))
        rejections += [(generation, generation * 16 + index % 4, INVALID) for index in expected - {12}
                       if index // 4 + 1 == generation]
    rejections += [(completed, generation * 16 + lane, INVALID) for generation in range(1, 4) for lane in range(4)]
    require(all(type(row) is list and len(row) == 3 and all(type(v) is int for v in row) for row in record['rejections'])
            and Counter(map(tuple, record['rejections'])) == Counter(rejections), 'all stale/future/duplicate/post-close probes')
