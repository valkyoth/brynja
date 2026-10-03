"""Exact private scheduler observations; never promote production qualification."""
from collections import Counter
from windows_enclave_concurrent import INVALID
from windows_enclave_parallel_wave_validate import budget_check
from windows_enclave_window_lock import geometry, flags_check
from windows_protection_probe import require


def validate(record):
    from windows_enclave_parallel_scheduler_native import cases
    case = record['case']
    require(case in cases(), 'known exact scheduler case')
    mode, fail_at = case['mode'], case['fail_at']
    success = mode in ('normal', 'early')
    leaves = (case['input_bits'] + case['block']*8-1)//(case['block']*8)
    total = (leaves+3)//4
    completed = total if success else 0 if mode == 'root-deny' else fail_at
    require(record['completed'] == completed and record['threads'] == 5 and record['joined'] is True and
            record['enclave_execution'] is True and record['public_fixture_only'] is True and
            record['production_qualified'] is False and record['whole_image_cleanup_qualified'] is False, 'scope/completion')
    require(record['result'] == (1 if success else INVALID if mode == 'root-deny' else 0), 'exact root result')
    require(record['output_matches'] is success and record['output_unchanged'] is (not success or case['output_bits'] == 0),
            'oracle public output or unchanged rejection sentinel')
    counts = [0]*5 if mode == 'root-deny' else [1, int(case['custom_bits'] != 0), completed, 2 if success else 0, 0]
    require(record['copy_counts'] == counts, 'exact bounded copy counts')
    state = record['final_state']
    require(type(state) is int and state >> 32 == completed, 'final generation')
    if success or mode == 'root-deny': require(state == completed << 32, 'successful retirement/no root state')
    else: require(state & ((1 << 16) | (1 << 17) | (15 << 4) | (4095 << 20)) == 1 << 17,
                  'failed generation sealed, quiescent and no active query pins')
    budget_check(record['working_set_budget'])
    expected = {(0, 4)}
    for gen in range(1, completed+1):
        if mode == 'empty' and gen == fail_at: continue
        lanes = min(4, leaves-(gen-1)*4)
        for lane in range(lanes - int(mode == 'partial' and gen == fail_at)): expected.add((gen, lane))
    frames = {(f['generation'], f['lane']): f for f in record['frames']}
    require(len(frames) == len(record['frames']) and set(frames) == expected, 'unique exact frame population')
    events = record['events']
    expected_events = [[*key, event] for key in expected for event in (0, 1)]
    expected_events += [[gen, 4, event] for gen in range(1, completed+1) for event in (2, 3, 4)]
    require(events[0] == [0, 4, 0] and events[-1] == [0, 4, 1] and sorted(events) == sorted(expected_events),
            'exact root lifetime and generation events')
    for gen in range(1, completed+1):
        begin, close, join = [events.index([gen, 4, event]) for event in (2, 3, 4)]
        require(begin < close < join, 'native close before join')
        if gen > 1: require(events.index([gen-1, 4, 4]) < begin, 'join before record reuse')
        for key in expected:
            if key[0] != gen: continue
            enter, finish = [events.index([*key, event]) for event in (0, 1)]
            require(begin < enter < finish < join, 'worker cleanup before join')
            require(enter < close < finish if mode == 'early' and gen == fail_at else finish < close,
                    'early/normal host ordering')
    results = {int(k): v for k, v in record['leaf_results'].items()}
    require(len(results) == len(record['leaf_results']) and results == {
        gen*16+lane: INVALID if mode == 'deny' and gen == fail_at and lane == 0 else 1
        for gen, lane in expected if gen != 0}, 'complete leaf result population')
    areas = {}
    for key, frame in frames.items():
        gen, lane = key
        denied = mode == 'root-deny' or mode == 'deny' and gen == fail_at and lane == 0
        trace = ['admit', 'deny', 'clear-confirmed', 'finish-ack'] if denied else [
            'admit', 'lock', 'all-pages-locked', 'admit-ack', 'clear-confirmed', 'still-locked', 'unlock', 'finish-ack']
        require(frame['trace'] == trace, 'complete cleanup/unlock ordering')
        values = frame['values']
        require(type(values) is list and len(values) == 8 and all(type(v) is int and 0 <= v < 1 << 64 for v in values),
                'native frame metadata')
        low, high, marker, admitted, cleared, restored, body, changed = values
        geometry(low, 0)
        require(high == low+65536 and admitted == body == int(not denied) and cleared == restored == 1 and changed == 0,
                'complete admitted/cleared/restored frame')
        require(marker == 0 if denied else low <= marker <= high-16, 'bounded body marker')
        require(set(frame['snapshots']) == (set() if denied else {'before', 'admitted', 'cleared'}), 'all page snapshots')
        for label, flags in frame['snapshots'].items(): flags_check(flags, 65536, label != 'before')
        count = 0 if denied or gen == 0 and expected == {(0, 4)} else 3
        require(len(frame['host_read_errors']) == count and all(type(e) is int and e > 0 for e in frame['host_read_errors']),
                'rejected live host reads')
        areas[key] = low-4096, high+4096
    for left in expected:
        for right in expected:
            if left >= right or left[0] != 0 and right[0] != 0 and left[0] != right[0]: continue
            a, b = areas[left], areas[right]
            require(a[1] <= b[0] or b[1] <= a[0], 'disjoint concurrently live windows')
    probes = []
    for gen in range(1, completed+1):
        lanes = min(4, leaves-(gen-1)*4)
        for invalid in (0, gen-1, gen+1):
            for lane in range(4):
                probes += [(gen, 0, invalid*16+lane, INVALID), (gen, 1, invalid*256+lane*16, INVALID)]
        probes += [(gen, 0, gen*16+lane, INVALID) for lane in range(lanes, 5)]
        probes += [(gen, 0, gen*16+lane, INVALID) for g, lane in expected if g == gen]
        probes += [(gen, 1, gen*256+lane*16, INVALID) for lane in range(lanes) if (gen, lane) not in expected]
    for gen in range(1, completed+2):
        for lane in range(4):
            probes += [(completed, 0, gen*16+lane, INVALID)]
            if success: probes += [(completed, 1, gen*256+lane*16, INVALID)]
    require(Counter(map(tuple, record['rejections'])) == Counter(probes), 'exact stale/future/duplicate worker and query probes')
