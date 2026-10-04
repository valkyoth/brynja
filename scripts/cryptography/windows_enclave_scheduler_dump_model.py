"""Bounded public-fixture dump observations, not whole-image qualification."""
import windows_minidump as dump
from windows_protection_probe import require

PHASES = ('root', 'workers', 'output')
SIZE, WINDOW, RESERVATION = 8192, 65536, 0x10000000


def validate(target, pid, phase):
    require(type(target) is dict and set(target) == {
        'pid', 'phase', 'base', 'control', 'staging', 'windows', 'cleared_frames',
        'completed', 'active', 'output_verified'}, 'exact dump checkpoint schema')
    require(type(pid) is int and pid > 0 and type(target['pid']) is int
            and target['pid'] == pid and phase in PHASES and target['phase'] == phase,
            'checkpoint process/phase identity')
    for key in ('base', 'control', 'staging', 'cleared_frames', 'completed', 'active'):
        require(type(target[key]) is int and 0 <= target[key] < 2**64, 'integer checkpoint metadata')
    base = target['base']
    require(base > 0 and base % WINDOW == 0 and base + RESERVATION <= 2**64,
            'bounded enclave reservation')
    windows = target['windows']
    require(type(windows) is list and 1 <= len(windows) <= 18, 'bounded measured windows')
    areas = []
    for row in windows:
        require(type(row) is dict and set(row) == {'low', 'locked_pages'}
                and type(row['low']) is int and type(row['locked_pages']) is int,
                'exact measured window fields')
        low = row['low']
        require(low % 4096 == 0 and base + 4096 <= low
                and low + WINDOW + 4096 <= base + RESERVATION, 'guarded window bounds')
        area = (low - 4096, low + WINDOW + 4096)
        require(all(area[1] <= a or b <= area[0] for a, b in areas), 'disjoint measured windows')
        areas.append(area)
        require(row['locked_pages'] == (0 if phase == 'output' else 16), 'phase-specific locks')
    expected = {'root': (1, 0, 0), 'workers': (5, 1, 4), 'output': (0, 5, 18)}[phase]
    require((target['active'], target['completed'], target['cleared_frames']) == expected,
            'exact scheduler checkpoint progress')
    require(target['output_verified'] is (phase == 'output'), 'phase-specific output verification')
    if phase != 'output':
        require(len(windows) == expected[0], 'complete active window population')
    for key, size in (('control', SIZE), ('staging', 33)):
        address = target[key]
        require(0 < address <= 2**64 - size and
                (address + size <= base or address >= base + RESERVATION), 'ordinary control outside enclave')
    require(target['control'] + SIZE <= target['staging'] or
            target['staging'] + 33 <= target['control'], 'distinct ordinary controls')


def analyze(blob, target, expected_output):
    validate(target, target.get('pid'), target.get('phase'))
    require(type(expected_output) is bytes and len(expected_output) == 33, 'bounded independent public output')
    ranges = dump.memory_ranges(blob)
    control = dump.observe(blob, target['control'], SIZE, 0x5a)
    require(control['complete_marker'], 'ordinary positive control missing/corrupt')
    expected = expected_output if target['phase'] == 'output' else b'\xa5' * 33
    staging, covered = bytearray(33), 0
    for start, length, offset in ranges:
        low, high = max(start, target['staging']), min(start + length, target['staging'] + 33)
        if low < high:
            staging[low-target['staging']:high-target['staging']] = blob[offset+low-start:offset+high-start]
            covered += high - low
    require(covered == 33 and staging == expected, 'phase-specific public staging missing/corrupt')

    def included(address, size):
        return sum(max(0, min(address + size, start + length) - max(address, start))
                   for start, length, _ in ranges)

    counts = [included(row['low'], WINDOW) for row in target['windows']]
    total = included(target['base'], RESERVATION)
    return dict(control=control, public_staging_verified=True, window_included_bytes=counts,
                reservation_included_bytes=total, windows_absent_in_this_dump=not any(counts),
                reservation_absent_in_this_dump=total == 0)
