"""Exact sequential-image dump checkpoints; not secret-erasure qualification."""
import windows_minidump as dump
from windows_protection_probe import require

PHASES = ('admission', 'retained')
SIZE, WINDOW, RESERVATION = 8192, 65536, 0x10000000


def validate(value, pid, phase):
    require(type(value) is dict and set(value) == {'pid', 'phase', 'base', 'control',
            'window', 'window_locked_pages', 'retained', 'retained_locked_pages'}, 'checkpoint schema')
    require(phase in PHASES and value['phase'] == phase and type(pid) is int
            and pid > 0 and value['pid'] == pid, 'checkpoint identity')
    for key in set(value)-{'phase'}:
        require(type(value[key]) is int and 0 <= value[key] < 2**64, 'integer checkpoint')
    base, low, page = value['base'], value['window'], value['retained']
    require(base > 0 and base % WINDOW == 0 and base + RESERVATION <= 2**64,
            'bounded enclave reservation')
    require(low % 4096 == 0 and base + 4096 <= low
            and low + WINDOW + 4096 <= base + RESERVATION, 'guarded window')
    require(value['window_locked_pages'] == (16 if phase == 'admission' else 0)
            and value['retained_locked_pages'] == (0 if phase == 'admission' else 1),
            'phase-specific residency')
    if phase == 'admission':
        require(page == 0, 'no retained owner before admitted body')
    else:
        require(page % 4096 == 0 and base + 4096 <= page
                and page + 8192 <= base + RESERVATION
                and (page + 8192 <= low - 4096 or low + WINDOW + 4096 <= page - 4096),
                'disjoint guarded retained page')
    control = value['control']
    require(0 < control <= 2**64-SIZE and
            (control+SIZE <= base or control >= base+RESERVATION), 'ordinary control outside enclave')


def analyze(blob, value):
    validate(value, value.get('pid'), value.get('phase'))
    ranges = dump.memory_ranges(blob)
    control = dump.observe(blob, value['control'], SIZE, 0x5a)
    require(control['complete_marker'], 'complete ordinary positive control required')
    def included(address, size):
        return sum(max(0, min(address+size, start+length)-max(address, start))
                   for start, length, _ in ranges)
    total = included(value['base'], RESERVATION)
    return dict(ordinary_control_bytes=control['included_bytes'],
                window_included_bytes=included(value['window'], WINDOW),
                retained_included_bytes=included(value['retained'], 4096) if value['retained'] else 0,
                reservation_included_bytes=total, reservation_absent_in_this_dump=total == 0)
