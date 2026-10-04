"""Crash only a uniquely named public-fixture child, at measured VBS checkpoints."""
import ctypes as c
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

import windows_enclave_parallel_scheduler_native as scheduler
from windows_enclave_window_lock import flags_check
import windows_enclave_scheduler_dump_model as model
import windows_wer_probe as wer
from windows_protection_api import Windows, PTR, U32
from windows_protection_probe import Layout, layout, require


def child(image, phase):
    require(phase in model.PHASES and wer.APP.fullmatch(Path(sys.executable).name.lower()) is not None,
            'unique owned crash child required')
    host = Windows()
    host.bind('RaiseFailFastException', None, [PTR, PTR, U32])
    fixtures, dispatches, validated = [], [], []
    original_validate = scheduler.validate

    def validate(record):
        original_validate(record)
        validated.append(record)

    def checkpoint(dispatch, control):
        require(not dispatch.errors and len(fixtures) == 1, 'clean scheduler at checkpoint')
        fixture = fixtures[0]
        with dispatch.lock:
            if phase == 'output':
                require(not dispatch.active and bytes(fixture.output) == fixture.expected,
                        'completed independent public-output comparison')
                lows = sorted({dispatch.base + row['values'][0] for row in dispatch.frames.values()})
            else:
                lows = sorted(area[0] + 4096 for area in dispatch.active.values())
                require(all(dispatch.handshakes[key].phase == 'admitted'
                            and dispatch.handshakes[key].locked for key in dispatch.active),
                        'all measured windows admitted and locked')
            windows = []
            for low in lows:
                flags = host.working_set(low, Layout(4096, model.WINDOW, model.WINDOW))
                flags_check(flags, model.WINDOW, phase != 'output')
                windows.append(dict(low=low, locked_pages=sum(bool(f & 1 and f & (1 << 22)) for f in flags)))
            target = dict(pid=os.getpid(), phase=phase, base=dispatch.base, control=control,
                staging=c.addressof(fixture.output), windows=windows, active=len(dispatch.active),
                completed=dispatch.completed, cleared_frames=len(dispatch.frames), output_verified=phase == 'output')
            model.validate(target, os.getpid(), phase)
        print(json.dumps(target), flush=True)
        host.dll.RaiseFailFastException(None, None, 0)
        raise RuntimeError('fail-fast unexpectedly returned')

    class Fixture(scheduler.Fixture):
        def __init__(self, case):
            super().__init__(case)
            fixtures.append(self)

    class Dispatch(scheduler.Dispatch):
        def __init__(self, *args):
            super().__init__(*args)
            dispatches.append(self)

        def dispatch(self):
            if phase == 'root': checkpoint(self, control)
            return super().dispatch()

        def observe(self):
            super().observe()
            # Barrier action: all four workers are still held, before their
            # current bodies. First wave completed; this is NOT mid-compression.
            if phase == 'workers' and self.generation == 2: checkpoint(self, control)

    class Native(scheduler.ConcurrentNative):
        def terminate(self, base):
            # exercise() has validated output, joins, frame erasure and unlocks.
            if phase == 'output' and len(dispatches) == 1:
                require(len(validated) == 1, 'functional scheduler validation completed before dump')
                checkpoint(dispatches[0], control)
            return super().terminate(base)

    page, granularity = host.geometry()
    with wer.mapping(host, layout(page, granularity, model.SIZE), 0x5a, False) as control:
        with patch.object(scheduler, 'Fixture', Fixture), patch.object(scheduler, 'Dispatch', Dispatch), \
                patch.object(scheduler, 'ConcurrentNative', Native), patch.object(scheduler, 'validate', validate):
            scheduler.exercise(image, scheduler.cases()[4])
    raise RuntimeError('required crash checkpoint not reached')
