"""Public-only admission/retained-owner checkpoints in unchanged signed images."""
import ctypes as c
import json
import os
from pathlib import Path
import sys

import windows_enclave_image_dump_model as model
import windows_enclave_persistent as storage
import windows_wer_probe as wer
from windows_protection_api import Windows, PTR, U32
from windows_protection_probe import Layout, layout, require


def child(image, phase):
    require(phase in model.PHASES and wer.APP.fullmatch(Path(sys.executable).name.lower()),
            'unique owned crash child required')
    host, api = Windows(), storage.WorkerNative()
    require(host.geometry() == (4096, 65536), 'native page geometry')
    host.bind('RaiseFailFastException', None, [PTR, PTR, U32])
    base = api.create()
    initialized = False
    resident = storage.Retained(host, base, False)

    def checkpoint(control):
        require(resident.error is None and resident.window.error is None, 'clean callback state')
        active = phase == 'admission'
        require(resident.window.phase == ('admitted' if active else 'finished')
                and resident.window.locked is active and resident.locked is (not active),
                'exact lifecycle checkpoint')
        low = resident.window.low
        flags = host.working_set(low, Layout(4096, model.WINDOW, model.WINDOW))
        storage.flags_check(flags, model.WINDOW, active)
        slot_flags = resident.snapshot() if resident.locked else []
        value = dict(pid=os.getpid(), phase=phase, base=base, control=control, window=low,
                     window_locked_pages=sum(bool(f & 1 and f & (1 << 22)) for f in flags),
                     retained=resident.address or 0, retained_locked_pages=len(slot_flags))
        model.validate(value, os.getpid(), phase)
        print(json.dumps(value), flush=True)
        host.dll.RaiseFailFastException(None, None, 0)
        raise RuntimeError('fail-fast unexpectedly returned')

    class Handshake(storage.Handshake):
        def __call__(self, argument):
            result = super().__call__(argument)
            if phase == 'admission' and self.phase == 'admitted' and result == 1:
                # No algorithm body has run at this point.
                checkpoint(control)
            return result

    try:
        loaded, error = api.load(base, image)
        require(loaded, 'current image load: '+str(error))
        require(api.initialize_worker(base) == 1, 'one synchronous worker')
        initialized = True
        def export(name): return api.check(api.GetProcAddress(base, name), 'checkpoint export')
        routine = export(b'PublicRetained')
        register = export(b'PublicLockedHost')
        report = export(b'PublicRetainedControl')
        resident.window = Handshake(host, base)
        callback = storage.guard.callback(resident)
        page, granularity = host.geometry()
        with wer.mapping(host, layout(page, granularity, model.SIZE), 0x5a, False) as control:
            require(api.call(register, c.cast(callback, c.c_void_p).value) == 1, 'register callback')
            require(api.call(routine, 0) == 95, 'completed protected creation and window cleanup')
            require(api.call(report, 16) == 1 and api.call(report, 19) == 1,
                    'retained owner created and live')
            checkpoint(control)
    finally:
        try:
            if initialized: api.terminate(base)
        finally:
            api.delete(base)
