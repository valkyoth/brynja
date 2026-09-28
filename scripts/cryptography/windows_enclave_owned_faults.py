"""One-shot host faults around real public-marker enclave calls, not crypto."""
from windows_protection_probe import ProbeError, require

STAGES = ('before-fill', 'after-fill', 'after-clear', 'after-write-query')


class Injected(ProbeError):
    pass


class Fault:
    def __init__(self, stage):
        require(stage in STAGES, 'known owned fault required')
        self.stage = stage
        self.fired = False
        self.allocated = False
        self.trace = []
        self.queries = 0

    def inject(self, stage):
        if stage == self.stage and not self.fired:
            self.fired = True
            self.trace.append('injected:' + stage)
            raise Injected(stage)


class Api:
    def __init__(self, api, fault):
        self.inner, self.fault = api, fault

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def call(self, routine, op):
        if op == 2 and self.fault.allocated:
            self.fault.inject('before-fill')
        value = self.inner.call(routine, op)
        if op == 1 and value:
            self.fault.allocated = True
            self.fault.trace.append('allocated')
        if op in (2, 3, 5) and value == 8192:
            self.fault.trace.append({2: 'filled', 3: 'cleared', 5: 'zero-readback'}[op])
            if op == 2:
                self.fault.inject('after-fill')
            if op == 3:
                self.fault.inject('after-clear')
        if op == 4 and value == 1:
            self.fault.allocated = False
            self.fault.trace.append('released')
        return value

    def terminate(self, base):
        self.inner.terminate(base)
        self.fault.trace.append('terminated')

    def delete(self, base):
        self.inner.delete(base)
        self.fault.trace.append('deleted')


class Host:
    def __init__(self, host, fault):
        self.inner, self.fault = host, fault

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def lock(self, address, size):
        self.inner.lock(address, size)
        self.fault.trace.append('locked')

    def unlock(self, address, size):
        self.inner.unlock(address, size)
        self.fault.trace.append('unlocked')

    def working_set(self, address, shape):
        self.fault.queries += 1
        if self.fault.queries == 2:
            self.fault.inject('after-write-query')
        result = self.inner.working_set(address, shape)
        # Only report a verified page set, never merely a successful API call.
        from windows_protection_probe import locked_pages
        require(len(result) == 2, 'fault probe complete page observation required')
        locked_pages(result)
        self.fault.trace.append('pages-locked')
        return result


def validate_trace(trace, stage):
    require(type(trace) is list and 0 < len(trace) <= 32 and
            all(type(item) is str for item in trace), 'bounded fault trace required')
    # The exact sequences prove cleanup happened AFTER injection, even when
    # the fill/clear call completed but the host never received its result.
    start = ['allocated', 'zero-readback', 'locked', 'pages-locked']
    end = ['zero-readback', 'pages-locked', 'unlocked', 'released', 'terminated', 'deleted']
    middle = {
        'before-fill': ['injected:before-fill'],
        'after-fill': ['filled', 'injected:after-fill', 'cleared'],
        'after-clear': ['filled', 'pages-locked', 'cleared', 'injected:after-clear'],
        'after-write-query': ['filled', 'injected:after-write-query', 'cleared'],
    }
    require(stage in middle and trace == start + middle[stage] + end,
            'exact injected failure / cleanup order required')


def exercise(api, host, image, stage):
    from windows_enclave_owned import exercise as run
    fault = Fault(stage)
    try:
        run(Api(api, fault), Host(host, fault), image, False)
    except Injected as error:
        require(str(error) == stage and fault.fired, 'original injected failure must survive cleanup')
    else:
        raise ProbeError('fault did not fail the operation')
    validate_trace(fault.trace, stage)
    return {'strict_qualified': False, 'production_signed': False, 'synthetic_only': True,
            'full_worker_cleanup_proved': False, 'dump_exclusion_verified': False,
            'native_machine': api.machine, 'deleted': True, 'mode': 'injected-failure',
            'fault': stage, 'original_error_retained': True, 'trace': fault.trace}


def validate_record(value, stage):
    require(value.get('mode') == 'injected-failure' and value.get('fault') == stage and
            value.get('original_error_retained') is True, 'injected failure identity required')
    validate_trace(value.get('trace'), stage)
