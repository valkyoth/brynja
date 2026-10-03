"""Private variable-wave VBS diagnostic with public oracle inputs, not shipping API."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from windows_enclave_concurrent import ConcurrentNative, INVALID
from windows_enclave_concurrent_stack import working_set_budget
from windows_enclave_parallel_input_native import oracle
from windows_enclave_parallel_scheduler_host import Dispatch
from windows_enclave_parallel_scheduler_validate import validate
from windows_protection_api import Windows
from windows_protection_probe import require


def cases():
    normal = [dict(identity=i, block=7, input_bits=0 if leaves == 0 else (leaves - 1)*56+3,
                   custom_bits=17, output_bits=259, mode='normal', fail_at=1)
              for i in range(1, 5) for leaves in (0, 1, 4, 5, 17)]
    normal += [dict(identity=2, block=1024, input_bits=8*8192+1, custom_bits=8191, output_bits=8192, mode='normal', fail_at=1),
               dict(identity=4, block=1, input_bits=128*8+7, custom_bits=0, output_bits=512, mode='normal', fail_at=1),
               dict(identity=3, block=1, input_bits=0, custom_bits=0, output_bits=0, mode='normal', fail_at=1)]
    normal += [dict(identity=1, block=7, input_bits=(leaves-1)*56+3, custom_bits=17, output_bits=259,
                    mode='normal', fail_at=1) for leaves in (2, 3)]
    template = normal[4] # 17 leaves, five waves; last wave one worker.
    return normal + [dict(template, mode=mode, fail_at=wave) for mode, wave in (
        ('early', 1), ('early', 5), ('deny', 3), ('partial', 2), ('empty', 1), ('root-deny', 1))]


class Fixture:
    def __init__(self, case):
        model = oracle()
        bits, custom_bits, output_bits = case['input_bits'], case['custom_bits'], case['output_bits']
        message = model.oracle.canonical(71 + bits, bits)
        custom = model.oracle.canonical(131, custom_bits)
        self.expected = model.parallel_hash(168 if case['identity'] % 2 else 136,
            model.oracle.byte_bits(message)[:bits], case['block'], model.oracle.byte_bits(custom)[:custom_bits],
            output_bits, case['identity'] > 2)
        self.message = (c.c_ubyte * max(1, len(message)))(*message)
        self.custom = (c.c_ubyte * max(1, len(custom)))(*custom)
        self.output = (c.c_ubyte * max(1, len(self.expected)))(*([0xa5]*max(1, len(self.expected))))
        self.header = (c.c_uint64 * 16)(0x4252594e50485749, 1, case['identity'], case['block'], bits,
            custom_bits, output_bits, c.addressof(self.message) if bits else 0,
            c.addressof(self.custom) if custom_bits else 0, 1, 0, 0, 0, 0, 0, 0)


def exercise(image, case):
    api, host = ConcurrentNative(), Windows()
    budget, fixture = working_set_budget(host), Fixture(case)
    base = api.create()
    initialized, dispatch, trampoline = False, None, None
    try:
        loaded, error = api.load(base, image)
        require(loaded, f'image load: {error}')
        threads = api.initialize(base)
        initialized = True
        require(threads == 5, 'five enclave threads')
        root, leaf, query, register, configure, copy_query, state = [api.export(base, name) for name in (
            b'PublicWaveRoot', b'PublicWaveWorker', b'PublicStackQuery', b'PublicStackRegister',
            b'PublicInputOutputSource', b'PublicInputQuery', b'PublicSchedulerState')]
        dispatch = Dispatch(api, host, base, leaf, query, state, case)
        trampoline = c.WINFUNCTYPE(c.c_void_p, c.c_void_p)(dispatch)
        require(api.call(register, c.cast(trampoline, c.c_void_p).value) == 1, 'immutable callback')
        require(api.call(configure, c.addressof(fixture.output)) == 1 and api.call(configure, c.addressof(fixture.output)) == 0,
                'immutable public-output destination')
        result = api.call(root, c.addressof(fixture.header))
        require(api.call(root, c.addressof(fixture.header)) == 0, 'one root per image')
        require(not dispatch.errors and not dispatch.active, 'all callbacks complete: ' + repr(dispatch.errors))
        dispatch.host_join()
        dispatch.collect(0, 4)
        success = case['mode'] in ('normal', 'early')
        for generation in range(1, dispatch.completed + 2):
            for lane in range(4):
                dispatch.reject(generation, lane)
                if success: dispatch.reject(generation, lane, query=True)
        output = bytes(fixture.output)
        record = dict(case=case, result=result, threads=threads, completed=dispatch.completed,
            frames=list(dispatch.frames.values()), events=dispatch.events, rejections=dispatch.rejections,
            leaf_results=dispatch.results, copy_counts=[api.call(copy_query, f) for f in range(5)],
            final_state=api.call(state, 0), output_matches=success and output[:len(fixture.expected)] == fixture.expected,
            output_unchanged=output == bytes([0xa5])*len(output), working_set_budget=budget,
            enclave_execution=True, public_fixture_only=True, joined=True, production_qualified=False,
            whole_image_cleanup_qualified=False)
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
    require(not args.output.exists(), 'fresh observations required')
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    records = []
    for index, case in enumerate(cases()):
        result = subprocess.run([sys.executable, __file__, str(image), str(args.output), '--case', str(index)],
            capture_output=True, text=True, timeout=90)
        require(result.returncode == 0 and not result.stderr and len(result.stdout) < 2000000,
                f'scheduler child {index}/{case}: {result.stdout[-1500:]} {result.stderr[-4500:]}')
        record = json.loads(result.stdout)
        validate(record)
        records.append(record)
        print(f'PRIVATE_SCHEDULER_VBS: case={index}; {case}; PASS', flush=True)
    require(digest == hashlib.sha256(image.read_bytes()).hexdigest(), 'unchanged image')
    args.output.write_text(json.dumps(dict(schema=1, image_sha256=digest, records=records,
        windows_build=sys.getwindowsversion().build, status='PRIVATE_VARIABLE_WAVE_PUBLIC_OBSERVATIONS_ONLY'), indent=2)+'\n')


if __name__ == '__main__': main()
