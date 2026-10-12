"""Finite saved-SDK success-continuation review, NOT an observed residue leak.

Start AFTER the opaque copy syscall, assuming status zero. Interpret only the
reviewed scalar instructions through the SDK export's normal return. No syscall
is executed, and no assumption about OS-returned vector contents is made.
"""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_sdk_status as status
import windows_enclave_stack_decode as decode

require = status.sdk.require
NAMES = ('EnclaveCopyIntoEnclave', 'EnclaveCopyOutOfEnclave',
         'copy_syscall_stub', 'copy_status', 'status_to_error', 'status_lookup')


def continuation(code, direction, thread_pointer, returned_status=0):
    """Small exact-encoding model, not a general x86 emulator or taint checker."""
    require(direction in NAMES[:2], 'one copy direction')
    require(type(thread_pointer) is bool, 'explicit GS-pointer alternative')
    require(type(returned_status) is int and returned_status == 0,
            'only the successful status-zero continuation is modeled')
    export = status.sdk.BODIES[direction][0]
    pc = status.sdk.BODIES['copy_syscall_stub'][0] + 10
    # Relative to copy-export entry. SUB 40 + CALL 8 have already executed.
    rsp, eax, ecx, zf = -48, 0, None, None
    stack = {-48: export + 12, 0: 'caller'}
    calls, path, status_writes = [], [], []
    for _ in range(100):
        require(pc in code, 'continuation stays in bound instruction population')
        raw = code[pc]
        path.append(pc)
        after = pc + len(raw)
        if raw == b'\xc3':
            require(rsp in stack, 'return has a matching saved address')
            target = stack.pop(rsp)
            rsp += 8
            if target == 'caller':
                require(rsp == 8 and eax == 0 and not calls,
                        'balanced SDK return with successful result')
                return dict(instruction_rvas=path, instructions=len(path),
                            status_writes=status_writes,
                            vector_writes=0, vector_state='unchanged_from_syscall_return')
            if calls:
                require(calls.pop() == target, 'matching nested call/return')
            pc = target
            continue
        if len(raw) == 5 and raw[0] in (0xe8, 0xe9):
            target = decode.relative(raw, pc)
            if raw[0] == 0xe8:
                rsp -= 8
                stack[rsp] = after
                calls.append(after)
            pc = target
            continue
        if len(raw) == 2 and raw[0] in (0xeb, 0x74, 0x75, 0x7e):
            require(raw[0] == 0xeb or type(zf) is bool, 'known branch flags')
            # All modeled TEST operands are zero or one (SF=OF=0); JLE is ZF.
            take = raw[0] == 0xeb or (not zf if raw[0] == 0x75 else zf)
            pc = decode.relative(raw, pc) if take else after
            continue
        if raw in (b'\x48\x83\xec\x28', b'\x48\x83\xec\x20'):
            rsp -= raw[-1]
        elif raw in (b'\x48\x83\xc4\x28', b'\x48\x83\xc4\x20'):
            rsp += raw[-1]
        elif raw == b'\x8b\xc8':
            ecx = eax
        elif raw == b'\x89\x4c\x24\x08':
            require(ecx == 0, 'only public status stored in caller home space')
            status_writes.append(dict(kind='stack', offset=rsp+8, bytes=4, value=ecx))
        elif raw == b'\x65\x48\x8b\x04\x25\x30\x00\x00\x00':
            eax = int(thread_pointer)  # Only nullness is used before EAX is reset.
        elif raw in (b'\x48\x85\xc0', b'\x85\xc0'):
            require(eax in (0, 1), 'bounded TEST value')
            zf = eax == 0
        elif raw == b'\x89\x88\x50\x12\x00\x00':
            require(thread_pointer and ecx == 0, 'non-null public thread-status store')
            status_writes.append(dict(kind='thread', offset=0x1250, bytes=4, value=ecx))
        elif raw == b'\x40\x53':
            rsp -= 8
            stack[rsp] = 'saved_rbx'
        elif raw == b'\x5b':
            require(stack.pop(rsp, None) == 'saved_rbx', 'matched nonvolatile restore')
            rsp += 8
        elif raw == b'\x45\x33\xc0':
            zf = True  # R8D cleared, unused on this success path.
        elif raw == b'\x85\xc9':
            require(ecx == 0, 'status lookup receives success')
            zf = True
        elif raw == b'\x33\xc0':
            eax, zf = 0, True
        else:
            raise ValueError('copy-success review: unmodeled instruction at '+hex(pc))
        pc = after
    raise ValueError('copy-success review: no bounded normal return')


def inspect(image, text):
    bound = status.inspect(image)  # Full-file identity AND reviewed body/edge checks.
    instructions = decode.parse(text)
    code, bodies = {}, {}
    for name in NAMES:
        rva, expected = (status.sdk.BODIES | status.BODIES)[name]
        raw = bytes.fromhex(expected)
        body = decode.body(image, dict(rva=rva, size=len(raw)), instructions)
        code.update({rva+at: item[0] for at, item in body.items()})
        bodies[name] = dict(rva=rva, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    paths = {direction+('/thread' if present else '/null'):
             continuation(code, direction, present)
             for direction in NAMES[:2] for present in (False, True)}
    return dict(schema=1, status='SUCCESS_CONTINUATION_CONTRACT_GAP_NOT_OBSERVED_LEAK',
                image_sha256=bound['image_sha256'], bodies=bodies, paths=paths,
                assumption='opaque OS copy returned status zero; normal continuation only',
                conclusion='SDK continuation preserves any vector state returned by OS',
                os_returned_secret_residue_observed=False,
                os_vector_state_payload_free_proven=False,
                error_or_exception_paths_qualified=False,
                sdk_transport_payload_handling_qualified=False,
                native_execution_added=False, whole_image_qualified=False,
                completion_package_closed=False, production_qualified=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--disassembly', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(inspect(args.sdk.read_bytes(), args.disassembly.read_text()), indent=2))
