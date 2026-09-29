#!/usr/bin/env python3
"""Instrument a temporary native-host callback copy at two fixed public checkpoints."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

import windows_enclave_native_host_build as host

NEEDLE = '        if (call->protocol(call->user, event - 2, call->command, call->output) != 1) { goto failed; }'
INSERT = '        HostDumpCheckpoint(call->instance->base, low, event, call->command, call->output);\n'
DECLARATION = ('extern void HostDumpCheckpoint(void*, ULONG_PTR, ULONG_PTR, '
               'const unsigned char*, const unsigned char*);\n')


def instrument(source):
    if source.count(NEEDLE) != 1 or source.count('#include "native_host.h"') != 1:
        raise ValueError('native callback changed; review checkpoint placement')
    if source.index('if (!call->locked || !pages(low, TRUE))') > source.index(NEEDLE):
        raise ValueError('checkpoint must follow lock observation')
    return source.replace('#include "native_host.h"', '#include "native_host.h"\n' + DECLARATION).replace(
        NEEDLE, INSERT + NEEDLE)


def build(directory):
    host.build(directory)
    destination = directory / 'native_host_transport.c'
    destination.write_text(instrument(destination.read_text()))
    shutil.copyfile(host.SOURCE / 'native_host_dump.c', directory / 'native_host_dump.c')
    sources = ('assurance/windows-enclave-probe/native_host_dump.c',
               'scripts/cryptography/windows_enclave_host_dump_build.py',
               'scripts/cryptography/windows_enclave_host_dump.py',
               'scripts/cryptography/test-windows-enclave-host-dump.py',
               'scripts/cryptography/windows_wer_probe.py',
               'scripts/cryptography/windows_minidump.py',
               'scripts/cryptography/windows_protection_probe.py',
               'scripts/cryptography/windows_protection_api.py')
    record = {'native_executed': False, 'strict_qualified': False,
              'source_sha256': {p: hashlib.sha256((host.ROOT / p).read_bytes()).hexdigest() for p in sources},
              'instrumented_transport_sha256': hashlib.sha256(destination.read_bytes()).hexdigest(),
              'insertion': INSERT, 'declaration': DECLARATION}
    (directory / 'dump-build.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    build(parser.parse_args().directory.resolve())
