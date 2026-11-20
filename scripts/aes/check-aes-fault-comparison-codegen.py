#!/usr/bin/env python3
"""Optional leaf inspection; NOT an AES fault-profile or release gate."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from aes_fault_comparison_codegen import inspect


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=('x86_64', 'aarch64'), required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--objdump', default='objdump', help='GNU objdump for x86; LLVM objdump for ARM')
    args = parser.parse_args()
    try:
        data = args.binary.read_bytes()
        if not data.startswith(b'\x7fELF'):
            raise ValueError('ELF observation only')
        header = subprocess.run([args.objdump, '-f', str(args.binary)], capture_output=True,
                                text=True, check=True, timeout=30).stdout
        expected = 'architecture: i386:x86-64,' if args.arch == 'x86_64' else 'architecture: aarch64'
        if expected not in header:
            raise ValueError('wrong object architecture')
        dumped = subprocess.run([args.objdump, '-d', '--demangle', '--no-show-raw-insn', str(args.binary)],
                                capture_output=True, text=True, check=True, timeout=30).stdout
        result = inspect(dumped, args.arch)
        print(json.dumps(dict(arch=args.arch, binary_sha256=hashlib.sha256(data).hexdigest(), leaves=result), sort_keys=True))
        print('OPAQUE_COMPARISON_LEAVES_OBSERVED; NOT caller, timing or fault-profile qualification')
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('comparison observation failed: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
