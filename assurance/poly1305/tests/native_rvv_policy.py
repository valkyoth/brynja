"""Native RV64 Linux package replay. Only a disposable child changes next-exec policy."""
import ctypes
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import sys


def off_on_exec(binary):
    # Linux UAPI: DEFAULT for this thread, OFF for its next exec, no inherit.
    # Call only from a separately launched Python process; never modify the
    # driver, sysctl, scheduler, or library consumer's thread policy.
    prctl = ctypes.CDLL(None, use_errno=True).prctl
    prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
    if prctl(69, 1 << 2, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'could not request OFF for child exec')
    os.execl(binary, binary)


def main():
    if platform.system() != 'Linux' or platform.machine() != 'riscv64':
        raise SystemExit('native RV64 Linux host with controllable V required')
    if len(sys.argv) == 3 and sys.argv[1] == '--child':
        off_on_exec(sys.argv[2])
    elif len(sys.argv) == 2:
        directory = Path(sys.argv[1]).resolve(strict=True)
        for v in ('1.90.0', '1.100.0'):
            owner = directory / ('owner-' + v)
            vectors = directory / ('vectors-' + v)
            def digests():
                return [hashlib.sha256(p.read_bytes()).hexdigest() for p in (vectors, owner)]
            before = digests()
            subprocess.run([owner], check=True, timeout=60)
            result = subprocess.check_output([vectors, '--exact', 'rfc_and_partitioned_long_updates'],
                                             text=True, timeout=120)
            if 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' not in result:
                raise SystemExit('RVV production MAC test did not run')
            denied = subprocess.run([sys.executable, __file__, '--child', owner],
                                    capture_output=True, timeout=60)
            if (denied.returncode, denied.stdout, denied.stderr) != (2, b'', b'required RVV: Unavailable\n'):
                raise SystemExit(f'{v}: expected a clean refusal after exec with V disabled; status {denied.returncode}')
            if before != digests():
                raise SystemExit('RVV binary changed during replay')
            print('riscv64gc-unknown-linux-gnu', v, *before)
    else:
        raise SystemExit('usage: native_rvv_policy.py EXPORTED_DIRECTORY')


if __name__ == '__main__':
    main()
