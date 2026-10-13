"""Run namespace mutations in a disposable Windows logon session, not the user's."""
import ctypes as c
import os
from ctypes import wintypes as w
from pathlib import Path
import subprocess
import sys
import tempfile


class Startup(c.Structure):
    _fields_ = [('cb', w.DWORD), ('reserved', w.LPWSTR), ('desktop', w.LPWSTR),
                ('title', w.LPWSTR), ('x', w.DWORD), ('y', w.DWORD),
                ('cx', w.DWORD), ('cy', w.DWORD), ('charsx', w.DWORD),
                ('charsy', w.DWORD), ('fill', w.DWORD), ('flags', w.DWORD),
                ('show', w.WORD), ('size', w.WORD), ('data', c.c_void_p),
                ('stdin', w.HANDLE), ('stdout', w.HANDLE), ('stderr', w.HANDLE)]


class Process(c.Structure):
    _fields_ = [('process', w.HANDLE), ('thread', w.HANDLE),
                ('pid', w.DWORD), ('tid', w.DWORD)]


def isolated(script):
    create = c.WinDLL('advapi32', use_last_error=True).CreateProcessWithLogonW
    create.argtypes = [w.LPCWSTR, w.LPCWSTR, w.LPCWSTR, w.DWORD,
                      w.LPCWSTR, w.LPWSTR, w.DWORD, c.c_void_p, w.LPCWSTR,
                      c.POINTER(Startup), c.POINTER(Process)]
    create.restype = w.BOOL
    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
    kernel.GetExitCodeProcess.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
    kernel.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
    kernel.CloseHandle.argtypes = [w.HANDLE]
    with tempfile.TemporaryDirectory(prefix='brynja-namespace-log-') as directory:
        log = Path(directory) / 'result.txt'
        command = c.create_unicode_buffer(subprocess.list2cmdline(
            [sys.executable, str(script), '--isolated', str(log)]))
        start, process = Startup(), Process()
        start.cb = c.sizeof(start)
        environment = c.create_unicode_buffer('\0'.join(
            f'{key}={value}' for key, value in sorted(os.environ.items())) + '\0\0')
        # LOGON_NETCREDENTIALS_ONLY: same local token, new logon namespace.
        # Synthetic credentials are neither validated nor used on a network.
        if not create('brynja-namespace-probe', '.', 'unused-local-probe', 2,
                      sys.executable, command, 0x08000400, environment, None,
                      c.byref(start), c.byref(process)):
            raise c.WinError(c.get_last_error())
        try:
            if kernel.WaitForSingleObject(process.process, 600000) != 0:
                kernel.TerminateProcess(process.process, 124)
                kernel.WaitForSingleObject(process.process, 10000)
                raise RuntimeError('isolated namespace test exceeded ten minutes')
            code = w.DWORD()
            if not kernel.GetExitCodeProcess(process.process, c.byref(code)):
                raise c.WinError(c.get_last_error())
            output = log.read_text()
            print(output)
            if code.value != 0:
                raise RuntimeError(f'isolated namespace test failed: {code.value}')
        finally:
            kernel.CloseHandle(process.thread)
            kernel.CloseHandle(process.process)
