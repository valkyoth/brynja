#!/usr/bin/env python3
"""Cross-platform process-tree ownership for assurance adapters."""

from __future__ import annotations

import os
import signal
import subprocess
import threading


CREATE_SUSPENDED = 0x00000004
WINDOWS_JOB_OBJECT = "windows-job-object"
TEST_ONLY_POSIX_GROUP = "test-only-cooperative-posix-process-group"
EXTERNAL_POSIX_CONTAINMENT = frozenset(
    {
        "linux-cgroup-v2",
        "pid-namespace",
        "container-vm",
        "fork-setsid-denied-sandbox",
    }
)


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9

    class IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount", ctypes.c_uint64),
            ("WriteTransferCount", ctypes.c_uint64),
            ("OtherTransferCount", ctypes.c_uint64),
        ]

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimitInformation),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    NTDLL = ctypes.WinDLL("ntdll", use_last_error=True)
    KERNEL32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    KERNEL32.CreateJobObjectW.restype = wintypes.HANDLE
    KERNEL32.SetInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    KERNEL32.SetInformationJobObject.restype = wintypes.BOOL
    KERNEL32.AssignProcessToJobObject.argtypes = (
        wintypes.HANDLE,
        wintypes.HANDLE,
    )
    KERNEL32.AssignProcessToJobObject.restype = wintypes.BOOL
    KERNEL32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    KERNEL32.TerminateJobObject.restype = wintypes.BOOL
    KERNEL32.CloseHandle.argtypes = (wintypes.HANDLE,)
    KERNEL32.CloseHandle.restype = wintypes.BOOL
    NTDLL.NtResumeProcess.argtypes = (wintypes.HANDLE,)
    NTDLL.NtResumeProcess.restype = ctypes.c_long


def popen_tree_options() -> dict[str, object]:
    """Return platform process-group or suspended Job Object startup options."""
    if os.name == "nt":
        return {
            "creationflags": (
                subprocess.CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED
            )
        }
    return {"start_new_session": True}


def validate_tree_containment(
    mode: str | None,
    *,
    allow_test_only: bool = False,
) -> str:
    """Require enforced containment for hostile POSIX adapter execution."""
    if os.name == "nt":
        if mode not in (None, WINDOWS_JOB_OBJECT):
            raise RuntimeError("Windows adapters require Job Object containment")
        return WINDOWS_JOB_OBJECT
    if mode in EXTERNAL_POSIX_CONTAINMENT:
        return mode
    if allow_test_only and mode == TEST_ONLY_POSIX_GROUP:
        return mode
    raise RuntimeError(
        "hostile POSIX adapter execution requires externally enforced "
        "cgroup/PID-namespace/container/VM/fork-denied containment"
    )


class ProcessTree:
    """Own the platform process boundary used by an assurance adapter."""

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self.process = process
        self._lock = threading.Lock()
        self._terminated = False
        self._job = None
        if os.name == "nt":
            self._attach_windows_job()

    def _attach_windows_job(self) -> None:
        job = KERNEL32.CreateJobObjectW(None, None)
        if not job:
            self._abort_windows("could not create Windows Job Object")
        self._job = job
        limits = ExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not KERNEL32.SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            self._abort_windows("could not configure Windows Job Object")
        process_handle = wintypes.HANDLE(int(self.process._handle))
        if not KERNEL32.AssignProcessToJobObject(job, process_handle):
            self._abort_windows("could not assign adapter to Windows Job Object")
        if NTDLL.NtResumeProcess(process_handle) != 0:
            self._abort_windows("could not resume job-owned adapter")

    def _abort_windows(self, message: str) -> None:
        self.process.kill()
        self.process.wait()
        self.close()
        raise RuntimeError(message)

    def kill(self) -> None:
        """Terminate the owned Job Object or cooperative POSIX process group."""
        with self._lock:
            if self._terminated:
                return
            if os.name == "nt":
                if self._job and not KERNEL32.TerminateJobObject(self._job, 1):
                    if self.process.poll() is None:
                        raise RuntimeError("could not terminate Windows Job Object")
                self._terminated = True
                return
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                if self.process.poll() is None:
                    self.process.kill()
            self._terminated = True

    def close(self) -> None:
        """Close platform ownership resources."""
        if os.name == "nt" and self._job:
            KERNEL32.CloseHandle(self._job)
            self._job = None
