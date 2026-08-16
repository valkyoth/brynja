#!/usr/bin/env python3
"""Descriptor-bound and allocation-bounded assurance input reads."""

from __future__ import annotations

import os
import stat
from contextlib import contextmanager
from pathlib import Path
from collections.abc import Iterator
from typing import BinaryIO


if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    GENERIC_READ = 0x80000000
    FILE_LIST_DIRECTORY = 0x00000001
    FILE_READ_ATTRIBUTES = 0x00000080
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_TAG_INFO_CLASS = 9

    class FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [
            ("FileAttributes", wintypes.DWORD),
            ("ReparseTag", wintypes.DWORD),
        ]

    KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    KERNEL32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    KERNEL32.CreateFileW.restype = wintypes.HANDLE
    KERNEL32.GetFileInformationByHandleEx.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    KERNEL32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    KERNEL32.CloseHandle.argtypes = (wintypes.HANDLE,)
    KERNEL32.CloseHandle.restype = wintypes.BOOL


def _open_windows_regular(path: Path) -> BinaryIO:
    handle = KERNEL32.CreateFileW(
        str(path),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
        None,
    )
    invalid = wintypes.HANDLE(-1).value
    if handle in (None, invalid):
        raise RuntimeError(f"could not securely open regular file: {path}")
    information = FileAttributeTagInfo()
    if not KERNEL32.GetFileInformationByHandleEx(
        handle,
        FILE_ATTRIBUTE_TAG_INFO_CLASS,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        KERNEL32.CloseHandle(handle)
        raise RuntimeError(f"could not inspect regular file: {path}")
    if information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
        KERNEL32.CloseHandle(handle)
        raise RuntimeError(f"could not securely open regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    try:
        descriptor = msvcrt.open_osfhandle(int(handle), flags)
    except OSError:
        KERNEL32.CloseHandle(handle)
        raise
    return os.fdopen(descriptor, "rb", closefd=True)


@contextmanager
def _hold_windows_directory(path: Path):
    handle = KERNEL32.CreateFileW(
        str(path),
        FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    invalid = wintypes.HANDLE(-1).value
    if handle in (None, invalid):
        raise RuntimeError("could not securely open case corpus")
    try:
        information = FileAttributeTagInfo()
        if not KERNEL32.GetFileInformationByHandleEx(
            handle,
            FILE_ATTRIBUTE_TAG_INFO_CLASS,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            raise RuntimeError("could not inspect case corpus")
        if information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
            raise RuntimeError("case corpus cannot be a reparse point")
        if not information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY:
            raise RuntimeError("case corpus is not a directory")
        yield
    finally:
        KERNEL32.CloseHandle(handle)


def _open_regular(path: Path) -> BinaryIO:
    if os.name == "nt":
        return _open_windows_regular(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RuntimeError(f"could not securely open regular file: {path}") from error
    return os.fdopen(descriptor, "rb", closefd=True)


def _read_open_regular(handle: BinaryIO, maximum: int, label: object) -> bytes:
    metadata = os.fstat(handle.fileno())
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError(f"case is not a regular file: {label}")
    if metadata.st_size > maximum:
        raise RuntimeError("case exceeds policy input bound")
    data = handle.read(maximum + 1)
    if len(data) > maximum:
        raise RuntimeError("case exceeds policy input bound")
    return data


def read_bounded_regular(path: Path, maximum: int) -> bytes:
    """Read at most maximum bytes from one already-open regular file."""
    if maximum < 0:
        raise RuntimeError("input bound cannot be negative")
    with _open_regular(path) as handle:
        return _read_open_regular(handle, maximum, path)


def bounded_entries(directory: Path, maximum_cases: int) -> list[Path]:
    """Enumerate no more than the allowed number of deterministic entries."""
    if maximum_cases < 1:
        raise RuntimeError("case bound must be positive")
    entries: list[Path] = []
    try:
        with os.scandir(directory) as iterator:
            for entry in iterator:
                if len(entries) == maximum_cases:
                    raise RuntimeError("case corpus exceeds policy bound")
                entries.append(directory / entry.name)
    except OSError as error:
        raise RuntimeError("could not enumerate case corpus") from error
    return sorted(entries)


def iter_bounded_corpus(
    directory: Path,
    maximum_cases: int,
    maximum_bytes: int,
) -> Iterator[bytes]:
    """Yield one bounded case at a time from a descriptor-owned directory."""
    if maximum_cases < 1 or maximum_bytes < 0:
        raise RuntimeError("corpus bounds are invalid")
    if os.name == "nt":
        with _hold_windows_directory(directory):
            for path in bounded_entries(directory, maximum_cases):
                yield read_bounded_regular(path, maximum_bytes)
        return
    flags = os.O_RDONLY | os.O_DIRECTORY
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(directory, flags)
    except OSError as error:
        raise RuntimeError("could not securely open case corpus") from error
    try:
        names: list[str] = []
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                if len(names) == maximum_cases:
                    raise RuntimeError("case corpus exceeds policy bound")
                names.append(entry.name)
        file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        file_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        for name in sorted(names):
            try:
                descriptor = os.open(name, file_flags, dir_fd=directory_fd)
            except OSError as error:
                raise RuntimeError(
                    f"could not securely open corpus entry: {name}"
                ) from error
            with os.fdopen(descriptor, "rb", closefd=True) as handle:
                data = _read_open_regular(handle, maximum_bytes, name)
            yield data
    finally:
        os.close(directory_fd)
