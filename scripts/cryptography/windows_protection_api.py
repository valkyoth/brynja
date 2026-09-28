"""Windows-only ctypes boundary for public synthetic platform experiments.

Not linked into Brynja; not an implementation of protected secret storage.
Fixed-width Windows ABI fields intentionally avoid ctypes.c_ulong on Unix.
"""
import ctypes as c
import sys

from windows_protection_probe import ProbeError, require

U16, U32, SIZE, PTR = c.c_uint16, c.c_uint32, c.c_size_t, c.c_void_p
COMMIT, RESERVE, RELEASE, PRIVATE = 0x1000, 0x2000, 0x8000, 0x20000
NOACCESS, READWRITE = 1, 4


class SystemInfo(c.Structure):
    _fields_ = [('architecture', U16), ('reserved', U16), ('page', U32),
                ('minimum', PTR), ('maximum', PTR), ('mask', SIZE),
                ('processors', U32), ('processor_type', U32), ('granularity', U32),
                ('level', U16), ('revision', U16)]


class MemoryInfo(c.Structure):
    _fields_ = [('base', PTR), ('allocation', PTR), ('allocation_protect', U32),
                ('partition', U16), ('size', SIZE), ('state', U32),
                ('protect', U32), ('kind', U32)]


class WorkingSet(c.Structure):
    _fields_ = [('address', PTR), ('flags', SIZE)]


def check_abi():
    require(c.sizeof(PTR) == 8, '64-bit Python required')
    require(c.sizeof(SystemInfo) == 48 and SystemInfo.granularity.offset == 40,
            'SYSTEM_INFO ABI')
    require(c.sizeof(MemoryInfo) == 48 and MemoryInfo.size.offset == 24
            and MemoryInfo.state.offset == 32, 'MEMORY_BASIC_INFORMATION ABI')
    require(c.sizeof(WorkingSet) == 16 and WorkingSet.flags.offset == 8,
            'PSAPI_WORKING_SET_EX_INFORMATION ABI')


class Windows:
    def __init__(self):
        require(sys.platform == 'win32', 'native Windows required; no emulated success')
        check_abi()
        self.dll = c.WinDLL('kernel32', use_last_error=True)
        self.bind('GetCurrentProcess', PTR, [])
        self.bind('IsWow64Process2', c.c_int32, [PTR, c.POINTER(U16), c.POINTER(U16)])
        self.bind('GetSystemInfo', None, [c.POINTER(SystemInfo)])
        self.bind('VirtualAlloc', PTR, [PTR, SIZE, U32, U32])
        self.bind('VirtualQuery', SIZE, [PTR, c.POINTER(MemoryInfo), SIZE])
        self.bind('VirtualLock', c.c_int32, [PTR, SIZE])
        self.bind('VirtualUnlock', c.c_int32, [PTR, SIZE])
        self.bind('VirtualFree', c.c_int32, [PTR, SIZE, U32])
        self.bind('K32QueryWorkingSetEx', c.c_int32, [PTR, PTR, U32])
        self.bind('WerRegisterExcludedMemoryBlock', c.c_int32, [PTR, U32])
        self.bind('WerUnregisterExcludedMemoryBlock', c.c_int32, [PTR])
        process, native = U16(), U16()
        self.ok(self.dll.IsWow64Process2(self.dll.GetCurrentProcess(),
                                        c.byref(process), c.byref(native)), 'IsWow64Process2')
        require(process.value == 0 and native.value in (0x8664, 0xaa64),
                'native x86-64 or Arm64 Python required, not WOW/emulation')
        self.native_machine = hex(native.value)

    def bind(self, name, result, arguments):
        try:
            function = getattr(self.dll, name)
        except AttributeError as error:
            raise ProbeError('required OS export absent: ' + name) from error
        function.restype, function.argtypes = result, arguments

    @staticmethod
    def ok(result, operation):
        if not result:
            raise ProbeError(f'{operation}: Windows error {c.get_last_error()}')
        return result

    @staticmethod
    def hresult(result, operation):
        require(result == 0, f'{operation}: HRESULT 0x{result & 0xffffffff:08x}')

    def geometry(self):
        info = SystemInfo()
        self.dll.GetSystemInfo(c.byref(info))
        return info.page, info.granularity

    def reserve(self, size):
        return self.ok(self.dll.VirtualAlloc(None, size, RESERVE, NOACCESS), 'reserve')

    def commit(self, address, size):
        result = self.ok(self.dll.VirtualAlloc(address, size, COMMIT, READWRITE), 'commit')
        require(result == address, 'commit returned unexpected address')

    def query(self, address):
        info = MemoryInfo()
        size = self.dll.VirtualQuery(address, c.byref(info), c.sizeof(info))
        require(size == c.sizeof(info), 'VirtualQuery complete result')
        return info

    def check_regions(self, base, data, shape):
        for address, size, state in ((base, shape.page, RESERVE),
                                     (data, shape.payload, COMMIT),
                                     (data + shape.payload, shape.page, RESERVE)):
            info = self.query(address)
            require(info.allocation == base and info.base == address and info.size >= size
                    and info.state == state and info.kind == PRIVATE, 'mapping geometry/state')
            if state == COMMIT:
                require(info.protect == READWRITE and info.size == size, 'payload-only access')
            # Protect is undefined for reserved pages. Their State is the guard check.

    def lock(self, address, size):
        self.ok(self.dll.VirtualLock(address, size), 'VirtualLock')

    def working_set(self, address, shape):
        entries = (WorkingSet * (shape.payload // shape.page))()
        for index, entry in enumerate(entries):
            entry.address = address + index * shape.page
        self.ok(self.dll.K32QueryWorkingSetEx(self.dll.GetCurrentProcess(),
                                            entries, c.sizeof(entries)), 'QueryWorkingSetEx')
        return [entry.flags for entry in entries]

    def register(self, address, size):
        require(0 < size <= 0xffffffff, 'WER size must fit DWORD without truncation')
        self.hresult(self.dll.WerRegisterExcludedMemoryBlock(address, size), 'WER register')

    def unregister(self, address):
        self.hresult(self.dll.WerUnregisterExcludedMemoryBlock(address), 'WER unregister')

    @staticmethod
    def fill(address, size, value):
        c.memset(address, value, size)

    @staticmethod
    def matches(address, size, value):
        return c.string_at(address, size) == bytes([value]) * size

    def unlock(self, address, size):
        self.ok(self.dll.VirtualUnlock(address, size), 'VirtualUnlock')

    def release(self, base):
        self.ok(self.dll.VirtualFree(base, 0, RELEASE), 'VirtualFree')
