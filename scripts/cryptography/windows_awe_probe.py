"""Synthetic AWE adapter experiment, not production protected storage.

Never grants account rights. Enables an already-assigned Lock Pages privilege
only in this short-lived probe process. PFN arrays remain opaque and unmodified.
"""
from contextlib import contextmanager
import ctypes as c

from windows_protection_api import Windows, PTR, U32, SIZE, RESERVE, READWRITE
from windows_protection_probe import require


class Luid(c.Structure):
    _fields_ = [('low', U32), ('high', c.c_int32)]


class Privileges(c.Structure):
    _fields_ = [('count', U32), ('luid', Luid), ('attributes', U32)]


def acquire(api, requested):
    """Exercise rollback independently from the real Windows FFI."""
    require(type(requested) is int and 0 < requested <= 256, 'bounded AWE page count')
    pages, count = api.allocate(requested)
    require(0 <= count <= requested, 'OS returned impossible AWE page count')
    if count != requested:
        if count:
            api.free(pages, count)
        require(False, 'partial AWE physical allocation rejected')
    return pages


@contextmanager
def mapping(api, shape, value):
    count = shape.payload // shape.page
    pages = acquire(api, count)
    base = None
    mapped = False
    try:
        base = api.reserve_awe(shape.reserved)
        address = base + shape.page
        api.map_pages(address, count, pages)
        mapped = True
        api.fill(address, shape.payload, value)
        require(api.matches(address, shape.payload, value), 'AWE synthetic marker readback')
        # Only this middle range is mapped. First and last pages have no PFNs.
        yield address
    finally:
        if mapped:
            api.fill(address, shape.payload, 0)
            require(api.matches(address, shape.payload, 0), 'complete AWE clear before release')
            api.map_pages(address, count, None)
        # Do not release the virtual range while uncertain live mappings remain.
        api.free(pages, count)
        if base is not None:
            api.release(base)


class Awe(Windows):
    def __init__(self):
        super().__init__()
        self.bind('AllocateUserPhysicalPages', c.c_int32, [PTR, c.POINTER(SIZE), c.POINTER(SIZE)])
        self.bind('MapUserPhysicalPages', c.c_int32, [PTR, SIZE, c.POINTER(SIZE)])
        self.bind('FreeUserPhysicalPages', c.c_int32, [PTR, c.POINTER(SIZE), c.POINTER(SIZE)])
        self.bind('CloseHandle', c.c_int32, [PTR])
        self.enable_assigned_privilege()

    def enable_assigned_privilege(self):
        require(c.sizeof(Privileges) == 16 and Privileges.attributes.offset == 12,
                'TOKEN_PRIVILEGES single-entry ABI')
        dll = c.WinDLL('advapi32', use_last_error=True)
        for name, result, arguments in (
                ('OpenProcessToken', c.c_int32, [PTR, U32, c.POINTER(PTR)]),
                ('LookupPrivilegeValueW', c.c_int32, [c.c_wchar_p, c.c_wchar_p, c.POINTER(Luid)]),
                ('AdjustTokenPrivileges', c.c_int32, [PTR, c.c_int32, c.POINTER(Privileges),
                                                     U32, PTR, PTR])):
            function = getattr(dll, name)
            function.restype, function.argtypes = result, arguments
        token = PTR()
        self.ok(dll.OpenProcessToken(self.dll.GetCurrentProcess(), 0x28, c.byref(token)), 'OpenProcessToken')
        try:
            state = Privileges(count=1, attributes=2)
            self.ok(dll.LookupPrivilegeValueW(None, 'SeLockMemoryPrivilege', c.byref(state.luid)),
                    'LookupPrivilegeValueW')
            c.set_last_error(0)
            result = dll.AdjustTokenPrivileges(token, False, c.byref(state), 0, None, None)
            error = c.get_last_error()
            self.ok(result, 'AdjustTokenPrivileges')
            require(error == 0, f'Lock Pages privilege unavailable; Windows error {error}')
        finally:
            self.ok(self.dll.CloseHandle(token), 'CloseHandle')

    def allocate(self, requested):
        require(type(requested) is int and 0 < requested <= 256, 'bounded AWE allocation')
        count = SIZE(requested)
        pages = (SIZE * requested)()
        self.ok(self.dll.AllocateUserPhysicalPages(self.dll.GetCurrentProcess(),
                                                 c.byref(count), pages), 'AllocateUserPhysicalPages')
        return pages, count.value

    def reserve_awe(self, size):
        return self.ok(self.dll.VirtualAlloc(None, size, RESERVE | 0x400000, READWRITE), 'AWE reserve')

    def map_pages(self, address, count, pages):
        self.ok(self.dll.MapUserPhysicalPages(address, count, pages), 'MapUserPhysicalPages')

    def free(self, pages, count):
        freed = SIZE(count)
        self.ok(self.dll.FreeUserPhysicalPages(self.dll.GetCurrentProcess(),
                                             c.byref(freed), pages), 'FreeUserPhysicalPages')
        require(freed.value == count, 'partial AWE release is not successful cleanup')
