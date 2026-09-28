"""Synthetic VBS enclave lifecycle; not a protected-memory implementation."""
import ctypes as c
import sys

from windows_protection_probe import ProbeError, require

PTR, U32, SIZE, BOOL = c.c_void_p, c.c_uint32, c.c_size_t, c.c_int32
VALUES = (0, 1, 0x1234, 0xffffffff)


class CreateInfo(c.Structure):
    _fields_ = [('flags', U32), ('owner', c.c_ubyte * 32)]


class InitInfo(c.Structure):
    _fields_ = [('length', U32), ('threads', U32)]


class Native:
    def __init__(self):
        from windows_protection_api import Windows
        self.machine = Windows().native_machine  # No WOW/emulated execution.
        require(sys.platform == 'win32' and c.sizeof(PTR) == 8, 'native Windows 64-bit required')
        require(c.sizeof(CreateInfo) == 36 and c.sizeof(InitInfo) == 8, 'enclave structure ABI')
        self.kernel = c.WinDLL('kernel32', use_last_error=True)
        self.enclave = c.WinDLL('api-ms-win-core-enclave-l1-1-0.dll', use_last_error=True)
        self.bind('GetCurrentProcess', PTR, [])
        self.bind('IsEnclaveTypeSupported', BOOL, [U32])
        self.bind('CreateEnclave', PTR, [PTR, PTR, SIZE, SIZE, U32, PTR, U32, PTR])
        self.bind('LoadEnclaveImageW', BOOL, [PTR, c.c_wchar_p])
        self.bind('InitializeEnclave', BOOL, [PTR, PTR, PTR, U32, PTR])
        self.bind('GetProcAddress', PTR, [PTR, c.c_char_p])
        self.bind('CallEnclave', BOOL, [PTR, PTR, BOOL, c.POINTER(PTR)])
        self.bind('TerminateEnclave', BOOL, [PTR, BOOL])
        self.bind('DeleteEnclave', BOOL, [PTR])
        self.bind('SetErrorMode', U32, [U32])
        self.SetErrorMode(1)  # Suppress critical-error UI in this bounded child only.

    def bind(self, name, result, args):
        library = self.enclave if 'Enclave' in name else self.kernel
        function = getattr(library, name)
        function.restype, function.argtypes = result, args
        setattr(self, name, function)

    @staticmethod
    def check(result, stage):
        if not result:
            raise ProbeError(f'{stage}: Windows error {c.get_last_error()}')
        return result

    def create(self):
        self.check(self.IsEnclaveTypeSupported(16), 'VBS support')
        info = CreateInfo(0, (c.c_ubyte * 32)(0x42, 0x52))
        return self.check(self.CreateEnclave(self.GetCurrentProcess(), None, 0x10000000,
                                           0, 16, c.byref(info), 36, None), 'create')

    def load(self, address, image):
        c.set_last_error(0)
        success = self.LoadEnclaveImageW(address, str(image))
        return bool(success), c.get_last_error()

    def initialize(self, address):
        info = InitInfo(8, 1)
        self.check(self.InitializeEnclave(self.GetCurrentProcess(), address,
                                         c.byref(info), 8, None), 'initialize')

    def routine(self, address):
        return self.check(self.GetProcAddress(address, b'PublicProbe'), 'export')

    def call(self, routine, value):
        result = PTR()
        self.check(self.CallEnclave(routine, value, False, c.byref(result)), 'call')
        return result.value or 0

    def terminate(self, address):
        self.check(self.TerminateEnclave(address, False), 'terminate')

    def delete(self, address):
        self.check(self.DeleteEnclave(address), 'delete')


def exercise(api, image, negative):
    require(type(negative) is bool, 'explicit expected signature outcome')
    address = api.create()
    initialized = False
    failure = None
    result = {'strict_qualified': False, 'production_signed': False, 'synthetic_only': True,
              'native_machine': api.machine}
    try:
        loaded, error = api.load(address, image)
        if negative:
            require(not loaded and error == 577, 'unsigned image must reject with error 577')
            result['unsigned_rejection'] = error
        else:
            require(loaded, f'load: Windows error {error}')
            api.initialize(address)
            initialized = True
            routine = api.routine(address)
            for value in VALUES:
                require(api.call(routine, value) == value ^ 0x4252594e, 'synthetic result mismatch')
            result['calls_passed'] = len(VALUES)
    except Exception as error:
        failure = error
    finally:
        cleanup_errors = []
        if initialized:
            try:
                api.terminate(address)
            except Exception as error:
                cleanup_errors.append(str(error))
        try:
            api.delete(address)
        except Exception as error:
            cleanup_errors.append(str(error))
        if cleanup_errors:
            raise ProbeError('enclave cleanup failed: ' + '; '.join(cleanup_errors)) from failure
    if failure is not None:
        raise failure
    result['deleted'] = True
    return result
