#!/usr/bin/env python3
"""Read-only enclave availability observation; never admission or activation.

Does not create enclaves, enable VBS, change registry/boot policy, install signing
certificates or execute cryptography. False support is a valid negative result.
"""
import ctypes as c
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from windows_protection_api import Windows, U32
from windows_protection_probe import require

TYPES = {'sgx': 1, 'sgx2': 2, 'vbs': 0x10}
QUERY = r"""$ErrorActionPreference = 'Stop'
$guard = Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard
$cpu = @(Get-CimInstance Win32_Processor | Select-Object Name,VirtualizationFirmwareEnabled,VMMonitorModeExtensions,SecondLevelAddressTranslationExtensions)
[ordered]@{
    vbs_status = [int]$guard.VirtualizationBasedSecurityStatus
    services_configured = @($guard.SecurityServicesConfigured)
    services_running = @($guard.SecurityServicesRunning)
    processors = $cpu
} | ConvertTo-Json -Depth 4 -Compress
"""


def supported(api):
    api.bind('IsEnclaveTypeSupported', c.c_int32, [U32])
    records = {}
    for name, flag in TYPES.items():
        c.set_last_error(0)
        result = api.dll.IsEnclaveTypeSupported(flag)
        error = c.get_last_error()
        records[name] = {'supported': bool(result), 'last_error': error}
    return records


def host_state():
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', QUERY],
                            capture_output=True, text=True, timeout=30, check=True)
    require(not result.stderr and 0 < len(result.stdout) <= 16384, 'bounded clean CIM response')
    value = json.loads(result.stdout)
    require(isinstance(value, dict) and type(value.get('vbs_status')) is int
            and value['vbs_status'] in (0, 1, 2), 'known VBS status required')
    for field in ('services_configured', 'services_running'):
        require(isinstance(value.get(field), list)
                and all(type(item) is int and 0 <= item <= 0xffffffff for item in value[field]),
                'complete integer service list required')
    require(isinstance(value.get('processors'), list) and 0 < len(value['processors']) <= 64,
            'bounded CPU observation required')
    for cpu in value['processors']:
        require(isinstance(cpu, dict) and isinstance(cpu.get('Name'), str), 'CPU identity required')
        for field in ('VirtualizationFirmwareEnabled', 'VMMonitorModeExtensions',
                      'SecondLevelAddressTranslationExtensions'):
            require(type(cpu.get(field)) is bool, 'CPU capability observation required')
    return value


def observation(api):
    return {'schema': 1, 'kind': 'windows-enclave-availability-experiment',
            'status': 'OBSERVATIONS_ONLY', 'strict_qualified': False,
            'enclave_created': False, 'machine_policy_changed': False,
            'native_machine': api.native_machine,
            'enclave_types': supported(api), 'host_state': host_state()}


def main():
    api = Windows()  # Native architecture check only; no allocation or mutation.
    source = Path(__file__).resolve()
    root = source.parents[2]
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root),
            'clean checkout required')
    record = observation(api)
    record.update(commit=commit, os=sys.getwindowsversion().build,
                  source_sha256={name: hashlib.sha256(source.with_name(name).read_bytes()).hexdigest()
                                 for name in ('windows_enclave_probe.py', 'windows_protection_api.py',
                                              'windows_protection_probe.py')})
    print(json.dumps(record, indent=2, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('WINDOWS_ENCLAVE_PROBE: FAILED: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
