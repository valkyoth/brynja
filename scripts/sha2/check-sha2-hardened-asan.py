#!/usr/bin/env python3
"""Required local ASan evidence for the actual SHA-NI secret kernel."""
import hardened_native_host as host


def main():
    env = host.clean_environment()
    identity = host.x86_host()  # Must precede compiling/executing target features.
    env['RUSTFLAGS'] = host.FLAGS
    text = host.execute(host.asan_command(), env)
    host.validate_asan(text)
    print(text, end='')
    print('Hardened native x86 ASan: PASS; CPU=' + identity)


if __name__ == '__main__':
    main()
