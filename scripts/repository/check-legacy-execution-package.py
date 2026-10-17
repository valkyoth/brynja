#!/usr/bin/env python3
"""Focused isolated legacy consumers; no publication or full sweep."""
import argparse
import importlib.util
from pathlib import Path
import sys

import legacy_execution_package as legacy

spec = importlib.util.spec_from_file_location('legacy_facade_api', Path(__file__).with_name('check-facade-package.py'))
api = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = api
spec.loader.exec_module(api)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', default='1.99.1')
    parser.add_argument('--native-simd', action='store_true')
    parser.add_argument('--profile', choices=('ordinary', 'hardened', 'all'), default='all')
    args = parser.parse_args()
    with api.cargo_environment.private_directory(api.ROOT) as directory:
        legacy.execute(api, Path(directory), args.toolchain, args.native_simd, args.profile)


if __name__ == '__main__':
    main()
