#!/usr/bin/env python3
"""Opt-in public Apple Silicon legacy resident checks; no dump exclusion claim."""
import argparse
import importlib.util
from pathlib import Path
import sys

import legacy_strict_package as protected

spec = importlib.util.spec_from_file_location('resident_legacy_facade_api', Path(__file__).with_name('check-facade-package.py'))
api = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = api
spec.loader.exec_module(api)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', default='1.99.1')
    parser.add_argument('--native-simd', action='store_true')
    args = parser.parse_args()
    protected.require_host(True)
    with api.cargo_environment.private_directory(api.ROOT) as directory:
        protected.execute(api, Path(directory), args.toolchain, args.native_simd, resident=True)


if __name__ == '__main__':
    main()
