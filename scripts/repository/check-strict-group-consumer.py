#!/usr/bin/env python3
"""Extracted protected batch/ParallelHash consumers; not release qualification."""
import argparse
from pathlib import Path

from importlib.util import spec_from_file_location, module_from_spec
import strict_group_consumer as groups

spec = spec_from_file_location('strict_group_api', Path(__file__).with_name('check-facade-package.py'))
api = module_from_spec(spec)
spec.loader.exec_module(api)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', default='1.99.1')
    parser.add_argument('--native-simd', action='store_true')
    args = parser.parse_args()
    with api.cargo_environment.private_directory(api.ROOT) as directory:
        groups.execute(api, Path(directory), args.toolchain, args.native_simd)


if __name__ == '__main__':
    main()
