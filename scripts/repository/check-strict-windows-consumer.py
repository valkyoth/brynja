#!/usr/bin/env python3
"""Cross-check extracted Windows public APIs; no Windows runtime qualification."""
import argparse
from pathlib import Path
from importlib.util import spec_from_file_location, module_from_spec

import strict_windows_consumer as windows

spec = spec_from_file_location('strict_windows_api', Path(__file__).with_name('check-facade-package.py'))
api = module_from_spec(spec)
spec.loader.exec_module(api)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', default='1.99.1')
    args = parser.parse_args()
    with api.cargo_environment.private_directory(api.ROOT) as directory:
        windows.execute(api, Path(directory), args.toolchain)


if __name__ == '__main__':
    main()
