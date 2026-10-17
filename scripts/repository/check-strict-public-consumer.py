#!/usr/bin/env python3
"""Opt-in isolated strict scalar consumer acceptance; no full verification sweep."""
import argparse
import importlib.util
from pathlib import Path
import sys

import strict_public_consumer as strict

spec = importlib.util.spec_from_file_location('strict_public_api', Path(__file__).with_name('check-facade-package.py'))
api = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = api
spec.loader.exec_module(api)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', default='1.99.1')
    args = parser.parse_args()
    with api.cargo_environment.private_directory(api.ROOT) as directory:
        strict.execute(api, Path(directory), args.toolchain)


if __name__ == '__main__':
    main()
