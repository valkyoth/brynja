#!/usr/bin/env python3
"""Tag-only requirement; absent native observations block, never silently skip."""
import argparse
import hardened_native_evidence as evidence

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--commit')
    args = parser.parse_args()
    evidence.validate(commit=args.commit)
