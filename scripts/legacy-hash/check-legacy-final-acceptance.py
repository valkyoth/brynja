#!/usr/bin/env python3
"""Run the final downstream contract; never enables instruction candidates."""
import legacy_final_acceptance as policy
import legacy_acceptance as runner
import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    if args.write:
        policy.validate(hashes=False)
        (policy.ROOT / policy.HASHES).write_text(policy.render_hashes(), encoding='utf-8')
        return
    policy.validate()
    manifest = policy.FIXTURE + '/Cargo.toml'
    runner.execute('cargo', 'fmt', '--manifest-path', manifest, '--check')
    runner.execute('cargo', 'test', '--locked', '--offline', '--manifest-path', manifest)
    runner.execute('cargo', 'run', '--locked', '--offline', '--release', '--manifest-path', manifest)
    runner.execute('cargo', 'clippy', '--locked', '--offline', '--manifest-path', manifest,
                   '--all-targets', '--', '-D', 'warnings')
    print('Legacy final acceptance and non-authorizing evidence disposition: PASS')


if __name__ == '__main__':
    main()
