#!/usr/bin/env python3
"""Check the development-only HMAC owner/profile inventory."""
import argparse
import hmac_inventory as inventory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    inventory.validate()
    path = inventory.ROOT / inventory.DOC
    expected = inventory.render()
    if args.write:
        path.write_text(expected)
    inventory.require(path.read_text() == expected, "generated document is stale")
    print(f"HMAC development inventory: PASS; {len(inventory.OWNERS)} owners/outputs, "
          f"{len(inventory.PROFILES)} profiles; qualification PENDING")


if __name__ == "__main__":
    main()
