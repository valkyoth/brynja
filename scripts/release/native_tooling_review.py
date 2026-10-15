"""Exact KMAC compiler-checker correction; never a runtime-source exemption.

The native capture does not execute this compiler inspector. Current repository
checks execute it separately. Preserve the original capture and permit only its
one reviewed digest substitution, with both checker versions bound by hash.
"""
import native_review_io as io

PATH = 'scripts/kmac/kmac_reviewed_hashes.py'
CHECKER = 'scripts/kmac/check-kmac-codegen.sh'
OLD = 'd5ae2e96eaa9d59fdd6cca36ebdd96fa90566e9aa7f62f6a8f3f7d67e3961e1f'
NEW = '7befaee4af1c13b27a19da497b2919c2ca8baf4385fed8cbcdaceaad5b1cb66c'


def equivalent(root, before, after, name):
    if name != PATH:
        return False
    old = io.historical(root, before, PATH)
    new = io.historical(root, after, PATH)
    old_entry = f'"{CHECKER}": "{OLD}"'.encode()
    new_entry = f'"{CHECKER}": "{NEW}"'.encode()
    return (old.count(old_entry) == 1 and
            new == old.replace(old_entry, new_entry) and
            io.sha(io.historical(root, before, CHECKER)) == OLD and
            io.sha(io.historical(root, after, CHECKER)) == NEW)
