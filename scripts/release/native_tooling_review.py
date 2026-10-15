"""Exact KMAC compiler-checker correction; never a runtime-source exemption.

The native capture does not execute this compiler inspector. Current repository
checks execute it separately. Preserve the original capture and permit only its
one reviewed digest substitution and the inspector's regression-test addition,
with both checker and regression-test versions bound by hash.
"""
import native_review_io as io

PATH = 'scripts/kmac/kmac_reviewed_hashes.py'
CHECKER = 'scripts/kmac/check-kmac-codegen.sh'
OLD = 'd5ae2e96eaa9d59fdd6cca36ebdd96fa90566e9aa7f62f6a8f3f7d67e3961e1f'
NEW = '7befaee4af1c13b27a19da497b2919c2ca8baf4385fed8cbcdaceaad5b1cb66c'
TEST = 'scripts/kmac/test-kmac.py'
TEST_OLD = 'a0e04695db4174c7a5805ce1c265751e4205047fbe8d4e166ad674f31a367d98'
TEST_NEW = '3d44060aaec01b2d5d6a3af00fef2a7328fa65571439bbe9e962ff21f3c8bcd3'


def equivalent(root, before, after, name):
    if name not in (PATH, TEST):
        return False
    if (io.sha(io.historical(root, before, CHECKER)) != OLD or
            io.sha(io.historical(root, after, CHECKER)) != NEW):
        return False
    if name == TEST:
        return (io.sha(io.historical(root, before, TEST)) == TEST_OLD and
                io.sha(io.historical(root, after, TEST)) == TEST_NEW)
    old = io.historical(root, before, PATH)
    new = io.historical(root, after, PATH)
    old_entry = f'"{CHECKER}": "{OLD}"'.encode()
    new_entry = f'"{CHECKER}": "{NEW}"'.encode()
    return (old.count(old_entry) == 1 and
            new == old.replace(old_entry, new_entry))
