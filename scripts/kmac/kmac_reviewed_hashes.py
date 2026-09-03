#!/usr/bin/env python3
"""Exact source identities reviewed for the v0.24.13 KMAC boundary."""

REVIEWED_HASHES = {
    "crates/brynja-mac-kmac/src/backend.rs": "530074613bab6f8415e5a500a6c690e7421e01d337fee18afa65e64fd7aec765",
    "crates/brynja-mac-kmac/src/core_state.rs": "b0940585ad90255e2e4b4b9908513b37767fbee159643063e56046e0caf947d1",
    "crates/brynja-mac-kmac/src/error.rs": "6e73a95863f6897b6e22c2cefb91996097ca79dd1d14359f3454195b40edcd66",
    "crates/brynja-mac-kmac/src/fixed.rs": "202552f28c2da059b7792e4fcd4c7500607ac1a8179be506fb213f125d164d2d",
    "crates/brynja-mac-kmac/src/lib.rs": "198eafc784d01e0d4376dd026f56ad26e6677cd9db23b6a29bf187e066bb3b82",
    "crates/brynja-mac-kmac/src/output.rs": "194598a94ca33aad9b0e885159268c70faf6412f9665ac7e2c9c5bbccad54b75",
    "crates/brynja-mac-kmac/src/packer.rs": "a6603bf967547957e2c6ed36f4e349187eaa6c7ce4e17f5682f43f3dab6fc4d2",
    "crates/brynja-mac-kmac/src/policy.rs": "1263e759cca9e58f45a47a498d786a405301a5df5ce2df672d101e201eebb7eb",
    "crates/brynja-mac-kmac/src/verify.rs": "e40cbe3886881c8e52bb389db560b1158dce0b777a191d11c122c1f0187d883c",
    "crates/brynja-mac-kmac/src/xof.rs": "3f1c86ec1bca5758b0d065800ec1a3b6712c34a2a0676b24361cf80f2e735230",
    "crates/brynja-mac-kmac/tests/api.rs": "fdb0f5e6eb5c2fe9ccc50a78d397051a935da39a7c458ca8ebf283c0452aef98",
    "crates/brynja-mac-kmac/tests/official_vectors.rs": "db57d0e2d6b8156b5b3944e941b80a8fef5305610950c243afeced144db91ee2",
    "assurance/kmac-public-api/src/lib.rs": "01c18b5dd45d3e90ed15450834adbadb9233a44b3f4a5b7696435bba5caff9b3",
    "assurance/kmac-differential/src/main.rs": "121ce030016e04f0dec5b82511b8ce360a5434805b070cca74bd2ddbd5abecaa",
    "scripts/kmac/check-kmac-codegen.sh": "93af6bd118eb73f8c1a8542a02861cfeb64f21af79760dac5a83128676675058",
    "scripts/kmac/check-kmac-differential.py": "b3bb8f84f7648c369e00bd7753b92cecab7dc0b19e6c2b5652bd874ee3f5c640",
}
