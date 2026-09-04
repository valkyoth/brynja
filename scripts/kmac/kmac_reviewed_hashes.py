#!/usr/bin/env python3
"""Exact source identities reviewed for the v0.24.13 KMAC boundary."""

REVIEWED_HASHES = {
    "crates/brynja-mac-kmac/src/backend.rs": "62296b1fdbefc0a1781d3b8fa0b68f65ef0c0f0e5f704d3957355302392a4a24",
    "crates/brynja-mac-kmac/src/core_state.rs": "846e8faf8aff60286f0903fc26420e397aa48883313df3bef9226ee4aa6b6f18",
    "crates/brynja-mac-kmac/src/error.rs": "7b683e37ec4ec798ee2e2a544fb8d42858214f166dcba83a240b2c6a2e92f3e8",
    "crates/brynja-mac-kmac/src/fixed.rs": "424e0be6b9b05b57ce582d286cbacba4e369c8309f2b57a4aae427571167b8a6",
    "crates/brynja-mac-kmac/src/lib.rs": "1282c26647508cd62283b404ff07d0b8768fc5148cd85165b2bf069a4c5a53fc",
    "crates/brynja-mac-kmac/src/output.rs": "194598a94ca33aad9b0e885159268c70faf6412f9665ac7e2c9c5bbccad54b75",
    "crates/brynja-mac-kmac/src/packer.rs": "94e511dc66101f61bfecc9596a7551efc0f9a7a5ec489f2d260d74a7a3e7d5da",
    "crates/brynja-mac-kmac/src/policy.rs": "1263e759cca9e58f45a47a498d786a405301a5df5ce2df672d101e201eebb7eb",
    "crates/brynja-mac-kmac/src/verify.rs": "e40cbe3886881c8e52bb389db560b1158dce0b777a191d11c122c1f0187d883c",
    "crates/brynja-mac-kmac/src/xof.rs": "0ea4b24c170c36109b237aa91d1807b1efc7deef0a9e05b6ba6352342c971ede",
    "crates/brynja-mac-kmac/tests/api.rs": "9709fa94906a0e18e3a4cfa7e56ab84ae67504337f8b25e7930898f59189bfad",
    "crates/brynja-mac-kmac/tests/official_vectors.rs": "db57d0e2d6b8156b5b3944e941b80a8fef5305610950c243afeced144db91ee2",
    "assurance/kmac-public-api/src/lib.rs": "01c18b5dd45d3e90ed15450834adbadb9233a44b3f4a5b7696435bba5caff9b3",
    "assurance/kmac-differential/src/main.rs": "121ce030016e04f0dec5b82511b8ce360a5434805b070cca74bd2ddbd5abecaa",
    "assurance/kmac-differential/Cargo.toml": "6c3b87ebd805b64d9df4e42cb1d413207037e277408f35ffa32019e9051007fa",
    "scripts/kmac/check-kmac-conformance-gate.sh": "e54887e6fdc558b52e8327a01c8f401469dce94ebe495d8a33a61c1e15e1bffa",
    "assurance/kmac-conformance-rejected/src/lib.rs": "fe4a3db89edf219e343df7e5b55bff94fcef99fdc582c17c05230e20606b5a5a",
    "assurance/kmac-conformance-rejected/Cargo.toml": "825eedc9799aba873adef3227538a3fb4458b8c84fd92c56d3c12dcc72fdfac0",
    "crates/brynja-hash-sha3/src/hardened/cshake.rs": "663b34d19246778cbd4b126582b6731e6fba6e3627e5067eeda120e936f45c2d",
    "scripts/kmac/check-kmac-codegen.sh": "303f0dcc4f8c7f0b00d3ce7d8c94e5323cfa3ce75a9ffa2c280fe93a369d9347",
    "scripts/kmac/check-kmac-differential.py": "b3bb8f84f7648c369e00bd7753b92cecab7dc0b19e6c2b5652bd874ee3f5c640",
}
