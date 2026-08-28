"""Hash-bound portable SHA-2 source and test inventory."""

SOURCE_HASHES = {
    "crates/brynja-hash-core/src/lib.rs": "d6c8b4046978d74e077079701c3c17c06a8fd9fbfc15ef10368a41cf9a63d64d",
    "crates/brynja-hash-sha2/src/lib.rs": "aa1a4f0ce77768b180daae6ead51a739452d7bd057bbfa8f348df5a7ee3732d2",
    "crates/brynja-hash-sha2/src/compress.rs": "d4229f08e40392976f354eaf81f5d5cd03069d5f3c497e2cf481f65a9848e4b1",
    "crates/brynja-hash-sha2/src/digest.rs": "a861b334e041502bfb56b5de12a4c83468cbfa2440881288aca94c1aa6c08634",
    "crates/brynja-hash-sha2/src/error.rs": "9657f1223bd80a8c16f93585f690a7b17dd2fe51486ccf161a962810f79cfa7e",
    "crates/brynja-hash-sha2/src/sha224.rs": "fb2663369b896047fc3618bcaf6f3d78bae9d4b89e529e574a60040fb34375d1",
    "crates/brynja-hash-sha2/src/sha256.rs": "efbe3a588947e127dd0b0cecbe2b3e3b0a876a354d8d1f798052060d35ddb68d",
    "crates/brynja-hash-sha2/src/compress64.rs": "40edca2d80e9f60db4a9ea793fe5c61f79232012fb439025539e6b50c93f812b",
    "crates/brynja-hash-sha2/src/sha512_state.rs": "492aaceedc1c168bf0bb1bc07c876e735edb5da1a325fb7663123b1bb25a3622",
    "crates/brynja-hash-sha2/src/sha384.rs": "f4039d389c33de004d4a5f14eebc453fec3ce7fd60560f0897fbc37e48e5c9b7",
    "crates/brynja-hash-sha2/src/sha512.rs": "66ece003b16b1256acf35ff2b4b4beffa495b77b820ac0ead03719847ff2d236",
    "crates/brynja-hash-sha2/src/sha512_t.rs": "1a87c5259498d2cff9951bb0b4a213a30dcf76182191ff3f6a421e5ba7c03916",
    "crates/brynja-hash-sha2/src/sha512_224.rs": "4a691a855a6362c873da53c13a43227f06fd328a21d24e44ea4bcba2bf99b704",
    "crates/brynja-hash-sha2/src/sha512_256.rs": "8fe18e207fbdb55c3d55a0a54dbc427c334ac7359b6cbc1dda4752d05393a1f6",
}

TEST_HASHES = {
    "crates/brynja-hash-sha2/tests/sha224.rs": "4a154a5293aa7fca5862fe1b383807998baa69b5eb5dd1ae2393b11d2c4fecb5",
    "crates/brynja-hash-sha2/tests/sha256.rs": "c3eebf6ae0202321f72ddc131691720c94709e5281f905a5bd7d0fe4a603a3d1",
    "crates/brynja-hash-sha2/tests/sha256_accelerated.rs": "576c89cbbca4f0f45ce88efe750bd2976c5fa547becaae9fdbff103a38f66ae1",
    "crates/brynja-hash-sha2/tests/sha384.rs": "37bfa6cf7d73e4b4b15c6211f11bcdfeefcf8bd0ff44f5ddcd501ecf4ce0bf0e",
    "crates/brynja-hash-sha2/tests/sha512.rs": "2f7ed01daeac2e92d53a06fda04603e8e50a5a059c13c8212d2584c0f3a168eb",
    "crates/brynja-hash-sha2/tests/sha512_224.rs": "31e8eea07d54224200a1c6d40cf96fbb59a7d75e8f1acfb5c810977470497af9",
    "crates/brynja-hash-sha2/tests/sha512_256.rs": "55532453913f4b507684fc19fae1ca6aaf274de5f6b52ab18d5cb736b9f41b80",
    "crates/brynja-hash-sha2/tests/sha2_accelerated.rs": "2f11089d150ac83d8dbe73416e571364e7d1b23f6e3ea1dd387beb7314add8e5",
}
