// McGrew & Viega, The Galois/Counter Mode of Operation (GCM), Appendix B.
// Fixed public inputs and answers cross-checked against Bouncy Castle r1rv80:
// https://github.com/bcgit/bc-java/blob/r1rv80/core/src/test/java/org/bouncycastle/crypto/test/GCMTest.java
// Each group contains the zero-key single block, then the same padded AAD
// and payload under 12-, 8- and 60-byte IVs. Never derive answers at runtime.
pub(super) const PLAINTEXT: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
pub(super) const AAD: &str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
pub(super) const IV12: [u8; 12] = [
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
];
pub(super) const IV8: &str = "cafebabefacedbad";
pub(super) const IV60: &str = "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b";

// Cases 2, 4, 5, 6 (ciphertext, tag).
pub(super) const AES128: [(&str, u128); 4] = [
    (
        "0388dace60b6a392f328c2b971b2fe78",
        0xab6e47d42cec13bdf53a67b21257bddf,
    ),
    (
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        0x5bc94fbc3221a5db94fae95ae7121a47,
    ),
    (
        "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
        0x3612d2e79e3b0785561be14aaca2fccb,
    ),
    (
        "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
        0x619cc5aefffe0bfa462af43c1699d050,
    ),
];

// Cases 8, 10, 11, 12 (ciphertext, tag).
pub(super) const AES192: [(&str, u128); 4] = [
    (
        "98e7247c07f0fe411c267e4384b0f600",
        0x2ff58d80033927ab8ef4d4587514f0fb,
    ),
    (
        "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
        0x2519498e80f1478f37ba55bd6d27618c,
    ),
    (
        "0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7",
        0x65dcc57fcf623a24094fcca40d3533f8,
    ),
    (
        "d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b",
        0xdcf566ff291c25bbb8568fc3d376a6d9,
    ),
];

// Cases 14, 16, 17, 18 (ciphertext, tag).
pub(super) const AES256: [(&str, u128); 4] = [
    (
        "cea7403d4d606b6e074ec5d3baf39d18",
        0xd0d1c8a799996bf0265b98b5d48ab919,
    ),
    (
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        0x76fc6ece0f4e1768cddf8853bb2d551b,
    ),
    (
        "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
        0x3a337dbf46a792c45e454913fe2ea8f2,
    ),
    (
        "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
        0xa44a8266ee1c8eb0c8b5d4cf5ae9f19a,
    ),
];
