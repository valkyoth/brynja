//! Official NIST ParallelHash and ParallelHashXOF sample acceptance.

use brynja_hash_parallel::{
    parallel_hash_xof128, parallel_hash_xof256, parallel_hash128, parallel_hash256,
};

const SHORT: [u8; 24] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
];
const LONG: [u8; 72] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x50, 0x51, 0x52, 0x53,
    0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b,
];

#[test]
fn all_six_official_fixed_examples_match() {
    check128(
        false,
        false,
        "BA8DC1D1D979331D3F813603C67F72609AB5E44B94A0B8F9AF46514454A2B4F5",
    );
    check128(
        true,
        false,
        "FC484DCB3F84DCEEDC353438151BEE58157D6EFED0445A81F165E495795B7206",
    );
    check128(
        true,
        true,
        "F7FD5312896C6685C828AF7E2ADB97E393E7F8D54E3C2EA4B95E5ACA3796E8FC",
    );
    check256(
        false,
        false,
        "BC1EF124DA34495E948EAD207DD9842235DA432D2BBC54B4C110E64C451105531B7F2A3E0CE055C02805E7C2DE1FB746AF97A1DD01F43B824E31B87612410429",
    );
    check256(
        true,
        false,
        "CDF15289B54F6212B4BC270528B49526006DD9B54E2B6ADD1EF6900DDA3963BB33A72491F236969CA8AFAEA29C682D47A393C065B38E29FAE651A2091C833110",
    );
    check256(
        true,
        true,
        "69D0FCB764EA055DD09334BC6021CB7E4B61348DFF375DA262671CDEC3EFFA8D1B4568A6CCE16B1CAD946DDDE27F6CE2B8DEE4CD1B24851EBF00EB90D43813E9",
    );
}

#[test]
fn all_six_official_xof_examples_match() {
    check_xof128(
        false,
        false,
        "FE47D661E49FFE5B7D999922C062356750CAF552985B8E8CE6667F2727C3C8D3",
    );
    check_xof128(
        true,
        false,
        "EA2A793140820F7A128B8EB70A9439F93257C6E6E79B4A540D291D6DAE7098D7",
    );
    check_xof128(
        true,
        true,
        "0127AD9772AB904691987FCC4A24888F341FA0DB2145E872D4EFD255376602F0",
    );
    check_xof256(
        false,
        false,
        "C10A052722614684144D28474850B410757E3CBA87651BA167A5CBDDFF7F466675FBF84BCAE7378AC444BE681D729499AFCA667FB879348BFDDA427863C82F1C",
    );
    check_xof256(
        true,
        false,
        "538E105F1A22F44ED2F5CC1674FBD40BE803D9C99BF5F8D90A2C8193F3FE6EA768E5C1A20987E2C9C65FEBED03887A51D35624ED12377594B5585541DC377EFC",
    );
    check_xof256(
        true,
        true,
        "6B3E790B330C889A204C2FBC728D809F19367328D852F4002DC829F73AFD6BCEFB7FE5B607B13A801C0BE5C1170BDB794E339458FDB0E62A6AF3D42558970249",
    );
}

fn parameters(long: bool) -> (&'static [u8], usize) {
    if long { (&LONG, 12) } else { (&SHORT, 8) }
}

fn custom(enabled: bool) -> &'static [u8] {
    if enabled { b"Parallel Data" } else { b"" }
}

fn check128(customized: bool, long: bool, expected: &str) {
    let (input, block) = parameters(long);
    let mut workspace = [0_u8; 12];
    let mut output = [0_u8; 32];
    let workspace = workspace.get_mut(..block).unwrap_or_default();
    assert_eq!(
        parallel_hash128(input, workspace, custom(customized), &mut output),
        Ok(())
    );
    assert_hex(&output, expected);
}

fn check256(customized: bool, long: bool, expected: &str) {
    let (input, block) = parameters(long);
    let mut workspace = [0_u8; 12];
    let mut output = [0_u8; 64];
    let workspace = workspace.get_mut(..block).unwrap_or_default();
    assert_eq!(
        parallel_hash256(input, workspace, custom(customized), &mut output),
        Ok(())
    );
    assert_hex(&output, expected);
}

fn check_xof128(customized: bool, long: bool, expected: &str) {
    let (input, block) = parameters(long);
    let mut workspace = [0_u8; 12];
    let mut output = [0_u8; 32];
    let workspace = workspace.get_mut(..block).unwrap_or_default();
    assert_eq!(
        parallel_hash_xof128(input, workspace, custom(customized), &mut output),
        Ok(())
    );
    assert_hex(&output, expected);
}

fn check_xof256(customized: bool, long: bool, expected: &str) {
    let (input, block) = parameters(long);
    let mut workspace = [0_u8; 12];
    let mut output = [0_u8; 64];
    let workspace = workspace.get_mut(..block).unwrap_or_default();
    assert_eq!(
        parallel_hash_xof256(input, workspace, custom(customized), &mut output),
        Ok(())
    );
    assert_hex(&output, expected);
}

fn assert_hex(actual: &[u8], expected: &str) {
    assert_eq!(actual.len().checked_mul(2), Some(expected.len()));
    for (actual, pair) in actual.iter().zip(expected.as_bytes().chunks(2)) {
        let high = pair.first().copied().map(hex).unwrap_or_default();
        let low = pair.get(1).copied().map(hex).unwrap_or_default();
        assert_eq!(*actual, (high << 4) | low);
    }
}

const fn hex(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value.saturating_sub(b'0'),
        b'A'..=b'F' => value.saturating_sub(b'A').saturating_add(10),
        _ => 0,
    }
}
