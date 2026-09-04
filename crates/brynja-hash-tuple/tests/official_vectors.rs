//! Official NIST TupleHash and TupleHashXOF example acceptance.

use brynja_hash_tuple::{tuple_hash_xof128, tuple_hash_xof256, tuple_hash128, tuple_hash256};

const FIRST: &[u8] = &[0x00, 0x01, 0x02];
const SECOND: &[u8] = &[0x10, 0x11, 0x12, 0x13, 0x14, 0x15];
const THIRD: &[u8] = &[0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28];
const CUSTOM: &[u8] = b"My Tuple App";

#[test]
fn all_six_official_fixed_examples_match() {
    check_128(
        false,
        false,
        "C5D8786C1AFB9B82111AB34B65B2C0048FA64E6D48E263264CE1707D3FFC8ED1",
    );
    check_128(
        true,
        false,
        "75CDB20FF4DB1154E841D758E24160C54BAE86EB8C13E7F5F40EB35588E96DFB",
    );
    check_128(
        true,
        true,
        "E60F202C89A2631EDA8D4C588CA5FD07F39E5151998DECCF973ADB3804BB6E84",
    );
    check_256(
        false,
        false,
        "CFB7058CACA5E668F81A12A20A2195CE97A925F1DBA3E7449A56F82201EC607311AC2696B1AB5EA2352DF1423BDE7BD4BB78C9AED1A853C78672F9EB23BBE194",
    );
    check_256(
        true,
        false,
        "147C2191D5ED7EFD98DBD96D7AB5A11692576F5FE2A5065F3E33DE6BBA9F3AA1C4E9A068A289C61C95AAB30AEE1E410B0B607DE3620E24A4E3BF9852A1D4367E",
    );
    check_256(
        true,
        true,
        "45000BE63F9B6BFD89F54717670F69A9BC763591A4F05C50D68891A744BCC6E7D6D5B5E82C018DA999ED35B0BB49C9678E526ABD8E85C13ED254021DB9E790CE",
    );
}

#[test]
fn all_six_official_xof_examples_match() {
    check_xof_128(
        false,
        false,
        "2F103CD7C32320353495C68DE1A8129245C6325F6F2A3D608D92179C96E68488",
    );
    check_xof_128(
        true,
        false,
        "3FC8AD69453128292859A18B6C67D7AD85F01B32815E22CE839C49EC374E9B9A",
    );
    check_xof_128(
        true,
        true,
        "900FE16CAD098D28E74D632ED852F99DAAB7F7DF4D99E775657885B4BF76D6F8",
    );
    check_xof_256(
        false,
        false,
        "03DED4610ED6450A1E3F8BC44951D14FBC384AB0EFE57B000DF6B6DF5AAE7CD568E77377DAF13F37EC75CF5FC598B6841D51DD207C991CD45D210BA60AC52EB9",
    );
    check_xof_256(
        true,
        false,
        "6483CB3C9952EB20E830AF4785851FC597EE3BF93BB7602C0EF6A65D741AECA7E63C3B128981AA05C6D27438C79D2754BB1B7191F125D6620FCA12CE658B2442",
    );
    check_xof_256(
        true,
        true,
        "0C59B11464F2336C34663ED51B2B950BEC743610856F36C28D1D088D8A2446284DD09830A6A178DC752376199FAE935D86CFDEE5913D4922DFD369B66A53C897",
    );
}

fn tuple(include_third: bool) -> &'static [&'static [u8]] {
    if include_third {
        &[FIRST, SECOND, THIRD]
    } else {
        &[FIRST, SECOND]
    }
}

fn customization(customized: bool) -> &'static [u8] {
    if customized { CUSTOM } else { b"" }
}

fn check_128(customized: bool, third: bool, expected: &str) {
    let mut output = [0_u8; 32];
    assert_eq!(
        tuple_hash128(tuple(third), customization(customized), &mut output),
        Ok(())
    );
    assert_hex(&output, expected);
}

fn check_256(customized: bool, third: bool, expected: &str) {
    let mut output = [0_u8; 64];
    assert_eq!(
        tuple_hash256(tuple(third), customization(customized), &mut output),
        Ok(())
    );
    assert_hex(&output, expected);
}

fn check_xof_128(customized: bool, third: bool, expected: &str) {
    let mut output = [0_u8; 32];
    assert_eq!(
        tuple_hash_xof128(tuple(third), customization(customized), &mut output),
        Ok(())
    );
    assert_hex(&output, expected);
}

fn check_xof_256(customized: bool, third: bool, expected: &str) {
    let mut output = [0_u8; 64];
    assert_eq!(
        tuple_hash_xof256(tuple(third), customization(customized), &mut output),
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
