//! Official NIST KMAC and KMACXOF example acceptance.

use brynja_mac_kmac::{
    KmacPublicDeclassification, kmac128, kmac256, kmacxof128_public, kmacxof256_public,
};

const CUSTOM: &[u8] = b"My Tagged Application";

macro_rules! require_some {
    ($value:expr) => {{
        let value = $value;
        assert!(value.is_some());
        let Some(value) = value else { return };
        value
    }};
}

#[test]
fn all_six_official_kmac_examples_match() {
    let short = sequence::<4>(0x00);
    let long = sequence::<200>(0x00);
    check_fixed_128(
        &short,
        b"",
        "E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E",
    );
    check_fixed_128(
        &short,
        CUSTOM,
        "3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5",
    );
    check_fixed_128(
        &long,
        CUSTOM,
        "1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230",
    );
    check_fixed_256(
        &short,
        CUSTOM,
        "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD",
    );
    check_fixed_256(
        &long,
        b"",
        "75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69",
    );
    check_fixed_256(
        &long,
        CUSTOM,
        "B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D970FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965",
    );
}

#[test]
fn all_six_official_kmacxof_examples_match() {
    let short = sequence::<4>(0x00);
    let long = sequence::<200>(0x00);
    check_xof_128(
        &short,
        b"",
        "CD83740BBD92CCC8CF032B1481A0F4460E7CA9DD12B08A0C4031178BACD6EC35",
    );
    check_xof_128(
        &short,
        CUSTOM,
        "31A44527B4ED9F5C6101D11DE6D26F0620AA5C341DEF41299657FE9DF1A3B16C",
    );
    check_xof_128(
        &long,
        CUSTOM,
        "47026C7CD793084AA0283C253EF658490C0DB61438B8326FE9BDDF281B83AE0F",
    );
    check_xof_256(
        &short,
        CUSTOM,
        "1755133F1534752AAD0748F2C706FB5C784512CAB835CD15676B16C0C6647FA96FAA7AF634A0BF8FF6DF39374FA00FAD9A39E322A7C92065A64EB1FB0801EB2B",
    );
    check_xof_256(
        &long,
        b"",
        "FF7B171F1E8A2B24683EED37830EE797538BA8DC563F6DA1E667391A75EDC02CA633079F81CE12A25F45615EC89972031D18337331D24CEB8F8CA8E6A19FD98B",
    );
    check_xof_256(
        &long,
        CUSTOM,
        "D5BE731C954ED7732846BB59DBE3A8E30F83E77A4BFF4459F2F1C2B4ECEBB8CE67BA01C62E8AB8578D2D499BD1BB276768781190020A306A97DE281DCC30305D",
    );
}

fn check_fixed_128(message: &[u8], customization: &[u8], expected: &str) {
    let key = sequence::<32>(0x40);
    let mut output = [0_u8; 32];
    let tag = require_some!(kmac128(&key, message, customization, &mut output).ok());
    assert_eq!(tag.bit_len(), 256);
    assert_hex(tag.as_bytes(), expected);
}

fn check_fixed_256(message: &[u8], customization: &[u8], expected: &str) {
    let key = sequence::<32>(0x40);
    let mut output = [0_u8; 64];
    let tag = require_some!(kmac256(&key, message, customization, &mut output).ok());
    assert_eq!(tag.bit_len(), 512);
    assert_hex(tag.as_bytes(), expected);
}

fn check_xof_128(message: &[u8], customization: &[u8], expected: &str) {
    let key = sequence::<32>(0x40);
    let mut output = [0_u8; 32];
    assert_eq!(
        kmacxof128_public(
            &key,
            message,
            customization,
            &mut output,
            KmacPublicDeclassification::acknowledge()
        ),
        Ok(())
    );
    assert_hex(&output, expected);
}

fn check_xof_256(message: &[u8], customization: &[u8], expected: &str) {
    let key = sequence::<32>(0x40);
    let mut output = [0_u8; 64];
    assert_eq!(
        kmacxof256_public(
            &key,
            message,
            customization,
            &mut output,
            KmacPublicDeclassification::acknowledge()
        ),
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

fn sequence<const LENGTH: usize>(start: u8) -> [u8; LENGTH] {
    core::array::from_fn(|index| start.wrapping_add(u8::try_from(index).unwrap_or_default()))
}
