//! Typed input/descriptor geometry for the emitted worker checker.
use brynja_legacy_hmac::{BitString, md5_batch::Input};

macro_rules! field {
    ($name:ident, $kind:ty, $value:ident, $body:expr) => {
        #[inline(never)]
        pub fn $name($value: &super::host::Md5BatchInput<'_>) -> $kind {
            $body
        }
    };
}
field!(key_pointer, *const u8, v, v.key.as_ptr());
field!(key_length, usize, v, v.key.len());
field!(message_pointer, *const u8, v, v.message.bytes.as_ptr());
field!(message_length, usize, v, v.message.bytes.len());
field!(valid_bits, u8, v, v.message.valid_bits);

#[inline(never)]
pub fn input<'a>(key: &'a [u8], message: BitString<'a>) -> Input<'a> {
    Input::new(key, message)
}

#[inline(never)]
pub fn inactive() -> [Option<Input<'static>>; 8] {
    [const { None }; 8]
}

#[inline(never)]
pub fn present(value: &Option<Input<'_>>) -> bool {
    value.is_some()
}

#[inline(never)]
pub fn bit_result<'a, 'b>(
    value: &'a Result<BitString<'b>, brynja_legacy_hmac::BitStringError>,
) -> Option<&'a BitString<'b>> {
    value.as_ref().ok()
}
