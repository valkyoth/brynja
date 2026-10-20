//! Explicit all-admitted-parameter oracle; author testing, not certification.
#[macro_use]
mod support;
use brynja_mac_hmac::*;

fn check<const T: u16>(key: &[u8], message: &[u8], bits: usize, expected: &[u8]) {
    assert_eq!(message.len(), require_some!(bits.checked_add(7)) / 8);
    assert_eq!(expected.len(), Sha512T::<T>::TAG_BYTES);
    let valid = if bits == 0 {
        0
    } else if bits.is_multiple_of(8) {
        8
    } else {
        require_ok!(u8::try_from(bits % 8))
    };
    let input = require_ok!(Sha2BitString::new(message, valid));
    let mut output = vec![0; expected.len()];
    let tag = require_ok!(Hmac::<Sha512T<T>>::authenticate_bits(
        key,
        input,
        &mut output
    ));
    assert_eq!(tag.bit_len(), usize::from(T));
    assert_eq!(tag.as_bytes(), expected);
    for split in [0, message.len().saturating_sub(1)] {
        let mut mac = require_ok!(Hmac::<Sha512T<T>>::new(key));
        require_ok!(mac.update(require_some!(message.get(..split))));
        let tail = require_ok!(Sha2BitString::new(
            require_some!(message.get(split..)),
            valid
        ));
        {
            let secret = require_ok!(mac.finalize_bits_secret(tail, &mut output));
            assert_eq!(secret.bit_len(), usize::from(T));
            assert_eq!(secret.expose(), expected);
        }
        assert!(output.iter().all(|byte| *byte == 0));
    }
    let verifier = require_ok!(Hmac::<Sha512T<T>>::with_tag_length(key, 16));
    assert!(
        require_ok!(verifier.verify_bits(input, require_some!(expected.get(..16)))).expose_public()
    );
}

#[test]
#[ignore = "run scripts/hmac/check-hmac-general-differential.py"]
fn external_general_oracle() {
    let file = require_ok!(std::env::var("BRYNJA_HMAC_GENERAL_ORACLE"));
    let text = require_ok!(std::fs::read_to_string(file));
    let mut counts = [0_usize; 512];
    for row in text.lines() {
        let fields: Vec<_> = row.split(':').collect();
        let fields: [&str; 5] = require_ok!(fields.try_into());
        let t = require_ok!(fields[0].parse::<usize>());
        let key = require_some!(support::decode(fields[1]));
        let message = require_some!(support::decode(fields[2]));
        let bits = require_ok!(fields[3].parse::<usize>());
        let expected = require_some!(support::decode(fields[4]));
        macro_rules! dispatch {
            ($($parameter:literal),*) => {
                match t {
                    $($parameter => {check::<$parameter>(&key, &message, bits, &expected); true},)*
                    _ => false,
                }
            }
        }
        let recognized = dispatch!(
            128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144,
            145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161,
            162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178,
            179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195,
            196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212,
            213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229,
            230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246,
            247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263,
            264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280,
            281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297,
            298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314,
            315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331,
            332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348,
            349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365,
            366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 382,
            383, 385, 386, 387, 388, 389, 390, 391, 392, 393, 394, 395, 396, 397, 398, 399, 400,
            401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417,
            418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434,
            435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451,
            452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468,
            469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482, 483, 484, 485,
            486, 487, 488, 489, 490, 491, 492, 493, 494, 495, 496, 497, 498, 499, 500, 501, 502,
            503, 504, 505, 506, 507, 508, 509, 510, 511
        );
        assert!(recognized, "unadmitted general HMAC identity");
        let count = require_some!(counts.get_mut(t));
        *count = require_some!(count.checked_add(1));
    }
    for (t, count) in counts.iter().enumerate() {
        assert_eq!(
            *count,
            if (128..512).contains(&t) && t != 384 {
                16
            } else {
                0
            }
        );
    }
    println!("HMAC_GENERAL_ORACLE: 6128 cases; 383 parameters; exact-bit inner and outer messages");
}
