// Test-only address/value controls. No cryptographic or timer implementation.
use std::hint::black_box;

pub type Input = ([u8; 32], [u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    SeparateValues,
    SharedValues,
    SeparateIdentical,
    SharedIdentical,
}

impl Control {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "separate-values" => Ok(Self::SeparateValues),
            "shared-values" => Ok(Self::SharedValues),
            "separate-identical" => Ok(Self::SeparateIdentical),
            "shared-identical" => Ok(Self::SharedIdentical),
            _ => Err("unknown address/value control".into()),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::SeparateValues => "separate-values",
            Self::SharedValues => "shared-values",
            Self::SeparateIdentical => "separate-identical",
            Self::SharedIdentical => "shared-identical",
        }
    }

    pub fn pair(self, mut pair: [Input; 2]) -> [Input; 2] {
        if matches!(self, Self::SeparateIdentical | Self::SharedIdentical) {
            pair[1] = pair[0];
        }
        pair
    }

    pub fn invoke<T>(
        self,
        pair: &[Input; 2],
        class: usize,
        common: &mut Common,
        operation: impl FnOnce(&[u8; 32], &[u8; 16]) -> T,
    ) -> Result<T, String> {
        let selected = pair.get(class).ok_or("invalid class")?;
        if matches!(self, Self::SharedValues | Self::SharedIdentical) {
            // One fixed, aligned slot per campaign. Materialize both buffers
            // before calling the trial (and thus before Instant::now).
            let common = black_box(common);
            common.key.copy_from_slice(black_box(&selected.0));
            common.block.copy_from_slice(black_box(&selected.1));
            Ok(operation(black_box(&common.key), black_box(&common.block)))
        } else {
            Ok(operation(black_box(&selected.0), black_box(&selected.1)))
        }
    }
}

#[repr(C, align(64))]
#[derive(Default)]
pub struct Common {
    key: [u8; 32],
    block: [u8; 16],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_names_are_closed_and_roundtrip() {
        for name in [
            "separate-values",
            "shared-values",
            "separate-identical",
            "shared-identical",
        ] {
            assert_eq!(Control::parse(name).unwrap().name(), name);
        }
        for name in ["", "shared", "unknown", "shared-values "] {
            assert!(Control::parse(name).is_err());
        }
    }

    #[test]
    fn controls_preserve_or_equalize_the_complete_input() {
        let input = [([7; 32], [8; 16]), ([9; 32], [10; 16])];
        for control in [Control::SeparateValues, Control::SharedValues] {
            assert_eq!(control.pair(input), input);
        }
        for control in [Control::SeparateIdentical, Control::SharedIdentical] {
            assert_eq!(control.pair(input), [input[0], input[0]]);
        }
    }

    #[test]
    fn address_control_is_independent_of_values_and_class_order() {
        let input = [([7; 32], [8; 16]), ([9; 32], [10; 16])];
        for control in [
            Control::SeparateValues,
            Control::SharedValues,
            Control::SeparateIdentical,
            Control::SharedIdentical,
        ] {
            let pair = control.pair(input);
            let mut common = Common::default();
            let mut addresses = [None, None];
            for class in [0, 1, 1, 0] {
                let pointers = control
                    .invoke(&pair, class, &mut common, |key, block| {
                        assert_eq!((*key, *block), pair[class]);
                        (key.as_ptr() as usize, block.as_ptr() as usize)
                    })
                    .unwrap();
                if let Some(previous) = addresses[class] {
                    assert_eq!(previous, pointers);
                }
                addresses[class] = Some(pointers);
            }
            if matches!(control, Control::SharedValues | Control::SharedIdentical) {
                assert_eq!(addresses[0], addresses[1]);
                let (key, block) = addresses[0].unwrap();
                assert_eq!(key % 64, 0);
                assert_eq!(block, key + 32);
            } else {
                assert_ne!(addresses[0].unwrap().0, addresses[1].unwrap().0);
                assert_ne!(addresses[0].unwrap().1, addresses[1].unwrap().1);
            }
        }
    }

    #[test]
    fn invalid_class_does_not_invoke_operation() {
        let pair = [([0; 32], [0; 16]); 2];
        for control in [Control::SeparateValues, Control::SharedValues] {
            assert!(
                control
                    .invoke(&pair, 2, &mut Common::default(), |_, _| panic!(
                        "must not run"
                    ))
                    .is_err()
            );
        }
    }
}
