use crate::Error;

pub(super) struct Retained<T>(Option<T>);

impl<T> Retained<T> {
    pub(super) fn new(value: T) -> Self {
        Self(Some(value))
    }
    pub(super) fn take(mut self) -> Result<T, Error> {
        self.0.take().ok_or(Error::ExecutionFailed)
    }
    pub(super) fn update(
        &mut self,
        operation: impl FnOnce(&mut T) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut guard = Guard {
            slot: &mut self.0,
            preserve: false,
        };
        let result = operation(guard.slot.as_mut().ok_or(Error::ExecutionFailed)?);
        guard.preserve = matches!(result, Ok(()) | Err(Error::MessageTooLong));
        result
    }
}

struct Guard<'a, T> {
    slot: &'a mut Option<T>,
    preserve: bool,
}
impl<T> Drop for Guard<'_, T> {
    fn drop(&mut self) {
        if !self.preserve {
            let _ = self.slot.take();
        }
    }
}
