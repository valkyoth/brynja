use super::*;
extern crate std;
std::thread_local! {
    static REMOVE_VECTOR_REPORT: Cell<bool> = const { Cell::new(false) };
}

pub(super) fn alter_report(work: &mut Md5BatchReport) {
    if REMOVE_VECTOR_REPORT.get() {
        work.vector_blocks = 0;
    }
}

#[cfg(not(any(miri, kani)))]
#[cfg(any(
    all(target_arch = "x86_64", target_feature = "avx2"),
    all(target_arch = "aarch64", target_feature = "neon")
))]
struct Reset;
#[cfg(not(any(miri, kani)))]
#[cfg(any(
    all(target_arch = "x86_64", target_feature = "avx2"),
    all(target_arch = "aarch64", target_feature = "neon")
))]
impl Drop for Reset {
    fn drop(&mut self) {
        REMOVE_VECTOR_REPORT.set(false);
    }
}

#[test]
#[cfg(not(any(miri, kani)))]
#[cfg(any(
    all(target_arch = "x86_64", target_feature = "avx2"),
    all(target_arch = "aarch64", target_feature = "neon")
))]
fn missing_post_execution_vector_work_quarantines_and_clears() -> Result<(), Error> {
    for secret in [false, true] {
        let executor = Executor::for_compiled_target(Mode::Require)?;
        let bytes = [0x39; 128];
        let bits = BitString::new(&bytes, 8).map_err(|_| Md5BatchError::Backend)?;
        let inputs = [Some(bits); 8];
        let mut output = [[0xa5; 16]; 8];
        REMOVE_VECTOR_REPORT.set(true);
        let reset = Reset;
        let result = if secret {
            executor
                .batch()
                .digest_secret(&inputs, &mut output, &mut Md5BatchControl::new(64))
                .map(|(owner, report)| {
                    drop(owner);
                    report
                })
        } else {
            executor.batch().digest_public(
                &inputs,
                &mut output,
                &mut Md5BatchControl::new(64),
                PublicDeclassification::acknowledge(),
            )
        };
        drop(reset);
        assert_eq!(result, Err(Error::Batch(Md5BatchError::Backend)));
        assert_eq!(executor.health(), Md5BackendHealth::Quarantined);
        assert_eq!(
            output,
            if secret {
                [[0; 16]; 8]
            } else {
                [[0xa5; 16]; 8]
            }
        );
        assert_eq!(
            executor.batch().digest_public(
                &inputs,
                &mut output,
                &mut Md5BatchControl::new(64),
                PublicDeclassification::acknowledge()
            ),
            Err(Error::Quarantined)
        );
    }
    Ok(())
}
