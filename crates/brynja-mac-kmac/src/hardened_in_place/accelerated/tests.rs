use super::*;

#[test]
fn scoped_accelerated_scratch_guard_clears_on_exit() {
    let mut bytes = [0xa5; 200];
    {
        let _guard = Scratch(&mut bytes);
    }
    assert_eq!(bytes, [0; 200]);
}
