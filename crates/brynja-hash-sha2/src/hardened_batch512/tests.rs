use super::*;
extern crate std;
mod differential;
mod general;
mod lifecycle;

std::thread_local! {
    static DROP_CLEARED: Cell<bool> = const { Cell::new(false) };
}
pub(super) fn observe_drop(s: &Workspace) {
    DROP_CLEARED.with(|flag| flag.set(is_cleared(s)));
}
#[test]
fn destructor_clears_all_leaf_regions() {
    let mut workspace = Workspace::new();
    poison(&mut workspace);
    DROP_CLEARED.with(|flag| flag.set(false));
    drop(workspace);
    assert!(DROP_CLEARED.with(Cell::get));
}

fn bits(bytes: &[u8], tail: u8) -> Result<BitString<'_>, Error> {
    BitString::new(bytes, if bytes.is_empty() { 0 } else { tail }).map_err(|_| Error::Invariant)
}
fn oracle(input: &Input<'_>) -> Result<[u8; 64], Error> {
    let mut result = [0; 64];
    let size = input.algorithm.output_bytes();
    let bytes = result.get_mut(..size).ok_or(Error::Invariant)?;
    match input.algorithm {
        Algorithm::Sha384 => bytes.copy_from_slice(
            crate::Sha384::new()
                .finalize_bits(input.bits)
                .map_err(|_| Error::Invariant)?
                .as_bytes(),
        ),
        Algorithm::Sha512 => bytes.copy_from_slice(
            crate::Sha512::new()
                .finalize_bits(input.bits)
                .map_err(|_| Error::Invariant)?
                .as_bytes(),
        ),
        Algorithm::Sha512_224 => bytes.copy_from_slice(
            crate::Sha512_224::new()
                .finalize_bits(input.bits)
                .map_err(|_| Error::Invariant)?
                .as_bytes(),
        ),
        Algorithm::Sha512_256 => bytes.copy_from_slice(
            crate::Sha512_256::new()
                .finalize_bits(input.bits)
                .map_err(|_| Error::Invariant)?
                .as_bytes(),
        ),
        Algorithm::Sha512T(t) => bytes.copy_from_slice(
            crate::Sha512T::new(t)
                .finalize_bits(input.bits)
                .map_err(|_| Error::Invariant)?
                .as_bytes(),
        ),
    }
    Ok(result)
}
fn destinations<'a>(
    storage: &'a mut [[u8; 64]; CAPACITY],
    inputs: &[Option<Input<'_>>; CAPACITY],
) -> [Option<&'a mut [u8]>; CAPACITY] {
    let mut index = 0_usize;
    storage.each_mut().map(|out| {
        let input = inputs.get(index).and_then(Option::as_ref);
        index = index.saturating_add(1);
        input.and_then(|input| out.get_mut(..input.algorithm.output_bytes()))
    })
}
fn poison(s: &mut Workspace) {
    s.states.as_flattened_mut().fill(0xa5);
    s.packed.as_flattened_mut().fill(0xa5);
    s.blocks.as_flattened_mut().fill(0xa5);
    s.output.as_flattened_mut().fill(0xa5);
    s.offsets.as_flattened_mut().fill(0xa5);
    s.indices.fill(0xa5);
    s.active.fill(0xa5);
    s.scalar.chaining_state.fill(0xa5);
    s.scalar.partial_input.fill(0xa5);
    s.scalar.message_length.fill(0xa5);
    s.scalar.phase.fill(0xa5);
    s.scalar.message_schedule.fill(0xa5);
    s.scalar.block_copy.fill(0xa5);
    s.scalar.padding_block.fill(0xa5);
    s.scalar.output_staging.fill(0xa5);
}
fn cleared(s: &Workspace) {
    assert!(is_cleared(s));
}
fn is_cleared(s: &Workspace) -> bool {
    [
        s.states.as_flattened(),
        s.packed.as_flattened(),
        s.blocks.as_flattened(),
        s.output.as_flattened(),
        s.offsets.as_flattened(),
        &s.indices,
        &s.active,
        &s.scalar.chaining_state,
        &s.scalar.partial_input,
        &s.scalar.message_length,
        &s.scalar.phase,
        &s.scalar.message_schedule,
        &s.scalar.block_copy,
        &s.scalar.padding_block,
        &s.scalar.output_staging,
    ]
    .into_iter()
    .all(|region| region.iter().all(|byte| *byte == 0))
}
fn reusable(executor: &Executor<'_>) -> Result<(), Error> {
    executor.check()?;
    // At least two full blocks in every lane also satisfies Require mode.
    let bytes = [0x93; 256];
    let b = bits(&bytes, 8)?;
    let inputs = core::array::from_fn(|_| Some(Input::new(Algorithm::Sha512, b)));
    let mut storage = [[0xa5; 64]; CAPACITY];
    let mut workspace = Workspace::new();
    let mut cancel = || false;
    let mut control = Control::new(12, &mut cancel);
    executor.digest_public(
        &inputs,
        destinations(&mut storage, &inputs),
        &mut workspace,
        &mut control,
        PublicDeclassification::acknowledge(),
    )?;
    for (out, input) in storage.iter().zip(inputs.iter().flatten()) {
        assert_eq!(*out, oracle(input)?);
    }
    cleared(&workspace);
    Ok(())
}

#[test]
fn portable_sha384_sha512_known_answers_and_output_drop() -> Result<(), Error> {
    let inputs = [
        Some(Input::new(
            Algorithm::Sha384,
            BitString::new(b"abc", 8).map_err(|_| Error::Invariant)?,
        )),
        Some(Input::new(
            Algorithm::Sha512,
            BitString::new(b"abc", 8).map_err(|_| Error::Invariant)?,
        )),
        None,
        None,
    ];
    let mut a = [0xa5; 48];
    let mut b = [0xa5; 64];
    let mut workspace = Workspace::new();
    let mut cancelled = || false;
    let mut control = Control::new(2, &mut cancelled);
    let (out, report) = Executor::portable().digest_secret(
        &inputs,
        [Some(&mut a), Some(&mut b), None, None],
        &mut workspace,
        &mut control,
    )?;
    assert_eq!(out.algorithm(0), Some(Algorithm::Sha384));
    assert_eq!(out.algorithm(1), Some(Algorithm::Sha512));
    assert_eq!(out.algorithm(2), None);
    assert_eq!(
        out.expose(0),
        Some(
            crate::sha384(b"abc")
                .map_err(|_| Error::Invariant)?
                .as_bytes()
                .as_slice()
        )
    );
    assert_eq!(
        out.expose(1),
        Some(
            crate::sha512(b"abc")
                .map_err(|_| Error::Invariant)?
                .as_bytes()
                .as_slice()
        )
    );
    assert_eq!(report.scalar_blocks, 2);
    assert_eq!(report.vector_calls, 0);
    assert_eq!(control.used(), 2);
    drop(out);
    assert_eq!(a, [0; 48]);
    assert_eq!(b, [0; 64]);
    Ok(())
}
