// Included only in the generated private ingress/native bridge.
// Still three waves/ten leaves; lengths/content otherwise caller supplied.
struct NativeCopy;
unsafe extern "C" {
    fn PrivateInputCopy(kind: usize, address: usize, destination: *mut u8, length: usize) -> usize;
    fn PrivateInputOutput(source: *const u8, length: usize) -> usize;
}
impl parallel_input::CopyIn for NativeCopy {
    fn copy_into(
        &mut self,
        kind: parallel_input::Kind,
        address: usize,
        destination: &mut [u8],
    ) -> bool {
        let kind = match kind {
            parallel_input::Kind::Header => 0,
            parallel_input::Kind::Custom => 1,
            parallel_input::Kind::Wave => 2,
        };
        // SAFETY: destination is a live exclusive bounded slice. C independently
        // checks admitted root placement and copies through the OS primitive.
        // address is untrusted public metadata, never dereferenced by Rust.
        unsafe { PrivateInputCopy(kind, address, destination.as_mut_ptr(), destination.len()) == 1 }
    }
}

fn root(source: usize) -> Option<usize> {
    let mut frame = parallel_input::InputFrame::new();
    if !contained(&frame) {
        return None;
    }
    let request = frame.begin(source, &mut NativeCopy).ok()?;
    // Keep the existing native three-gate/ten-leaf diagnostic shape. This is
    // NOT the general scheduling API or a claim to cover all ingress bounds.
    if request.input_bits.div_ceil(request.block.checked_mul(8)?) != 10 {
        return None;
    }
    let authority = authority()?;
    let mut root = Waves::new(
        &authority,
        request.identity,
        request.block,
        request.input_bits,
        frame.custom().ok()?,
        request.output_bits,
    )
    .ok()?;
    if !contained(&authority) || !contained(&root) {
        return None;
    }
    for _ in 0..3 {
        let chunk = frame.next_wave(&mut NativeCopy).ok()?;
        let mut publication = None;
        root.wave(|offset, plan, slots| {
            if offset != chunk.offset() {
                return Err(Error::State);
            }
            publication = Some(dispatch(offset, plan, slots, chunk.bytes(), request.block)?);
            Ok(())
        })
        .ok()?;
        let mut publication = publication?;
        publication.join();
        if !publication.wave.retire() {
            return None;
        }
        publication.retired = true;
    }
    frame.finish().ok()?;
    root.finish().ok()?;
    let length = request.output_bits.div_ceil(8);
    let mut output = [0_u8; 1024];
    if !contained(&output) {
        return None;
    }
    let exported = root.declassify_to(output.get_mut(..length)?).is_ok();
    // Explicit PUBLIC declassification in this diagnostic. An OS-copy failure
    // can modify a host prefix; no transactional host-output claim is made.
    let copied = exported && unsafe { PrivateInputOutput(output.as_ptr(), length) == 1 };
    let _ = clear_owned_region(&mut output);
    Some(usize::from(copied))
}

fn run_input_leaf(pointer: *mut Slot<'static>, lane: usize) -> Option<bool> {
    let authority = authority()?;
    let bits = BITS[lane].load(Ordering::Relaxed);
    let block = BLOCK.load(Ordering::Relaxed);
    let width = WIDTH.load(Ordering::Relaxed);
    let input = INPUT.load(Ordering::Relaxed);
    if !(1..=1024).contains(&block) || bits == 0 || bits > block.checked_mul(8)? || input.is_null()
    {
        return None;
    }
    let offset = lane.checked_mul(block)?;
    let count = bits.div_ceil(8);
    if offset.checked_add(count)? > width {
        return None;
    }
    // SAFETY: dispatch published an immutable slice from the root's InputFrame.
    // The claimed generation ticket holds the publication live until this call
    // ends; independent root join precedes next copy/clearing/destruction. Offset
    // and count are checked above, no host address can enter this pointer slot.
    let bytes = unsafe { core::slice::from_raw_parts(input.add(offset), count) };
    let input = Bits::new(bytes, ((bits - 1) % 8 + 1) as u8).ok()?;
    // SAFETY: the caller holds this generation's unique exclusive slot ticket.
    Some(unsafe { (&mut *pointer).run(&authority, input).is_ok() })
}
