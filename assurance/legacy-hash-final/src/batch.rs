use brynja_legacy_md5::{
    BitString, HardenedMd5Batch, Md5Batch, Md5BatchControl, Md5BatchError, PublicDeclassification,
};

pub fn check(data: &[u8], width: u8, expected: &[u8]) -> Result<usize, &'static str> {
    let expected: [u8; 16] = expected.try_into().map_err(|_| "frozen digest width")?;
    let bits = BitString::new(data, width).map_err(|_| "invalid frozen bits")?;
    let mut comparisons = 0;
    for mask in [0_u16, 1, 15, 85, 128, 170, 254, 255] {
        let mut inputs = [None; 8];
        let mut wanted = [[0; 16]; 8];
        for (index, (input, digest)) in inputs.iter_mut().zip(&mut wanted).enumerate() {
            if mask & (1 << index) != 0 {
                *input = Some(bits);
                *digest = expected;
            }
        }
        let mut output = [[0xa5; 16]; 8];
        let report = Md5Batch::new()
            .digest(&inputs, &mut output, &mut Md5BatchControl::new(8192))
            .map_err(|_| "portable batch failed")?;
        if output != wanted || report.vector_blocks != 0 {
            return Err("batch lane order, inactive output or portable execution differs");
        }
        HardenedMd5Batch::new()
            .digest_public(
                &inputs,
                &mut output,
                &mut Md5BatchControl::new(8192),
                PublicDeclassification::acknowledge(),
            )
            .map_err(|_| "hardened public batch failed")?;
        if output != wanted {
            return Err("hardened batch differs");
        }
        {
            let (secret, report) = HardenedMd5Batch::new()
                .digest_secret(&inputs, &mut output, &mut Md5BatchControl::new(8192))
                .map_err(|_| "secret batch failed")?;
            if secret.expose() != wanted.as_flattened() || report.vector_blocks != 0 {
                return Err("secret batch differs");
            }
        }
        if output != [[0; 16]; 8] {
            return Err("secret batch output not cleared");
        }
        comparisons += 1;
    }
    Ok(comparisons)
}

pub fn failures() -> Result<(), &'static str> {
    let bits = BitString::new(b"a", 8).map_err(|_| "invalid input")?;
    let inputs = [Some(bits); 8];
    let mut output = [[0xa5; 16]; 8];
    if Md5Batch::new().digest(&inputs, &mut output, &mut Md5BatchControl::new(0))
        != Err(Md5BatchError::WorkLimit)
        || output != [[0xa5; 16]; 8]
    {
        return Err("budget failure changed public output");
    }
    let mut cancel = || true;
    if Md5Batch::new().digest(
        &inputs,
        &mut output,
        &mut Md5BatchControl::with_cancellation(32, &mut cancel),
    ) != Err(Md5BatchError::Cancelled)
        || output != [[0xa5; 16]; 8]
    {
        return Err("cancellation changed public output");
    }
    if HardenedMd5Batch::new()
        .digest_secret(&inputs, &mut output, &mut Md5BatchControl::new(0))
        .map(drop)
        != Err(Md5BatchError::WorkLimit)
        || output != [[0; 16]; 8]
    {
        return Err("budget failure did not clear complete secret output");
    }
    output.fill([0xa5; 16]);
    if HardenedMd5Batch::new()
        .digest_secret(
            &inputs,
            &mut output,
            &mut Md5BatchControl::with_cancellation(32, &mut cancel),
        )
        .map(drop)
        != Err(Md5BatchError::Cancelled)
        || output != [[0; 16]; 8]
    {
        return Err("cancellation did not clear complete secret output");
    }
    Ok(())
}
