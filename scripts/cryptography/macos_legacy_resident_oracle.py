"""Independent bit-message corpus for the separate legacy resident adapters."""
import hashlib
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def oracle(family):
    path = ROOT / f'scripts/{family}/check-{family}-differential.py'
    spec = importlib.util.spec_from_file_location('resident_' + family, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.oracle


def corpus():
    sha1, md5 = oracle('sha1'), oracle('md5')
    lengths = sorted(set(range(33)) | {8 * size - tail for size in
        (7, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 511, 512, 513, 4095, 4096)
        for tail in range(8)})
    rows = []
    for bits in lengths:
        data = bytearray((i * 73 + bits) % 256 for i in range((bits + 7) // 8))
        if bits % 8:
            data[-1] &= (0xff << (8 - bits % 8)) & 0xff
        one, five = sha1(data, bits), md5(data, bits)
        if bits % 8 == 0:
            if (one != hashlib.sha1(data, usedforsecurity=False).hexdigest()
                    or five != hashlib.md5(data, usedforsecurity=False).hexdigest()):
                raise ValueError('legacy bit oracle disagrees with hashlib')
        rows.append(f'{bits} {data.hex() or "-"} {one} {five}')
    return rows


SOURCE = r'''#![forbid(unsafe_code)]
use brynja_legacy_sha1_std::macos_resident as s;
use brynja_legacy_md5_std::macos_resident as m;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn hex(text: &str) -> Result<Vec<u8>> {
    if text == "-" { return Ok(Vec::new()); }
    text.as_bytes().chunks(2).map(|c| Ok(u8::from_str_radix(std::str::from_utf8(c)?,16)?)).collect()
}
fn main() -> Result<()> {
    let sl = s::Limits { stack_bytes:262144,max_stack_mapping_bytes:1048576,
        max_output_mapping_bytes:65536,max_message_bits:65536,max_chunks:8 };
    let ml = m::Limits { stack_bytes:262144,max_stack_mapping_bytes:1048576,
        max_output_mapping_bytes:65536,max_message_bits:65536,max_chunks:8 };
    let mut scalar_sha = s::Session::new(sl)?;
    let mut arm_sha = s::CompiledSession::new(sl)?;
    assert_eq!(arm_sha.backend(),brynja_legacy_sha1::Sha1Backend::Aarch64Sha1);
    let mut scalar_md5 = m::Session::new(ml)?;
    let mut batch = m::batch::Session::new(m::batch::Limits {
        stack_bytes:262144,max_stack_mapping_bytes:1048576,
        max_output_mapping_bytes:65536,max_input_bits:524288 })?;
    assert_eq!(batch.backend(),brynja_legacy_md5::Md5Backend::Aarch64Neon);
    let mut eligible = Vec::new();
    let mut count = 0;
    for line in include_str!("legacy.txt").lines() {
        let columns: Vec<_> = line.split_whitespace().collect();
        let bits: usize = columns[0].parse()?;
        let input = hex(columns[1])?;
        let sha = hex(columns[2])?;
        let md5 = hex(columns[3])?;
        let valid = if bits == 0 {0} else {u8::try_from((bits-1)%8+1)?};
        let split = input.len().saturating_sub(1).min(17);
        let (head,tail) = input.split_at(split);
        assert_eq!(scalar_sha.hash_chunks(&[&[],head,&[]],tail,valid,&s::Cancellation::new())?.expose(),sha);
        assert_eq!(arm_sha.hash_chunks(&[&[],head,&[]],tail,valid,&s::Cancellation::new())?.expose(),sha);
        assert_eq!(scalar_md5.hash_chunks(&[&[],head,&[]],tail,valid,&m::Cancellation::new())?.expose(),md5);
        if bits >= 512 { eligible.push((input,valid,md5)); }
        count += 1;
    }
    assert_eq!(count,169);
    let mut lanes = 0;
    for start in 0..eligible.len() {
        let selected: [_;8] = core::array::from_fn(|i| &eligible[(start+i)%eligible.len()]);
        let inputs = selected.map(|v|Some(m::batch::Input{bytes:&v.0,valid_bits:v.1}));
        let output = batch.digest(&inputs,10000,&m::Cancellation::new())?;
        assert_eq!(output.report().backend,Some(brynja_legacy_md5::Md5Backend::Aarch64Neon));
        assert!(output.report().work.vector_blocks>0);
        for (actual,v) in output.expose().chunks_exact(16).zip(selected) {
            assert_eq!(actual,v.2); lanes += 1;
        }
    }
    assert_eq!(lanes,712);
    println!("RESIDENT_LEGACY_ORACLE: 507 scalar/Arm SHA1/MD5 comparisons; 712 NEON lanes");
    Ok(())
}
'''


def write_consumer(destination):
    rows = corpus()
    if len(rows) != 169 or sum(int(row.split()[0]) >= 512 for row in rows) != 89:
        raise ValueError('legacy corpus population changed')
    (destination / 'src/legacy.txt').write_text('\n'.join(rows) + '\n')
    (destination / 'src/main.rs').write_text(SOURCE)
    return len(rows)
