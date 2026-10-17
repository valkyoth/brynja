"""Public ordinary legacy selection controls; no secret or private API access."""
PROBE = r'''
fn main() {
    #[cfg(target_arch="x86_64")]
    println!("CPU:x86_64:{}:{}", std::is_x86_feature_detected!("sha") && std::is_x86_feature_detected!("sse2"), std::is_x86_feature_detected!("avx2"));
    #[cfg(target_arch="aarch64")]
    println!("CPU:aarch64:{}:{}", std::arch::is_aarch64_feature_detected!("sha2") && std::arch::is_aarch64_feature_detected!("neon"), std::arch::is_aarch64_feature_detected!("neon"));
    #[cfg(not(any(target_arch="x86_64", target_arch="aarch64")))]
    println!("CPU:other:false:false");
}
'''

SELECTION = r'''
use LEAF::{execution::{Executor, Mode}, BACKEND};
use HOST::execution as hosted;

#[test]
fn compiled_and_hosted_selection_cannot_silently_downgrade() {
    let compiled = if cfg!(all(target_arch="x86_64", X86_FEATURES)) {
        Some(BACKEND::X86_VARIANT)
    } else if cfg!(all(target_arch="aarch64",target_endian="little", ARM_FEATURES)) {
        Some(BACKEND::ARM_VARIANT)
    } else { None };
    let preferred = Executor::for_compiled_target(Mode::Prefer).unwrap();
    assert_eq!(preferred.BACKEND_EXPR, compiled);
    assert!(Executor::portable().BACKEND_EXPR.is_none());
    let required = Executor::for_compiled_target(Mode::Require);
    if let Some(backend) = compiled {
        assert_eq!(required.unwrap().BACKEND_EXPR, Some(backend));
    } else { assert!(required.is_err()); }
    let available = hosted::availability().is_ok();
    let preferred = hosted::select(Mode::Prefer).unwrap();
    assert_eq!(preferred.BACKEND_EXPR.is_some(), available);
    assert!(hosted::select(Mode::Portable).unwrap().BACKEND_EXPR.is_none());
    let required = hosted::select(Mode::Require);
    if available {
        assert_eq!(required.unwrap().BACKEND_EXPR, preferred.BACKEND_EXPR);
    } else { assert!(matches!(required, Err(hosted::Error::Unavailable(_)))); }
    println!("LEGACY_SELECTION: static={}; hosted={}", compiled.is_some(), available);
}
'''


def selection(family):
    values = {
        'sha1': ('Sha1Backend', 'X86Sha', 'Aarch64Sha1', 'report().backend',
                 'target_feature="sha",target_feature="sse2"', 'target_feature="sha2",target_feature="neon"'),
        'md5': ('Md5Backend', 'X86Avx2', 'Aarch64Neon', 'backend()',
                'target_feature="avx2"', 'target_feature="neon"'),
    }
    backend, x86, arm, expression, xflags, aflags = values[family]
    text = SELECTION
    for before, after in (('BACKEND_EXPR', expression), ('X86_FEATURES', xflags),
                          ('ARM_FEATURES', aflags), ('X86_VARIANT', x86), ('ARM_VARIANT', arm),
                          ('BACKEND', backend), ('LEAF', 'brynja_legacy_' + family),
                          ('HOST', 'brynja_legacy_' + family + '_std')):
        text = text.replace(before, after)
    return text


def mutations(family, native):
    if family == 'sha1':
        cases = [
            ('execution.rs', 'self.revoked.set(true);', 'self.revoked.set(false);'),
            ('execution.rs', 'pub fn finalize(mut self) -> Result<[u8; 20], Error> {\n        self.executor.ready()?;',
             'pub fn finalize(mut self) -> Result<[u8; 20], Error> {'),
        ]
        if native:
            cases.append(('execution.rs', 'Ok(owner) => Self::with_authority(owner),',
                          'Ok(_owner) => Ok(Self::portable()),'))
        return cases
    cases = [
        ('batch/execution.rs', 'owner.commit_public(output);', 'let _ = output;'),
        ('batch/execution.rs', 'owner.commit_public(output);',
         'owner.commit_public(output); if let Some(last) = output.last_mut() { last.fill(0); }'),
    ]
    for field in ('scalar_blocks', 'vector_blocks'):
        cases.append(('batch/execution.rs', 'owner.commit_public(output);',
                      f'let mut work = work; work.{field} += 1; owner.commit_public(output);'))
    if native:
        cases.extend([
            ('batch/execution.rs', 'vector::execute(&mut owner, inputs, control, a.session())', 'owner.portable(inputs, control)'),
            ('batch/vector.rs', 'session\n                .compress(&mut states, &data)\n                .map_err(|_| Md5BatchError::Backend)?;',
             'let _ = (&mut states, &data);'),
        ])
    return cases


def misuses(family):
    prefix = 'brynja_legacy_' + family
    backend, variant = ('Sha1Backend', 'X86Sha') if family == 'sha1' else ('Md5Backend', 'X86Avx2')
    call = ('e.hash(b"abc")' if family == 'sha1' else
            f'e.digest(&[None;8], &mut [[0;16];8], &mut {prefix}::Md5BatchControl::new(0))')
    return (
        (f'fn bad() {{let _ = {prefix}::execution::Authority::from_platform({prefix}::{backend}::{variant}, |_| true);}}', 'E0133'),
        (f'fn bad(a: &{prefix}::execution::Authority) {{let _ = a.session();}}', 'E0624'),
        (f'fn bad(e: &{prefix}::execution::Executor) {{let _ = {call};}}', 'E0061'),
    )
