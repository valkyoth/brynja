"""Downstream strict-only exports, ownership and default-feature regressions."""
import json


FORBIDDEN = ('crypto', 'legacy', 'protected_memory', 'execution::Authority',
             'sha2::Sha256', 'sha3::HardenedSha3_256',
             'parallelhash::ParallelHashExecutor', 'enclave::Backend',
             'enclave::Driver', 'enclave::engine', 'enclave::policy',
             'enclave::sha2::transport', 'enclave::sha2::Owner',
             'enclave::sha3::transport', 'enclave::sha3::Owner',
             'enclave::kmac::transport', 'enclave::kmac::Owner',
             'enclave::tuplehash::transport', 'enclave::tuplehash::Owner',
             'enclave::sha2_batch::transport', 'enclave::sha2_batch::Owner',
             'enclave::sha3_batch::transport', 'enclave::sha3_batch::Owner',
             'enclave::parallelhash::transport', 'enclave::parallelhash::Owner')
MODULES = ('sha2', 'sha3', 'kmac', 'tuplehash', 'parallelhash', 'batch', 'enclave')


def section_example(document, heading):
    """Select the named API example, not whichever fenced block appears first."""
    marker = '## ' + heading + '\n'
    if document.count(marker) != 1:
        raise ValueError('missing or ambiguous guide section: ' + heading)
    section = document.split(marker, 1)[1].split('\n## ', 1)[0]
    if section.count('```rust,no_run\n') != 1:
        raise ValueError('missing or ambiguous Rust example: ' + heading)
    return section.split('```rust,no_run\n', 1)[1].split('```', 1)[0]


def check(root, roots, destination, cargo, env, run, require):
    consumer = destination / 'strict-facade-consumer'
    (consumer / 'src').mkdir(parents=True)
    manifest = '''[package]
name = "strict-facade-consumer"
version = "0.0.0"
edition = "2024"
[features]
acceleration = ["brynja-strict/acceleration"]
[dependencies]
brynja-strict = { version = "=0.1.0", default-features = false }
[workspace]
[patch.crates-io]
'''
    manifest += ''.join(f'{name} = {{path={json.dumps(str(path))}}}\n'
                        for name, path in roots.items())
    (consumer / 'Cargo.toml').write_text(manifest)
    source = consumer / 'src/lib.rs'
    positive = '#![forbid(unsafe_code)]\n'
    positive += '\n'.join(f'pub type {name.title()} = brynja_strict::{name}::Session;'
                          for name in MODULES)
    positive += '\n' + '\n'.join(
        f"pub type EnclaveSha3{kind}<'a> = brynja_strict::enclave::sha3::{kind}<'a>;"
        for kind in ('Stream', 'Reader', 'Retained', 'Finalized'))
    positive += '\npub type EnclaveSha3Session = brynja_strict::enclave::sha3::Session;'
    positive += '\n' + '\n'.join(
        f"pub type EnclaveKmac{kind}<'a> = brynja_strict::enclave::kmac::{kind}<'a>;"
        for kind in ('Stream', 'Reader', 'Retained'))
    positive += '\npub type EnclaveKmacSession = brynja_strict::enclave::kmac::Session;'
    positive += '\n' + '\n'.join(
        f"pub type EnclaveTuple{kind}<'a> = brynja_strict::enclave::tuplehash::{kind}<'a>;"
        for kind in ('Stream', 'Reader', 'Retained'))
    positive += '\npub type EnclaveTupleSession = brynja_strict::enclave::tuplehash::Session;'
    positive += "\npub type EnclaveTupleItem<'s, 'a> = brynja_strict::enclave::tuplehash::Item<'s, 'a>;"
    positive += '\npub type EnclaveSha2BatchSession = brynja_strict::enclave::sha2_batch::Session;'
    positive += '\n' + '\n'.join(
        f"pub type EnclaveSha2Batch{kind}<'a> = brynja_strict::enclave::sha2_batch::{kind}<'a>;"
        for kind in ('Batch', 'Retained'))
    positive += "\npub type EnclaveSha2BatchItem<'s, 'a> = brynja_strict::enclave::sha2_batch::Item<'s, 'a>;"
    positive += '\npub type EnclaveSha3BatchSession = brynja_strict::enclave::sha3_batch::Session;'
    positive += '\n' + '\n'.join(
        f"pub type EnclaveSha3Batch{kind}<'a> = brynja_strict::enclave::sha3_batch::{kind}<'a>;"
        for kind in ('Batch', 'Retained'))
    positive += "\npub type EnclaveSha3BatchItem<'s, 'a> = brynja_strict::enclave::sha3_batch::Item<'s, 'a>;"
    positive += '\npub type EnclaveParallelSession = brynja_strict::enclave::parallelhash::Session;'
    positive += '\n' + '\n'.join(
        f"pub type EnclaveParallel{kind}<'a> = brynja_strict::enclave::parallelhash::{kind}<'a>;"
        for kind in ('Stream', 'Reader', 'Retained', 'Finalized'))
    # Compile the actual deployment-guide example, not a second hand-written copy.
    guide = (root / 'docs/windows-enclave-sha3.md').read_text()
    example = section_example(guide, 'Stream and retain output')
    positive += '\n' + example.replace('fn public_example', 'pub fn public_example')
    batch = guide.split('## Batching\n')[1].split('```rust,no_run\n')[1].split('```')[0]
    positive += '\nmod sha3_batch_example {\n' + batch + '\n}\n'
    batch_guide = (root / 'docs/windows-enclave-sha2-batch.md').read_text()
    batch_example = batch_guide.split('```rust,no_run\n')[1].split('```')[0]
    positive += '\nmod batch_example {\n' + batch_example + '\n}\n'
    parallel_guide = (root / 'docs/windows-enclave-parallelhash.md').read_text()
    positive += '\nmod parallel_example {\n' + parallel_guide.split('```rust,no_run\n')[1].split('```')[0] + '\n}\n'
    source.write_text(positive)
    (consumer / 'tests').mkdir()
    (consumer / 'tests/facade.rs').write_text(
        (root / 'crates/brynja-strict/src/tests.rs').read_text().replace('crate::sha2', 'brynja_strict::sha2'))
    require(run([*cargo, 'generate-lockfile', '--offline'], consumer, env))
    count = 0
    for features in ([], ['--features', 'acceleration']):
        compiled = '\n'.join(f'pub type Compiled{name.title()} = brynja_strict::{name}::CompiledSession;'
                             for name in MODULES if name not in ('batch', 'enclave'))
        compiled += "\npub fn enclave_sha_ni_open(path: &std::path::Path, policy: &'static brynja_strict::enclave::ImagePolicy) -> Result<brynja_strict::enclave::sha2::Session, brynja_strict::enclave::Error> { brynja_strict::enclave::sha2::Session::open_sha_ni(path, policy) }"
        compiled += "\npub fn enclave_sha3_avx2_open(path: &std::path::Path, policy: &'static brynja_strict::enclave::ImagePolicy) -> Result<brynja_strict::enclave::sha3::Session, brynja_strict::enclave::Error> { brynja_strict::enclave::sha3::Session::open_avx2(path, policy) }"
        selected = positive + ('\n' + compiled if features else '')
        if features:
            selected += '\nmod wide_simd_example {\n' + section_example(batch_guide, 'Four-message wide SIMD') + '\n}\n'
            selected += '\nmod narrow_simd_example {\n' + section_example(batch_guide, 'Eight-message narrow SIMD') + '\n}\n'
            selected += "\npub fn enclave_sha256_simd_open(path: &std::path::Path, policy: &'static brynja_strict::enclave::ImagePolicy) -> Result<brynja_strict::enclave::sha256_simd::Session, brynja_strict::enclave::Error> { brynja_strict::enclave::sha256_simd::Session::open_avx2(path, policy) }"
            selected += "\npub type EnclaveSha256SimdRetained<'a> = brynja_strict::enclave::sha256_simd::Retained<'a>;"
            selected += "\npub fn enclave_sha512_simd_open(path: &std::path::Path, policy: &'static brynja_strict::enclave::ImagePolicy) -> Result<brynja_strict::enclave::sha512_simd::Session, brynja_strict::enclave::Error> { brynja_strict::enclave::sha512_simd::Session::open_avx2(path, policy) }"
            selected += "\npub type EnclaveSha512SimdRetained<'a> = brynja_strict::enclave::sha512_simd::Retained<'a>;"
            selected += "\npub fn enclave_sha2_batch_sha_ni_open(path: &std::path::Path, policy: &'static brynja_strict::enclave::ImagePolicy) -> Result<brynja_strict::enclave::sha2_batch::Session, brynja_strict::enclave::Error> { brynja_strict::enclave::sha2_batch::Session::open_sha_ni(path, policy) }"
            selected += "\npub fn enclave_parallelhash_avx2_open(path: &std::path::Path, policy: &'static brynja_strict::enclave::ImagePolicy) -> Result<brynja_strict::enclave::parallelhash::Session, brynja_strict::enclave::Error> { brynja_strict::enclave::parallelhash::Session::open_avx2(path, policy) }"
            selected += "\npub fn enclave_sha3_batch_avx2_open(path: &std::path::Path, policy: &'static brynja_strict::enclave::ImagePolicy) -> Result<brynja_strict::enclave::sha3_batch::Session, brynja_strict::enclave::Error> { brynja_strict::enclave::sha3_batch::Session::open_avx2(path, policy) }"
            selected += "\npub fn enclave_tuple_avx2_open(path: &std::path::Path, policy: &'static brynja_strict::enclave::ImagePolicy) -> Result<brynja_strict::enclave::tuplehash::Session, brynja_strict::enclave::Error> { brynja_strict::enclave::tuplehash::Session::open_avx2(path, policy) }"
            selected += "\npub fn enclave_kmac_avx2_open(path: &std::path::Path, policy: &'static brynja_strict::enclave::ImagePolicy) -> Result<brynja_strict::enclave::kmac::Session, brynja_strict::enclave::Error> { brynja_strict::enclave::kmac::Session::open_avx2(path, policy) }"
        source.write_text(selected)
        for profile in ([], ['--release']):
            require(run([*cargo, 'test', '--locked', '--offline', *features, *profile], consumer, env))
        base = [*cargo, 'check', '--locked', '--offline', *features]
        cases = [(f'use brynja_strict::{name};',
                  'E0603' if name in ('enclave::Backend', 'enclave::engine', 'enclave::policy',
                                     'enclave::sha2::transport','enclave::sha2::Owner',
                                     'enclave::sha3::transport','enclave::sha3::Owner',
                                     'enclave::kmac::transport','enclave::kmac::Owner',
                                     'enclave::tuplehash::transport','enclave::tuplehash::Owner',
                                     'enclave::sha2_batch::transport','enclave::sha2_batch::Owner',
                                     'enclave::sha3_batch::transport','enclave::sha3_batch::Owner',
                                     'enclave::parallelhash::transport','enclave::parallelhash::Owner') else 'E0432')
                 for name in FORBIDDEN]
        if not features:
            cases += [('use brynja_strict::enclave::sha512_simd;', 'E0432')]
            cases += [('use brynja_strict::enclave::sha256_simd;', 'E0432')]
            cases += [(f'use brynja_strict::{name}::CompiledSession;', 'E0432')
                      for name in MODULES if name not in ('batch', 'enclave')]
            cases += [('fn probe() { let _ = brynja_strict::enclave::sha2::Session::open_sha_ni; }', 'E0599')]
            cases += [('fn probe() { let _ = brynja_strict::enclave::sha3::Session::open_avx2; }', 'E0599')]
        for module in MODULES:
            if module == 'enclave' and not features:
                cases.append(('fn probe() { let _ = brynja_strict::enclave::sha2_batch::Session::open_sha_ni; }', 'E0599'))
                cases.append(('fn probe() { let _ = brynja_strict::enclave::sha3_batch::Session::open_avx2; }', 'E0599'))
                cases.append(('fn probe() { let _ = brynja_strict::enclave::parallelhash::Session::open_avx2; }', 'E0599'))
                cases.append(('fn probe() { let _ = brynja_strict::enclave::tuplehash::Session::open_avx2; }', 'E0599'))
                cases.append(('fn probe() { let _ = brynja_strict::enclave::kmac::Session::open_avx2; }', 'E0599'))
            for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                cases.append((f'fn require<T: {trait}>() {{}}\n'
                              f'fn probe() {{ require::<brynja_strict::{module}::Session>(); }}', 'E0277'))
        for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
            cases.append((f'fn require<T: {trait}>() {{}}\n'
                          "fn probe() { require::<brynja_strict::enclave::Digest<'static>>(); }", 'E0277'))
            for kind in ('Session',"Stream<'static>","Digest<'static>"):
                cases.append((f'fn require<T: {trait}>() {{}}\n'
                    f'fn probe() {{ require::<brynja_strict::enclave::sha2::{kind}>(); }}','E0277'))
            for kind in ('Session', "Stream<'static>", "Reader<'static>",
                         "Retained<'static>", "Finalized<'static>"):
                cases.append((f'fn require<T: {trait}>() {{}}\n'
                    f'fn probe() {{ require::<brynja_strict::enclave::sha3::{kind}>(); }}','E0277'))
        try:
            if features:
                for name in ('Owner', 'Lease', 'transport', 'wire'):
                    cases.append((f'use brynja_strict::enclave::sha256_simd::{name};', 'E0603'))
                for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                    for kind in ('Session', "Retained<'static>"):
                        cases.append((f'fn require<T: {trait}>() {{}}\n'
                            f'fn probe() {{ require::<brynja_strict::enclave::sha256_simd::{kind}>(); }}', 'E0277'))
                for name in ('Owner', 'Lease', 'transport', 'wire'):
                    cases.append((f'use brynja_strict::enclave::sha512_simd::{name};', 'E0603'))
                for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                    for kind in ('Session', "Retained<'static>"):
                        cases.append((f'fn require<T: {trait}>() {{}}\n'
                            f'fn probe() {{ require::<brynja_strict::enclave::sha512_simd::{kind}>(); }}', 'E0277'))
            for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                for kind in ('Session', "Stream<'static>", "Reader<'static>", "Retained<'static>", "Finalized<'static>"):
                    cases.append((f'fn require<T: {trait}>() {{}}\n'
                        f'fn probe() {{ require::<brynja_strict::enclave::parallelhash::{kind}>(); }}', 'E0277'))
            for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                for kind in ('Session', "Batch<'static>", "Retained<'static>", "Item<'static, 'static>"):
                    cases.append((f'fn require<T: {trait}>() {{}}\n'
                        f'fn probe() {{ require::<brynja_strict::enclave::sha3_batch::{kind}>(); }}', 'E0277'))
            for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                for kind in ('Session', "Batch<'static>", "Retained<'static>", "Item<'static, 'static>"):
                    cases.append((f'fn require<T: {trait}>() {{}}\n'
                        f'fn probe() {{ require::<brynja_strict::enclave::sha2_batch::{kind}>(); }}', 'E0277'))
            for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                for kind in ('Session', "Stream<'static>", "Reader<'static>", "Retained<'static>", "Item<'static, 'static>"):
                    cases.append((f'fn require<T: {trait}>() {{}}\n'
                        f'fn probe() {{ require::<brynja_strict::enclave::tuplehash::{kind}>(); }}', 'E0277'))
            for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                for kind in ('Session', "Stream<'static>", "Reader<'static>", "Retained<'static>"):
                    cases.append((f'fn require<T: {trait}>() {{}}\n'
                        f'fn probe() {{ require::<brynja_strict::enclave::kmac::{kind}>(); }}', 'E0277'))
            for negative, error in cases:
                source.write_text('#![forbid(unsafe_code)]\n' + negative)
                result = run(base, consumer, env)
                if not result.returncode or f'error[{error}]' not in result.stderr:
                    raise ValueError('strict facade negative survived or failed unexpectedly: '
                                     + negative + '\n' + result.stderr[-2000:])
                count += 1
        finally:
            source.write_text(selected)
        require(run(base, consumer, env))
    print(f'Packaged strict-only facade: debug/release reuse; {count} export/ownership negatives rejected', flush=True)
