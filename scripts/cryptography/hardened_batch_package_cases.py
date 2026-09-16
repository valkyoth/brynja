"""External type-boundary probes for distinct hardened multibuffer owners."""

CPU = ('sha256', 'sha512', 'keccak')
LEAVES = (('brynja_hash_sha2', 'hardened_batch', 'batch'),
          ('brynja_hash_sha2', 'hardened_batch512', 'batch512'),
          ('brynja_hash_sha3', 'hardened_batch', 'batch'))
TRAITS = ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug')


def owners():
    result = []
    for family in CPU:
        base = f'brynja_crypto_cpu::{family}_hardened_batch::'
        result += [base + 'Authority', base + "Session<'static>", base + 'Workspace']
        result += [f'brynja_crypto_cpu_std::{family}_hardened_batch::Authority']
    for package, hardened, _ in LEAVES:
        base = f'{package}::{hardened}::'
        result += [base + "Executor<'static>", base + 'Workspace', base + "SecretBatchOutput<'static>"]
    base = 'brynja_hash_parallel::execution::batch::'
    result += [base + 'Workspace', base + "Leaves<'static, 'static, 'static>",
               base + "Stream<'static, 'static, 'static>",
               base + "StreamReader<'static, 'static, 'static, 'static>",
               base + "TransferredLeaves<'static, 'static, 'static>"]
    return result


def boundaries():
    """Each rejection has a same-type positive control and expected Rust error."""
    result = []
    for owner in owners():
        for trait in TRAITS:
            if 'TransferredLeaves<' in owner and trait == 'Send':
                continue  # Only completed CV transport is intentionally auto-Send.
            result.append((f'{owner}: !{trait}',
                           f'pub fn probe(_: Option<{owner}>) {{}}',
                           f'fn require<T: {trait}>() {{}} pub fn probe() {{ require::<{owner}>(); }}',
                           'E0277'))
    return result


def substitutions():
    pairs = []
    for family in CPU:
        for owner in ('Authority', "Session<'static>"):
            pairs.append((f'brynja_crypto_cpu::{family}_hardened_batch::{owner}',
                          f'brynja_crypto_cpu::{family}_batch::{owner}'))
        pairs.append((f'brynja_crypto_cpu_std::{family}_hardened_batch::Authority',
                      f'brynja_crypto_cpu_std::{family}_batch::Authority'))
    for package, hardened, ordinary in LEAVES:
        pairs.append((f"{package}::{hardened}::Executor<'static>",
                      f"{package}::{ordinary}::Executor<'static>"))
    pairs.append(('brynja_hash_sha3::hardened_batch::Workspace',
                  'brynja_hash_sha3::batch::Workspace'))
    for hardened, ordinary in pairs:
        positive = f'pub fn probe(value: {hardened}) -> {hardened} {{ value }}'
        negative = f'pub fn probe(value: {ordinary}) -> {hardened} {{ value }}'
        yield (f'ordinary substitution: {hardened}', positive, negative, 'E0308')
    for package, hardened, digest in (
        ('brynja_hash_sha2', 'hardened_batch', 'Sha256Digest'),
        ('brynja_hash_sha2', 'hardened_batch512', 'Sha512Digest'),
        ('brynja_hash_sha2', 'hardened_batch512', 'Sha512TDigest'),
    ):
        secret = f"{package}::{hardened}::SecretBatchOutput<'static>"
        public = f'{package}::{digest}'
        yield (f'implicit declassification: {public}',
               f'pub fn probe(_: {secret}, value: {public}) -> {public} {{ value }}',
               f'pub fn probe(value: {secret}) -> {public} {{ value.into() }}', 'E0277')


def examples(roots):
    """Run the shipped runnable module examples as an actual outside consumer."""
    paths = (
        ('brynja-hash-sha2', 'src/hardened_batch/mod.rs'),
        ('brynja-hash-sha2', 'src/hardened_batch512/mod.rs'),
        ('brynja-hash-sha3', 'src/hardened_batch/mod.rs'),
        ('brynja-hash-parallel', 'src/execution/batch.rs'),
        ('brynja-hash-parallel', 'src/execution/stream/batch.rs'),
        ('brynja-hash-parallel-std', 'src/execution/batch.rs'),
    )
    source = '#![forbid(unsafe_code)]\n'
    for index, (package, path) in enumerate(paths):
        lines = (roots[package] / path).read_text().splitlines()
        if path == 'src/execution/stream/batch.rs':
            lines = lines[:lines.index("pub struct Stream<'workspace, 'worker, 'authority> {")]
            lines = [line for line in lines if line.startswith('///')]
            lines = ['//!' + line[3:] for line in lines]
        docs = []
        for line in lines:
            if not line.startswith('//!'):
                break
            docs.append('///' + line[3:])
        if not any(line.startswith('/// ```') for line in docs):
            raise ValueError('missing runnable downstream example: ' + path)
        source += '\n'.join(docs) + f'\npub mod example_{index} {{}}\n'
    return source


def compiled_mutants(simd):
    for family in CPU:
        base = f'src/{family}_hardened_batch/'
        drop_test = ('every_region_clears_explicitly_and_on_drop' if family == 'keccak'
                     else 'destructor_clears_poisoned_storage')
        yield ('brynja-crypto-cpu', base + 'scratch.rs',
               'self.wipe();\n        #[cfg(test)]', '// omitted wipe\n        #[cfg(test)]',
               family + '_hardened_batch::tests::' + drop_test, 1)
        if simd:
            dispatch_test = ('native_word_and_byte_entries_match_independent_reference' if family == 'keccak'
                             else 'native_lane_distinct_differential_and_actual_dispatch')
            yield ('brynja-crypto-cpu', base + 'mod.rs',
                   'platform::dispatch(self.kernel(), operation.workspace)?;', '// omitted vector dispatch',
                   family + '_hardened_batch::tests::' + dispatch_test, 2)
    for module in ('hardened_batch', 'hardened_batch512'):
        yield ('brynja-hash-sha2', f'src/{module}/workspace.rs',
               'clear_owned_region(self.states.as_flattened_mut())', 'Ok::<(), ()>(())',
               module + '::tests::destructor_clears_all_leaf_regions', 1)
    yield ('brynja-hash-sha3', 'src/hardened_batch/workspace.rs',
           'clear_owned_region(self.states.as_flattened_mut())', 'Ok::<(), ()>(())',
           'hardened_batch::tests::lifecycle::workspace_destructor_clears_real_partial_state', 1)
    yield ('brynja-hash-parallel', 'src/execution/batch/transfer.rs',
           'clear_owned_region(self.values.as_flattened_mut())', 'Ok::<(), ()>(())',
           'execution::batch::transfer::tests::transfer_clears_source_and_all_transport_capacity', 1)
    yield ('brynja-hash-parallel-std', 'src/execution/batch/worker.rs',
           'self.clear();\n        #[cfg(test)]', '// omitted clear\n        #[cfg(test)]',
           'execution::batch::worker::tests::storage_drop_clears_all_live_transport_capacity', 1)
