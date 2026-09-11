# TupleHash accelerated operations

Status: v0.24.39 implemented; focused development verification, owner-supplied
retest and three-platform native collection passed. Final release gates pending.
This is not independent cryptographic verification or FIPS validation.

The default-off `brynja_hash_tuple::execution` module implements TupleHash128,
TupleHash256, TupleHashXOF128 and TupleHashXOF256 over portable or explicitly
authorized hardened cSHAKE. Existing portable APIs and facade defaults are
unchanged. No new unsafe Rust or external dependency is introduced.

Enable `hardened-execution` on the leaf for portable/static execution;
`runtime-execution` additionally forwards hosted support. Both are default-off.
The leaf remains allocation-free and `no_std`. Hosted OS detection belongs in
the optional separate `brynja-crypto-cpu-std` crate, not the portable leaf.

## Working public-data example

```rust
use brynja_hash_tuple::{execution::{Mode, TupleHash128}, TupleHashError};

fn main() -> Result<(), TupleHashError> {
    let mut tuple = TupleHash128::new(Mode::Portable, b"record fields")?;
    tuple.push_item(b"header")?;
    let mut item = tuple.begin_item(48)?;
    item.update(b"pay")?;
    item.update(b"load")?;
    item.finish()?;
    let mut digest = [0_u8; 32];
    tuple.finalize(&mut digest)?;
    Ok(())
}
```

For acceleration supply `Mode::Require(Some(KeccakSession))` or
`Mode::Prefer(Some(KeccakSession))`. Create that session from a supported
static authority or a supported hosted authority. It borrows the exact owner
and health generation; no callback, copied report or feature mask grants
authority. Prefer falls back only when no session was supplied. A supplied
session failing startup or becoming quarantined always returns an error.

x86 AVX2 execution requires a correctly target-specialized binary and a platform
that preserves the complete feature bundle while it runs. Current-core flags
alone do not authorize generic hosted x86 migration. Supported Linux AArch64
and Apple AArch64 hosted selection uses the established system-wide feature
contract. No new CPU admission or platform guarantee is created here.

## Owner and output choices

| Profile | Fixed owner | XOF owner and reader | Output |
| --- | --- | --- | --- |
| Public/unkeyed | `TupleHash128/256` | `TupleHashXof128/256`, `Reader` | Public bytes or canonical bits |
| Secret-bearing | `HardenedTupleHash128/256` | `HardenedTupleHashXof128/256`, `HardenedReader` | Typed secret output, or explicit public declassification |

Both internally own hardened sponge state. Only the hardened types implement
the sealed `HardenedState` capability. Ordinary types are for public/unkeyed
tuples and must not be substituted into a secret-bearing construction.
All owners, writers and readers are non-Copy, non-Clone, non-Debug, non-Send
and non-Sync. Fixed finalizers consume their owner exactly once.

Customization and items support bytes and canonical FIPS 202 bit strings:
low bits are meaningful in a partial final byte; unused high bits must be zero.
An exact-length item writer accepts irregular byte/bit fragments totaling
exactly its declared length. The empty tuple and a tuple containing an empty
item differ. Item boundaries and ordering are cryptographically significant.
Fixed output uses `right_encode(L)`; XOF output uses `right_encode(0)`.

The XOF reader exclusively borrows its original owner. It supports incremental
whole-byte output and a consuming partial-bit final output. Mixed secret/public
reads require explicit declassification for every public release.

Convenience public output methods use 168 bytes of owned clearing scratch.
Larger outputs use the explicit scratch APIs; scratch must cover the entire
destination. Scratch is erased in full, including unused capacity, on success,
failure and recoverable unwind. Public errors preserve the destination.
Secret errors clear the complete destination, including malformed output widths.
Successful secret output is affine and erases its borrowed destination on Drop;
`expose()` borrows it without turning it into an ordinary digest.

## Failure and cleanup boundary

An incomplete, overlong, abandoned or failed item closes the parent. Dropping
an unfinished writer clears it. Forgetting a writer cannot make the parent
accept another item or finalize; forgetting the entire owner can suppress Drop.
Dropping an XOF reader cancels and clears the exact source. A forgotten reader
cannot reopen absorption. Backend loss mid-item or mid-output is terminal and
never silently changes to another backend.

The source owns and erases its hardened sponge and eight metadata regions:
pending byte, used-bit count, item count, remaining item bits, absorbed input
count, output count, phase and bounded 168-byte packing scratch. SP 800-185
integer encodings use the existing clearing owner. Operation guards clear on
errors and recoverable unwinding; fixed helpers borrow rather than move out
the source. Misaligned large fragments remain bulk-absorbed through bounded
owned staging.

Only owned memory cleared during continuing execution is covered. This does
not guarantee erasure of registers, compiler-created copies, stack spills,
caches, swap, dumps, DMA-visible memory, process abort or forced termination.
Callers remain responsible for their original inputs and copied outputs.
Owners are movable, not pinned/locked allocations. Non-Send does not prevent
the operating system from migrating a thread.

## Verification and release

The new execution fixture exercises all profiles against official NIST examples
and an independent arbitrary-bit oracle, including exact item partitions,
mixed XOF output, destination clearing and authority revocation mid-item.
Ownership negatives, compiled mutants and emitted cleanup checks are separate
from native qualification.

Run the focused development campaign:

```sh
cargo test -p brynja-hash-tuple --features hardened-execution
python3 scripts/tuplehash/check-tuplehash-execution.py
```

Native execution is explicit: `--native-x86` or `--native-arm`.
`--qemu` provides emulated Arm testing only. Fresh Linux x86-64, Linux Arm64
and Apple Arm64 TupleHash evidence must be collected after a clean pentest;
old KMAC/cSHAKE evidence does not qualify these new tuple ownership paths.

The reviewed collection at `11e632ceeed37d54844e1cbcb42b5f13688f3f72`
is registered in [the native index](../security/tuplehash-execution-native.json).
Intel Xeon Platinum 8488C passed four execution modes; AWS Neoverse-V1 and
Apple M2 Pro passed five, including hosted execution. Each mode checked 268
official/independent cases, and each platform passed four kernel lifecycle tests
and 1,024 actual accelerated permutations under Rust 1.98.1. These are
project-owned functional observations, not side-channel, migration-safety,
register/spill-erasure or independent certification evidence.
