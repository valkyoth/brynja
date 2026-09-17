# Native hardware available for future qualification

Observed on 2026-09-17 while preparing v0.24.48. These are measurements of the
launched hosts, not a guarantee about every instance with the same family name.
The owner can supply larger instances when a test needs more cores or memory.
Re-probe every replacement host; do not infer an instruction set from its name.
Ephemeral addresses and SSH credentials are intentionally not recorded here.

| Available family | Observed processor and topology | Useful exposed capabilities |
| --- | --- | --- |
| AWS c8i.large | Intel Xeon 6975P-C; 2 vCPUs sharing 1 exposed physical core (SMT) | AVX2, SHA-NI, AES-NI, PCLMULQDQ, AVX-512 F/DQ/BW/VL/IFMA, VAES, VPCLMULQDQ, GFNI, ADX/BMI2 |
| AWS c8g.large | Graviton4 / Arm Neoverse-V2 r0p1; 2 cores, no SMT | NEON, AES, PMULL, SHA-1, SHA-256, SHA-512, SHA-3, SVE/SVE2, SVE AES/PMULL/SHA-3/bit-permute |

Both launches had approximately 3.7 GiB usable memory, no swap, a 96 GiB root
filesystem, and Linux 7.0.0-1006-aws. These sizes are sufficient to attempt the
current native correctness collection. Watch memory and elapsed time rather than
assuming that every future assurance campaign will fit.

## Intel: next-version boundary

The c8i host does **not** expose the dedicated x86 SHA512 instruction feature.
CPUID leaf 7, subleaf 1, EAX bit 0 was zero on both accessible logical CPUs.
AVX-512 support is a different capability and must never substitute for that bit.
Thus the v0.24.49 dedicated x86 SHA-512 work still needs emulation or a different
native processor with that feature. This host can exercise native unsupported-
feature rejection/fallback and the existing AVX2 implementations.

Raw observations, identical on both logical CPUs:

- CPUID(7,0): EAX `0x2`, EBX `0xf1bf27eb`, ECX `0x1b407f7e`, EDX `0xbfc04400`.
- CPUID(7,1): EAX `0x201c30`, EBX `0`, ECX `0`, EDX `0x84000`.
- XCR0 `0x602e7`: the operating system enables YMM and AVX-512 state.
- Dedicated SM3 and SM4 feature bits are also absent.

These were read with a CPUID/XGETBV diagnostic pinned in turn to each accessible
logical CPU, restoring affinity afterward. No unsupported hash instruction was
executed. The feature definition is in Intel's
[instruction-set manuals](https://cdrdv2-public.intel.com/874240/325462-090-sdm-vol-1-2abcd-3abcd-4.pdf),
CPUID leaf 07H, subleaf 01H, EAX bit 0.

Future AVX-512, VAES/VPCLMULQDQ, GFNI and IFMA implementations can potentially
receive native testing here once implemented with their own complete feature
checks. This observation neither implements nor admits any such backend.

## Arm: additional coverage

The OS reported HWCAP `0xeff3ffff` and HWCAP2 `0x3f3bf`; both CPUs advertised the
features above. `PR_SVE_GET_VL` returned 16 bytes: the observed SVE vector length
is **128 bits**, not an assumed 256/512-bit width. SVE2 enables new implementation
options, but its presence does not establish a speed advantage over NEON.
Existing NEON and dedicated Arm hash paths can be tested natively on this host.

## When to request a larger host

For v0.24.48 correctness, keep these machines unless collection shows resource
pressure. The four-worker timing rows oversubscribe both hosts; Intel's two
vCPUs are not two physical cores. Preserve those results as measured and do not
present them as four-core scaling evidence.

For scaling qualification, request at least four exposed physical cores (ideally
eight for a broader worker sweep), verify topology after launch, and use an idle
host with adequate memory. Increasing the c8i instance size must not be assumed
to add the missing SHA512 instruction feature. Ask for a different qualified
CPU, not merely more vCPUs, when that instruction is the requirement.

Cloud CPU enumeration is not a live-migration guarantee, hostile-host
attestation, independent review, side-channel proof or FIPS validation. Retain
the existing deployment-authority contract and default-off acceleration policy.
This inventory changes no release gate.
