# Windows enclave image admission and consumer workflow

This admission component now also backs the crate's bounded
[`brynja_strict::enclave` owner/session API](windows-enclave-owner.md). The separate
build/loader demonstration still accepts public test data only. Existing
Linux-style host-slice constructors remain Unsupported on Windows. Development
execution is tested; production-signed qualification remains pending.
See [deployment responsibilities](windows-enclave-deployment.md).

## Trust comes from the application build, not the candidate DLL

The application publisher reviews the enclave source/build and the final signed
artifact. A separate deployment policy records the complete signed-file SHA-256,
family/image IDs, image/security versions, non-debug policy, resource geometry
and imported-library minimum security versions. The publisher keeps that policy
under its own trusted build/release control. It is **not** an adjacent JSON file
automatically accepted from whoever supplies a DLL.

The build tool requires exact schema and an explicit profile, checks the reviewed
policy against the artifact, and compiles numeric policy values into the host's
Rust adapter. The runtime has no API to replace that policy or downgrade its
profile. The `OWNER_REVIEWED` field is bookkeeping, not a digital signature or
proof that someone reviewed the file. Protecting the policy, host executable and
their updates is part of the application's deployment trust chain.

`inspect` deliberately emits `UNTRUSTED_INSPECTION`. Copying its output and
changing that label without reviewing source, build provenance and the expected
identity is not an approval procedure. The source commit in a policy is an audit
reference; the complete artifact hash is the runtime byte binding. It is not a
claim that this hash is the platform's distinct enclave UniqueId.

## Admission order

1. Open and hold the main file and its ancestor directory handles using the
   checked file guard. Reject unsupported paths, reparse handles and conflicting
   access. Read a bounded complete public artifact, not executable code.
2. Match its entire signed-file hash to the compiled policy. Parse the file
   without executing it; compare identity/configuration and validate imports.
3. In the **production build**, require successful Windows Authenticode trust
   verification with revocation checking. Nonzero status, including unavailable
   trust/revocation information, rejects. The held file handle is supplied to
   verification. Verification state is closed before proceeding.
4. Create the enclave, load it with `LoadEnclaveImageW`, then require successful
   `InitializeEnclave`. Loading alone is insufficient: our native wrong-author
   and impossible-security-version controls loaded but failed initialization.
   Host Authenticode checking is not a substitute for the complete Windows
   enclave loading/initialization boundary.
5. Only after successful admission, loading and initialization may application
   enclave calls occur.
   Keep file/ancestor handles until confirmed enclave destruction. Uncertain
   cleanup aborts the diagnostic process rather than reporting clean release;
   fatal abort is not proof of secret erasure.

The development build is selected separately at compile time. It records the
Authenticode result but permits the known development-signed artifact to reach
the enclave loader. The production build contains no runtime fallback to that
behavior. The native campaign deliberately uses an untrusted test certificate
to verify production rejection, not to establish production success.

## Imported-library contract

This bounded x86-64 contract supports exactly `ucrtbase_enclave.dll` and
`vertdll.dll`. Both the normal PE import descriptors and enclave import-identity
records must contain those two distinct, canonical names and agree one-to-one.
Named import thunks must be bounded and terminated; ordinal imports, delayed or
bound imports, TLS initialization and CLR images are rejected. Duplicate or
overlapping section mappings and malformed/out-of-file RVAs reject.

Each enclave import must use `IMAGE_ENCLAVE_IMPORT_MATCH_AUTHOR_ID` with the
all-zero author identity and zero unused/reserved identity fields. Microsoft
defines that author rule to require a component of the Windows installation.
Image-ID matching alone is rejected: a GUID is not publisher authorization.
Minimum security versions must match the trusted policy; zero explicitly leaves
the SDK's version floor disabled and does not establish patch currency.
[Microsoft import identity contract](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_enclave_import).

The signed main image binds those import requirements; the Windows enclave loader
enforces them. Windows system libraries and their servicing remain part of the
OS trust boundary, not third-party Brynja cryptographic dependencies. Their exact
bytes are not frozen by the main-image hash. Arbitrary consumer/plugin imports
are not supported by this contract. Adding them requires a reviewed identity and
dependency policy, not a relaxed name filter.

## Consumer build, sign and load sequence

Use an appropriately configured Windows SDK/MSVC enclave build environment and
the reviewed enclave source. No signing credentials are stored in this repository.
The application publisher chooses/provisions its production signing account;
Brynja does not purchase or operate one on the publisher's behalf.

1. Build the enclave image using the reviewed source and enclave SDK libraries.
   Keep compiler/linker versions, source hashes and logs. The current retained
   SHA-256 fixture build is provided by
   `scripts/cryptography/windows_enclave_retained_cross_build.py`; it remains
   research code, not the future full-algorithm production enclave.
2. Run the SDK's **VEIID before the import transform**. In our tested SDK, VEIID
   regenerates image-ID import records; running it later would undo the stronger
   author rule and the final inspection would reject.
3. Apply the bounded transform to a new file:

   ```sh
   python3 scripts/cryptography/windows_enclave_admission.py prepare-system-imports linked-after-veiid.dll enclave-unsigned.dll
   ```

   This changes import identity requirements, clears the PE checksum and removes
   any previous certificate. It never loads or authorizes the image and refuses
   to overwrite an existing destination. Every transformed artifact needs signing.
4. Sign `enclave-unsigned.dll` using the publisher's selected **VBS enclave**
   signing route, producing the final artifact. For development, Microsoft
   documents test certificates and a test-configured host. For production, use
   the documented enclave certificate profile—not an ordinary code-signing
   certificate assumed to be interchangeable. Retain tool output and investigate
   warnings; do not change image bytes or rerun VEIID after signing.
   [Microsoft build/signing guide](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves-dev-guide).
5. Inspect the final file using the same parser that will be compiled into the
   loader:

   ```sh
   python3 scripts/cryptography/windows_enclave_admission.py inspect enclave-signed.dll
   ```

   Separately review that report against the intended source/build and identity.
   The trusted JSON has exactly the inspection fields plus `schema: 1`,
   `profile: "production"`, a nonempty `reviewer`, and the 40-character reviewed
   `source_commit`; only after that review is `status` set to `OWNER_REVIEWED`.
   Arrays remain numeric byte arrays; `minimum_import_security` has two integers
   in ucrtbase_enclave/vertdll order. Do not treat this step as trust-on-first-use.
6. Build the policy-bound adapter into a new output directory:

   ```sh
   python3 scripts/cryptography/windows_enclave_admission.py build enclave-signed.dll reviewed-policy.json admission-build --profile production
   ```

   The current build helper uses Rust 1.98.1 and cross-builds the x86-64 MSVC
   static library. In a configured x64 MSVC developer prompt, run the generated
   `admission-build\link.cmd`. The resulting `admission.exe` is the isolated
   **public-probe loader**, not a secret-processing product executable. It accepts
   one absolute main-image path; its compiled policy/profile cannot be supplied
   by command-line arguments. Output records the exact stage and trust status.
7. Deploy only the intended host/image pair through the application's trusted
   update channel, test the actual production configuration, and treat any
   admission failure as fatal to that operation. Do not retry through development
   or ordinary-memory APIs. Re-signing or updating the image changes its full-file
   hash and requires a reviewed policy/host rebuild. OS servicing can also require
   requalification of the platform assumptions.

For explicit development testing, both the reviewed policy and `--profile` must
say `development`. Renaming a JSON profile cannot downgrade a compiled production
loader. Production credentials, production signing success and production-host
qualification have **not** been obtained by these development experiments.

## Boundaries still outside this component

This is local trusted-build/image admission, not remote attestation or protection
against a hostile kernel/hypervisor. Authenticode's certificate-chain checks and
Windows' enclave signature checks are platform trust services, not a claim of
first-party cryptographic implementation of those platform services.
[WinVerifyTrust result rules](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust),
[enclave loading](https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-loadenclaveimagew).

The current accepted identity geometry is deliberately narrow: PE64 x86-64,
non-debug, one thread, 256 MiB enclave reservation, two Windows imports. It does
not silently generalize to Windows AArch64, other algorithms, workers or a
consumer's changed image. Production facade integration, broader functionality,
independent retest and final qualification remain in
[the version's remaining work](windows-v02450-remaining.md). Release gates are
unchanged.
