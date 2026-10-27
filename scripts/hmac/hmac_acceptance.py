"""Compile public boundary probes and execute mutations of actual HMAC archives."""
import json

from hmac_faults import accepted, rejected, replace_once, result

ALGORITHMS = ("Sha224", "Sha256", "Sha384", "Sha512", "Sha512_224", "Sha512_256",
              "Sha3_224", "Sha3_256", "Sha3_384", "Sha3_512", "Sha512T<129>", "Sha512T<511>")


def diagnostic_rejection(run, expected):
    codes = []
    for line in run.stdout.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("reason") == "compiler-message" and row["message"].get("level") == "error":
            codes.append((row["message"].get("code") or {}).get("code"))
    if run.returncode != 101 or not codes or set(codes) != {expected}:
        raise ValueError(f"HMAC negative did not fail with {expected}: {codes}\n" + run.stderr[-3000:])


def negative_cases():
    for algorithm in ALGORITHMS:
        for bound in ("Send", "Sync", "Copy", "Clone", "core::fmt::Debug"):
            yield (f"{algorithm}/{bound}",
                   f'fn bound<T: {bound}>() {{}} pub fn probe() {{bound::<Hmac<{algorithm}>>();}}', "E0277")
    for owner in ("Tag<'static, Sha256>", "SecretTag<'static, Sha256>"):
        for bound in ("Copy", "Clone", "core::fmt::Debug"):
            yield (f"{owner}/{bound}", f'fn bound<T: {bound}>() {{}} pub fn probe() {{bound::<{owner}>();}}', "E0277")
    yield ("sealed algorithm", 'pub struct External; impl Algorithm for External {const BLOCK_BYTES:usize=64; const TAG_BYTES:usize=32;}', "E0277")
    for method in ("reset", "clone", "check_additional_bits", "check_additional_bytes", "export_key"):
        yield (method, f'pub fn probe(mut mac: Hmac<Sha256>) {{mac.{method}();}}', "E0599")
    yield ("consumed stream", 'pub fn probe(mut mac: Hmac<Sha256>) {mac.cancel(); let _ = mac.update(b"late");}', "E0382")
    yield ("algorithm tag substitution", 'pub fn probe(tag: Tag<Sha224>) -> Tag<Sha256> {tag}', "E0308")
    yield ("secret tag substitution", 'pub fn probe(tag: SecretTag<Sha224>) -> SecretTag<Sha256> {tag}', "E0308")
    yield ("secret/public substitution", 'pub fn probe(tag: SecretTag<Sha256>) -> Tag<Sha256> {tag}', "E0308")
    yield ("secret borrow escape", 'pub fn probe(tag: SecretTag<Sha256>) -> &[u8] {tag.expose()}', "E0515")
    for owner in ("Tag", "SecretTag"):
        yield (f"{owner}/general parameter substitution",
               f'pub fn probe(tag: {owner}<Sha512T<129>>) -> {owner}<Sha512T<130>> {{tag}}', "E0308")
    for algorithm in ALGORITHMS:
        wrong = "Sha2BitString" if algorithm.startswith("Sha3_") else "Fips202BitString"
        for method in ("finalize_bits_tag", "finalize_bits_secret", "verify_bits"):
            yield (f"{algorithm}/{method}/bit-order", f'pub fn probe(mac: Hmac<{algorithm}>, output: &mut [u8]) {{'
                   f'let Ok(input) = {wrong}::new(&[], 0) else {{return}};'
                   f'let _ = mac.{method}(input, output);}}', "E0308")
    for method in ("finalize_bits_tag", "finalize_bits_secret", "verify_bits"):
        yield (f"{method}/consumed", f'pub fn probe(mut mac: Hmac<Sha256>, output: &mut [u8]) {{'
               f'let Ok(input) = Sha2BitString::new(&[], 0) else {{return}};'
               f'let _ = mac.{method}(input, output); let _ = mac.update(b"reopened");}}', "E0382")


def negatives(consumer, environment, no_std_target=None):
    source = consumer / "src/lib.rs"
    original = source.read_text()
    command = ["cargo", "check", "--offline", "--locked", "--lib", "--message-format=json"]
    prefix = '#![no_std]\n#![forbid(unsafe_code)]\nuse brynja_mac_hmac::*;\n'
    # A positive probe for EVERY admitted identity ensures negative failures
    # cannot be explained by unavailable imports, dependencies or Rust syntax.
    positive = prefix + '\n'.join(
        f'pub fn positive_{index}(key: &[u8], message: &[u8], tag: &[u8]) -> Result<(), Error> {{'
        f'let mut mac = Hmac::<{algorithm}>::new(key)?; mac.update(message)?; mac.verify(tag)}}'
        for index, algorithm in enumerate(ALGORITHMS))
    positive += '\n'.join(
        f'pub fn bits_{index}(key: &[u8], output: &mut [u8]) -> Result<(), Error> {{'
        f'let input = {"Fips202BitString" if algorithm.startswith("Sha3_") else "Sha2BitString"}'
        f'::new(&[], 0).map_err(|_| Error::SecretMemory)?;'
        f'let _ = Hmac::<{algorithm}>::authenticate_bits(key, input, output)?;'
        f'let _ = Hmac::<{algorithm}>::new(key)?.finalize_bits_secret(input, output)?;'
        f'let _ = Hmac::<{algorithm}>::new(key)?.verify_bits(input, output)?; Ok(())}}'
        for index, algorithm in enumerate(ALGORITHMS))
    try:
        source.write_text(positive)
        baseline = result(command, consumer, environment)
        if baseline.returncode:
            raise ValueError("HMAC positive API probe failed: " + baseline.stderr)
        if no_std_target:
            build = result(["cargo", "build", "--offline", "--locked", "--release",
                            "--lib", "--target", no_std_target], consumer, environment)
            if build.returncode:
                raise ValueError("HMAC extracted no_std consumer failed: " + build.stderr)
            print(f"HMAC extracted no_std consumer: {no_std_target}; {len(ALGORITHMS)} algorithm instantiations PASS")
        count = 0
        for name, code, diagnostic in negative_cases():
            source.write_text(prefix + code)
            try:
                diagnostic_rejection(result(command, consumer, environment), diagnostic)
            except ValueError as error:
                raise ValueError(name + ": " + str(error)) from error
            count += 1
    finally:
        source.write_text(original)
    print(f"HMAC packaged API/ownership negatives: {count} rejected")


def mutants(roots, consumer, environment):
    path = roots["brynja-mac-hmac"] / "src/engine.rs"
    original = path.read_text()
    cases = (
        ('mask_pad(pad, 0x36)?;', 'mask_pad(pad, 0x37)?;', "vectors", "rfc4231_case1"),
        ('mask_pad(pad, 0x36 ^ 0x5c)?;', 'mask_pad(pad, 0x36 ^ 0x5d)?;', "vectors", "rfc4231_case1"),
        ('if key.len() > A::BLOCK_BYTES {', 'if false {', "vectors", "rfc4231_case6_long_key_normalization"),
        ('A::finish_outer(self.outer, digest,', 'A::finish_outer(self.outer, &[],', "vectors", "rfc4231_case1"),
        ('digest.get(..self.tag_bytes)', 'digest.get(A::TAG_BYTES - self.tag_bytes..)', "vectors", "rfc4231_case5_explicit_truncation"),
        ('for (expected, actual) in tag.iter().zip(candidate) {',
         'for (expected, actual) in tag.iter().zip(candidate).take(1) {', "lifecycle", "sha256"),
        ('secret_difference_is_zero(&difference.0[0])', 'secret_difference_is_zero(&0)', "lifecycle", "sha256"),
        ('Some(input) => A::finish_bits(self.inner, input, destination, absorb_inner)',
         'Some(_input) => A::finish(self.inner, destination, absorb_inner)', "bits", "known_bit_answers"),
    )
    for before, after, target, test in cases:
        command = ["cargo", "test", "--offline", "--locked", "--release", "--test", target, test, "--", "--exact"]
        accepted(result(command, consumer, environment), 1)
        try:
            path.write_text(replace_once(original, before, after))
            rejected(result(command, consumer, environment))
        finally:
            path.write_text(original)
        accepted(result(command, consumer, environment), 1)
    print(f"HMAC packaged algorithm/comparison compiled mutants: {len(cases)} rejected")
    path = roots["brynja-mac-hmac"] / "src/algorithms.rs"
    original = path.read_text()
    before = "let secret = state.finalize_bits_secret(input, output).map_err($map)?;"
    after = ("let mut state = state; state.update(input.as_bytes()).map_err($map)?;"
             "let secret = state.finalize_secret(output).map_err($map)?;")
    command = ["cargo", "test", "--offline", "--locked", "--release", "--test", "bits",
               "known_bit_answers", "--", "--exact"]
    accepted(result(command, consumer, environment), 1)
    try:
        path.write_text(replace_once(original, before, after))
        rejected(result(command, consumer, environment))
    finally:
        path.write_text(original)
    accepted(result(command, consumer, environment), 1)
    print("HMAC packaged bit-rounding adapter mutant: 1 rejected")
    path = roots["brynja-mac-hmac"] / "src/general.rs"
    original = path.read_text()
    cases = (
        ("Self::finish_bits(state, input, output, consume)",
         "let mut state = state; Self::update(&mut state, input.as_bytes())?; Self::finish(state, output, consume)",
         "exact_inner_bit_answers"),
        ("if T < 128 {", "if T < 1 {", "parameter_and_truncation_policy"),
    )
    for before, after, test in cases:
        command = ["cargo", "test", "--offline", "--locked", "--release", "--test", "general", test, "--", "--exact"]
        accepted(result(command, consumer, environment), 1)
        try:
            path.write_text(replace_once(original, before, after))
            rejected(result(command, consumer, environment))
        finally:
            path.write_text(original)
        accepted(result(command, consumer, environment), 1)
    print("HMAC packaged general exact-bit/policy mutants: 2 rejected")
    tag_policy_mutants(roots, consumer, environment)


def tag_policy_mutants(roots, consumer, environment):
    path = roots["brynja-mac-hmac"] / "src/lib.rs"
    original = path.read_text()
    guard = "if !policy::valid_tag_length(A::TAG_BYTES, bytes) || bits > A::TAG_BITS {"
    cases = (
        ("A::validate()?;", "", "invalid_algorithms_precede_width_and_overflow_errors"),
        (guard, "if bits > A::TAG_BITS {", "every_named_algorithm_and_tag_width"),
        (guard, "if !policy::valid_tag_length(A::TAG_BYTES, bytes) {", "fractional_full_tags_are_not_byte_prefixes"),
        ("bytes.checked_mul(8).ok_or(Error::TagLength)?", "match bytes.checked_mul(8) { Some(bits) => bits, None => return Ok(128) }",
         "every_named_algorithm_and_tag_width"),
        ("validate_tag_policy::<A>(Some(tag_bytes))?;", "", "fractional_full_tags_are_not_byte_prefixes"),
        ("return Ok(A::TAG_BITS);", "return Ok(A::TAG_BYTES * 8);", "fractional_full_tags_are_not_byte_prefixes"),
    )
    for before, after, test in cases:
        command = ["cargo", "test", "--offline", "--locked", "--release", "--test", "tag_policy", test, "--", "--exact"]
        accepted(result(command, consumer, environment), 1)
        try:
            path.write_text(replace_once(original, before, after))
            rejected(result(command, consumer, environment))
        finally:
            path.write_text(original)
        accepted(result(command, consumer, environment), 1)
    print("HMAC packaged shared tag policy: 6 compiled caller/algorithm/width mutants rejected")
