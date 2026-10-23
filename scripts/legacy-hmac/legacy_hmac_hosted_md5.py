"""Compiled native MD5 hosted ownership, authority and cleanup regressions."""
import subprocess
from legacy_hmac_acceptance import require


def negatives():
    cases = [(f'fn bound<T:{bound}>(){{}} fn probe(){{bound::<{owner}>();}}', "E0277")
             for owner in ("Md5BatchSession", "Md5BatchOutput<'static>")
             for bound in ("Send", "Sync", "Copy", "Clone", "core::fmt::Debug")]
    cases.extend([
        ("fn probe(s:&mut Md5BatchSession,i:&[Option<Md5BatchInput>;8],c:&Cancellation)->Result<Md5BatchOutput<'static>,Error>{s.compute(i,c)}", "LIFETIME"),
        ('fn probe(s:&mut Md5BatchSession,i:&[Option<Md5BatchInput>;8],c:&Cancellation)->Result<(),Error>{let a=s.compute(i,c)?;let b=s.compute(i,c)?;let _=(a.expose(0),b.expose(0));Ok(())}', "E0499"),
        ('fn probe(l:Md5BatchLimits){let _=Md5BatchSession::new(TagPolicy::Full,l);}', "E0061"),
        ('fn probe(s:Md5BatchSession){let _=s.backend;}', "E0616"),
        ('fn probe(o:Md5BatchOutput,b:&mut[[u8;16];8]){let _=o.declassify(b);}', "E0061"),
    ])
    for origin, target in (("strict_execution", "macos_resident"), ("macos_resident", "strict_execution")):
        for owner in ("Md5BatchSession", "Md5BatchOutput<'static>"):
            cases.append((f'fn convert(s:brynja_legacy_hmac_std::{origin}::{owner})->'
                          f'brynja_legacy_hmac_std::{target}::{owner}{{s}}', "E0308"))
    return cases


def mutations(api, root, env, resident=False):
    module = "macos_resident" if resident else "strict_execution"
    feature = "macos-resident-md5-batch" if resident else "strict-md5-batch"
    boundary = "all_control_failures_preserve_or_quarantine_correctly"
    loans = "loans_admission_and_explicit_quarantine_clear_all_slots"
    matrix = "all_slot_masks_and_canonical_bits_match_portable"
    cases = [
        ("md5_compiled.rs", "self.quarantined = true;\n        let parameters", "self.quarantined = false;\n        let parameters", boundary),
        ("md5_compiled.rs", "if self.quarantined {", "if false {", loans),
        ("md5_compiled.rs", "if value.is_some() != candidates.is_some() {", "if false {", boundary),
        ("md5_compiled.rs", "self.output.clear();", "", loans),
        ("md5_compiled.rs", "self.staging.clear();", "", loans),
        ("md5_compiled/types.rs", "self.storage.clear();", "", matrix),
        ("md5_compiled/types.rs", "input.key.len() > limits.max_key_bytes", "false", loans),
        ("md5_compiled/worker.rs", "healthy(&owner)?;", "", boundary),
        ("md5_compiled/worker.rs", "report.inner.vector_blocks < parameters.backend.lane_width()", "false", boundary),
        ("md5_compiled/worker.rs", "if owner.backend() != Some(parameters.backend) {", "if false {", loans),
        ("md5_compiled/worker.rs", "Some(decision.expose_public())", "Some(true)", "every_active_tag_byte_is_compared_and_shapes_reject"),
    ]
    for name, before, after, selected in cases:
        path = root / f"src/{module}/{name}"
        original = path.read_text()
        require(before in original, "hosted MD5 mutation anchor: " + before)
        try:
            path.write_text(original.replace(before, after))
            for profile in ([], ["--release"]):
                command = ["cargo", "test", "--offline", "--features", feature, *profile, "--lib",
                           module + "::md5_compiled::tests::native::" + selected]
                api.run(command + ["--no-run"], root, env)
                api.cargo_environment.check(root, env)
                result = subprocess.run(command + ["--", "--exact"], cwd=root, env=env, capture_output=True,
                                        text=True, timeout=180, check=False)
                require(result.returncode == 101 and "test result: FAILED. 0 passed; 1 failed;" in result.stdout,
                        "hosted MD5 mutant must fail runtime: " + before + "\n" + result.stdout[-1500:] + result.stderr[-1000:])
        finally:
            path.write_text(original)
    print(f"Hosted MD5 compiled authority/cleanup mutants: {len(cases)*2} rejected", flush=True)
