"""Compiled regressions for explicit hosted SHA-1 authority and clearing."""
import subprocess
from legacy_hmac_acceptance import require


def negatives():
    cases = [(f'fn bound<T:{bound}>(){{}} fn probe(){{bound::<Sha1CompiledSession>();}}', "E0277")
             for bound in ("Send", "Sync", "Copy", "Clone", "core::fmt::Debug")]
    cases.extend([
        ("fn probe(s:&mut Sha1CompiledSession)->Result<Output<'static,Sha1>,Error>{s.authenticate(b\"k\",b\"m\")}", "LIFETIME"),
        ('fn probe(s:&mut Sha1CompiledSession)->Result<(),Error>{let a=s.authenticate(b"k",b"a")?;let b=s.authenticate(b"k",b"b")?;let _=(a.expose(),b.expose());Ok(())}', "E0499"),
        ('fn probe(l:Limits){let _=Sha1CompiledSession::new(TagPolicy::Full,l);}', "E0061"),
        ('fn probe(s:Sha1CompiledSession){let _=s.inner;}', "E0616"),
    ])
    for origin, target in (("strict_execution", "macos_resident"), ("macos_resident", "strict_execution")):
        cases.append((f'fn convert(s:brynja_legacy_hmac_std::{origin}::Sha1CompiledSession)->'
                      f'brynja_legacy_hmac_std::{target}::Sha1CompiledSession{{s}}', "E0308"))
    return cases


def mutations(api, root, env, resident=False):
    module = "macos_resident" if resident else "strict_execution"
    feature = "macos-resident-sha1-acceleration" if resident else "strict-sha1-acceleration"
    boundary = "every_hardware_boundary_clears_and_classifies_failure"
    loans = "hardware_request_rejection_output_loans_and_explicit_quarantine"
    cases = [
        ("sha1_compiled.rs", "self.quarantined = true;\n        let backend", "self.quarantined = false;\n        let backend", boundary),
        ("sha1_compiled.rs", "if self.quarantined {", "if false {", loans),
        ("sha1_compiled.rs", "if value.is_some() != verifying {", "if false {", boundary),
        ("sha1_compiled.rs", "self.inner.output.clear();", "", loans),
        ("sha1_compiled.rs", "self.inner.staging.clear();", "", loans),
        ("sha1_compiled/worker.rs", "if owner.report().backend != Some(backend) {", "if false {", boundary),
        ("sha1_compiled/worker.rs",
         "drop(\n        owner\n            .start()\n            .map_err(|_| Error::Mac(brynja_legacy_hmac::Error::ExecutionFailed))?,\n    );",
         "", boundary),
    ]
    for name, before, after, selected in cases:
        path = root / f"src/{module}/{name}"
        original = path.read_text()
        require(before in original, "compiled SHA1 mutation anchor: " + before)
        try:
            path.write_text(original.replace(before, after))
            for profile in ([], ["--release"]):
                command = ["cargo", "test", "--offline", "--features", feature, *profile, "--lib",
                           module + "::sha1_compiled::tests::native::" + selected]
                api.run(command + ["--no-run"], root, env)
                api.cargo_environment.check(root, env)
                result = subprocess.run(command + ["--", "--exact"], cwd=root, env=env, capture_output=True,
                                        text=True, timeout=180, check=False)
                require(result.returncode == 101 and "test result: FAILED. 0 passed; 1 failed;" in result.stdout,
                        "compiled SHA1 mutant must fail runtime: " + before + "\n" + result.stdout[-1500:] + result.stderr[-1000:])
        finally:
            path.write_text(original)
    print(f"Hosted SHA1 compiled authority/cleanup mutants: {len(cases)*2} rejected", flush=True)
