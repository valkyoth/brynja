"""Reject implicit, missing or cross-boundary workspace feature contracts."""
import copy
import macos_workspace_policy
import facade_workspace_policy


def check(baseline, package, reject):
    facade_workspace_policy.regressions(baseline, package, reject)
    macos_workspace_policy.regressions(baseline, package, reject)
    for features in (
        {"default": ["static-execution"], "static-execution": []},
        {"default": [], "static-execution": [], "automatic-execution": []},
    ):
        changed = copy.deepcopy(baseline)
        package(changed, "brynja-crypto-cpu")["features"] = features
        reject(changed, "all-features", "feature policy differs",
               "implicit or unregistered CPU execution feature")
    for name, key, value, label in (
        ("brynja", "aes-gcm", [], "missing portable GCM forwarding"),
        ("brynja-crypto", "aes-gcm", ["hazmat-ghash"], "raw GHASH enabled by portable GCM"),
        ("brynja-crypto", "aes-gcm", ["cpu"], "CPU support enabled by portable GCM"),
        ("brynja-crypto-cpu", "default", ["ghash-runtime-execution"], "default-on GHASH CPU kernel"),
        ("brynja-crypto-cpu", "ghash-runtime-execution", None, "missing GHASH CPU kernel feature"),
        ("brynja-crypto", "ghash-runtime-execution",
         ["hazmat-ghash", "cpu", "brynja-crypto-cpu/ghash-runtime-execution"],
         "unrelated CPU API enabled by GHASH"),
        ("brynja", "ghash-runtime-execution", ["brynja-crypto/ghash-runtime-execution"],
         "missing facade GHASH opt-in"),
        ("brynja", "legacy-ssl2", ["dep:brynja-legacy-ssl2"], "legacy feature smuggling"),
        ("brynja", "default", ["dtls"], "non-empty default feature"),
        ("brynja-mac-kmac", "conformance-testing", None, "missing conformance gate"),
    ):
        changed = copy.deepcopy(baseline)
        features = package(changed, name)["features"]
        if value is None:
            del features[key]
        else:
            features[key] = value
        reject(changed, "all-features", "feature policy differs", label)
