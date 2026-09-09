"""Reject implicit, missing or cross-boundary workspace feature contracts."""
import copy


def check(baseline, package, reject):
    for features in (
        {"default": ["static-execution"], "static-execution": []},
        {"default": [], "static-execution": [], "automatic-execution": []},
    ):
        changed = copy.deepcopy(baseline)
        package(changed, "brynja-crypto-cpu")["features"] = features
        reject(changed, "all-features", "feature policy differs",
               "implicit or unregistered CPU execution feature")
    for name, key, value, label in (
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
