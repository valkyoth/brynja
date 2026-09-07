"""Negative metadata fixtures for MD5's bounded CPU-feature implication."""
import copy

def check(no_default, all_features, package, node, reject):
    for features in ([], ["batch", "cpu-evidence"]):
        altered = copy.deepcopy(all_features)
        package(altered, "brynja-legacy-md5")["features"]["cpu"] = features
        reject(altered, "all-features", "feature policy differs",
               "MD5 CPU lost batch or enabled evidence transitively")
    altered = copy.deepcopy(no_default)
    node(altered, "brynja-legacy-md5")["features"].append("cpu-evidence")
    reject(altered, "no-default-features", "feature set drifted",
           "host adapter resolution silently enabled MD5 evidence")
