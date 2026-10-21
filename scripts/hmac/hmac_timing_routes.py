"""Exact timing route admission; generic feature probing before accelerated builds."""
import platform
import sys

import hmac_timing as timing
import hmac_verifiers as verifier
from hmac_adapter_native import FEATURES


def prepare(route, family, directory, env):
    timing.population(route, family)
    arch = {"arm64": "aarch64"}.get(platform.machine(), platform.machine())
    if route.startswith("linux-") and (sys.platform != "linux" or arch not in FEATURES):
        raise ValueError("Linux timing route requires native supported Linux")
    if route.startswith("macos-") and (sys.platform != "darwin" or arch != "aarch64"):
        raise ValueError("resident timing route requires native Apple Silicon")
    if route == "runtime" and (arch != "aarch64" or sys.platform not in ("linux", "darwin")):
        raise ValueError("runtime timing route requires admitted native Arm platform")
    if route not in timing.ACCELERATED:
        return dict(env), None
    if arch not in FEATURES:
        raise ValueError("unsupported accelerated timing architecture")
    probe = directory / "generic-host-probe"
    source = verifier.ROOT / "assurance/hmac-faults/host_probe.rs"
    command = ["rustc", "+1.99.1", "--edition=2024", "-C", "target-cpu=generic",
               str(source), "-o", str(probe)]
    verifier.run(command, env)
    probe_command = [str(probe), family]
    output = verifier.run(probe_command, env)
    if output.splitlines() != ["HMAC_HOST_FEATURES: " + family]:
        raise ValueError("generic timing CPU preflight failed")
    build_env = dict(env)
    if route in timing.COMPILED:
        build_env["RUSTFLAGS"] = "-C target-feature=" + FEATURES[arch][family]
    return build_env, {"compile_command": command, "command": probe_command, "output": output}
