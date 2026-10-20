"""Explicit test profiles; macOS residency is never Linux dump protection."""
from dataclasses import dataclass
import platform
import sys


@dataclass(frozen=True)
class Profile:
    feature: str
    module: str
    directory: str
    label: str

    def source(self, text):
        if "brynja_crypto_cpu_std::strict_hmac" not in text:
            raise ValueError("HMAC shared consumer namespace missing")
        return text.replace("brynja_crypto_cpu_std::strict_hmac",
                            "brynja_crypto_cpu_std::" + self.module)

    def require_host(self):
        system, arch = sys.platform, platform.machine()
        if self == RESIDENT:
            valid = system == "darwin" and arch == "arm64"
        else:
            valid = self == PROTECTED and system == "linux" and arch in ("x86_64", "aarch64")
        if not valid:
            raise ValueError("unsupported HMAC native owner profile/host")


PROTECTED = Profile("strict-hmac", "strict_hmac", "strict_hmac", "Protected")
RESIDENT = Profile("macos-resident-hmac", "macos_resident::hmac",
                   "macos_resident/hmac", "Mac resident (not dump-excluded)")
