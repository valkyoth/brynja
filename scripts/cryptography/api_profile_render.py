"""Render the API/owner inventory without turning registration into approval."""


def render_coverage(register: dict) -> bytes:
    profiles: dict[str, int] = {}
    dispositions: dict[str, int] = {}
    for capability in register["capabilities"]:
        profiles[capability["profile"]] = profiles.get(capability["profile"], 0) + 1
        dispositions[capability["disposition"]] = dispositions.get(capability["disposition"], 0) + 1
    lines = [
        "# Cryptographic API Profile And Secret-State Register", "",
        "Generated from the reviewed policy and semantic standards surfaces. Do not edit by hand.", "",
        f"- Capabilities: **{len(register['capabilities'])}**",
        f"- API dimensions per capability: **{len(register['api_dimensions'])}**",
        f"- Current secret owners: **{len(register['current_secret_owners'])}**",
        f"- Registered capability owners: **{len(register['registered_secret_owners'])}**",
        f"- Planned secret owners: **{len(register['planned_secret_owners'])}**", "",
        "## Profile Coverage", "", "| Profile | Capabilities |", "| --- | ---: |",
    ]
    lines.extend(f"| `{name}` | {count} |" for name, count in sorted(profiles.items()))
    lines.extend(["", "## Implementation Dispositions", "", "| Disposition | Capabilities |", "| --- | ---: |"])
    lines.extend(f"| `{name}` | {count} |" for name, count in sorted(dispositions.items()))
    lines.extend([
        "", "Every capability classifies every API dimension and binds an owner milestone.",
        "Secret owners enumerate fields, temporaries, lifecycle edges, cleanup contracts,",
        "output handling, evidence, and residual risks. Ordinary state never implies hardened",
        "ownership. The optional sanitization adapter cannot replace mandatory core cleanup or",
        "enter the FIPS graph. HMAC registers transitive inner/outer hash ownership and",
        "consuming handoffs, not an invented Engine destructor. Its existing emitted-code",
        "checks remain separate from the direct-destructor MIR checks. Registration is",
        "not native release qualification, independent review or whole-frame erasure.", "",
        "## Explicit Compatibility Profiles", "",
        "These profiles are separate owners of an existing capability, not modern",
        "algorithm admission or an extension of the strict facade. Compiler-driver",
        "registration is not an execution receipt or independent qualification.", "",
        "| Capability | Profile | Route | Storage | Qualification |",
        "| --- | --- | --- | --- | --- |",
    ])
    for owner in register["registered_secret_owners"]:
        for profile in owner.get("compatibility_profiles", []):
            for route in profile["routes"]:
                lines.append(f"| `{owner['capability']}` | `{profile['id']}` | `{route['id']}` | "
                             f"{route['storage']} | {profile['qualification']} |")
    lines.append("")
    return "\n".join(lines).encode()
