"""Dated upstream identity verification and explicit nightly-update policy."""
import tomllib
import urllib.request


def check(policy: dict, *, require_latest_nightly: bool = False) -> None:
    import assurance_policy as assurance
    nightly_tools = [tool for tool in policy['tools']
                     if tool['source_kind'] in {'rust-toolchain', 'rustup-component'}]
    if not nightly_tools:
        return
    pinned = {tool['version'] for tool in nightly_tools}
    if len(pinned) != 1:
        assurance.fail('nightly verifier pins must share one frozen toolchain')
    version = next(iter(pinned))
    if assurance.NIGHTLY.fullmatch(version) is None:
        assurance.fail('invalid frozen nightly date')

    def manifest(url):
        with urllib.request.urlopen(url, timeout=assurance.SUBPROCESS_TIMEOUT_SECONDS) as response:
            raw = response.read(assurance.MAXIMUM_NIGHTLY_MANIFEST_BYTES + 1)
        if len(raw) > assurance.MAXIMUM_NIGHTLY_MANIFEST_BYTES:
            assurance.fail('official Rust nightly manifest exceeds the bounded input limit')
        return tomllib.loads(raw.decode('utf-8'))

    # Reproducibility and upstream identity remain mandatory. A new nightly
    # does not retroactively invalidate a completed release qualification run.
    dated = manifest('https://static.rust-lang.org/dist/' + version[8:] +
                     '/channel-rust-nightly.toml')
    target = dated['pkg']['miri-preview']['target'].get('x86_64-unknown-linux-gnu')
    if not target or target.get('available') is not True:
        assurance.fail('frozen nightly does not provide Miri for the evidence host')
    for tool in nightly_tools:
        if (version != 'nightly-' + dated['date'] or
                tool['revision'] != dated['pkg']['rust']['git_commit_hash'] or
                tool['execution_toolchain'] != version):
            assurance.fail('frozen nightly upstream identity drifted')
    latest = manifest('https://static.rust-lang.org/dist/channel-rust-nightly.toml')
    latest_version = 'nightly-' + latest['date']
    if assurance.NIGHTLY.fullmatch(latest_version) is None or latest_version < version:
        assurance.fail('latest nightly manifest is invalid or older than the frozen pin')
    if latest_version == version:
        if latest['pkg']['rust']['git_commit_hash'] != dated['pkg']['rust']['git_commit_hash']:
            assurance.fail('latest and dated nightly identities disagree')
    elif require_latest_nightly:
        assurance.fail(f'nightly update required: pinned {version}, latest {latest_version}')
    else:
        print(f'Nightly update available: {latest_version}; release evidence retains '
              f'verified frozen pin {version}. Review/update before the next qualification cycle.')
