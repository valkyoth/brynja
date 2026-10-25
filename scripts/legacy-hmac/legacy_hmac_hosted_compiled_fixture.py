"""Private exact-path host copies for genuine compiled worker mutations."""
import shutil
import tomllib


def prepare(driver, work):
    leaf, fixture = work / 'host', work / 'fixture'
    source = driver.ROOT / 'crates/brynja-legacy-hmac-std'
    shutil.copytree(source / 'src', leaf / 'src')
    shutil.copyfile(source / 'README.md', leaf / 'README.md')
    manifest = (source / 'Cargo.toml').read_text()
    workspace = tomllib.loads((driver.ROOT / 'Cargo.toml').read_text())['workspace']
    for field in ('edition', 'rust-version', 'license', 'repository'):
        manifest = manifest.replace(field + '.workspace = true', field + ' = "' + workspace['package'][field] + '"')
    for dependency in ('brynja-core', 'brynja-crypto-cpu-std'):
        before = dependency + ('.workspace = true' if dependency == 'brynja-core' else ' = { workspace = true, optional = true }')
        manifest = manifest.replace(before, dependency + ' = { path = "' + str(driver.ROOT / 'crates' / dependency)
                                    + '", default-features = false' + (', optional = true' if dependency.endswith('-std') else '') + ' }')
    manifest = manifest.replace('path = "../', 'path = "' + str(driver.ROOT / 'crates') + '/')
    (leaf / 'Cargo.toml').write_text(manifest.replace('[lints]\nworkspace = true', '') + '\n[workspace]\n')
    shutil.copytree(driver.FIXTURE.parent / 'src', fixture / 'src')
    shutil.copyfile(driver.FIXTURE.parent / 'Cargo.lock', fixture / 'Cargo.lock')
    (fixture / 'Cargo.toml').write_text(driver.FIXTURE.read_text()
        .replace('../../crates/brynja-legacy-hmac-std', str(leaf))
        .replace('../../crates/', str(driver.ROOT / 'crates') + '/'))
    return leaf, fixture
