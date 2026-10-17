"""Compiled strict worker/quarantine mutants, changing extracted archives only."""
import strict_accelerated_sources as sources
from legacy_execution_package import require


def mutations(route):
    result = []
    for family in sources.FAMILIES[route]:
        base = f'strict_{family}/'
        test = family + '_lifecycle'
        result.append((base + 'compiled.rs', 'if self.quarantined {', 'if false {', test))
        if family == 'kmac':
            before = 'self.quarantined = false;\n                cancel.check()?;'
            after = 'self.quarantined = true;\n                cancel.check()?;'
        else:
            before, after = 'self.quarantined = false;', 'self.quarantined = true;'
        result.append((base + 'compiled.rs', before, after, test))
        before = {
            'sha2': 'brynja_core::copy_secret_region(destination, secret.digest.$borrow())',
            'sha3': 'brynja_core::copy_secret_region(out, source)',
            'kmac': 'brynja_core::copy_secret_region(out, source)',
            'tuplehash': 'brynja_core::copy_secret_region(out, input)',
        }[family]
        oracle = 'keyed_oracles' if family in ('kmac', 'tuplehash') else 'hash_oracles'
        result.append((base + 'compiled/worker.rs', before, 'brynja_core::copy_secret_region(&mut [], &[])', oracle))
        before = {'sha2': 'state.update(part)', 'sha3': '$state.update(part)',
                  'kmac': '$state.update(part)', 'tuplehash': 'writer.update(part)'}[family]
        # Reuse checks can compare two identically broken calls. Absorption
        # mutations must run against independent expected bytes instead.
        result.append((base + 'compiled/worker.rs', before, before.replace('(part)', '(&[])'), oracle))
        if family == 'sha2':
            before = 'let execution = api::Execution::from_static(&owner).map_err(convert)?;\n    let mut scratch'
            after = 'let execution = api::Execution::portable();\n    let mut scratch'
            result.append((base + 'compiled/worker.rs', before, after, oracle))
    return result


def rejection(result, test, population):
    require(result.returncode == 101 and f'test {test} ... FAILED' in result.stdout
            and f'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; {population-1} filtered out;' in result.stdout
            and 'panicked at' in result.stdout + result.stderr,
            'strict accelerated mutation unrelated failure')


def run(api, consumer, roots, cargo, env, route):
    population = 5 if route == 'keccak' else 3
    for name, before, after, test in mutations(route):
        path = roots['brynja-crypto-cpu-std'] / 'src' / name
        original = path.read_text()
        require(original.count(before) == 1, 'strict accelerated mutation anchor: ' + name)
        try:
            path.write_text(original.replace(before, after))
            for profile in ([], ['--release']):
                command = cargo + ['test', '--locked', '--offline', *profile, '--test', 'acceptance']
                api.run(command + ['--no-run'], consumer, env)
                result = api.run(command + [test, '--', '--exact', '--nocapture'], consumer, env, success=False)
                rejection(result, test, population)
        finally:
            path.write_text(original)
    print(f'PASS: strict compiled {route}; {len(mutations(route))*2} worker/quarantine mutation runs rejected', flush=True)
