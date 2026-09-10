"""Compiled entry probes distinguish actual kernel work from scalar substitution."""


def exercise(consumer, roots, env, command, run, *, hosted, wide):
    cpu = roots['brynja-crypto-cpu'] / 'src'
    # Startup uses abc. Poison a different block only after that real KAT can
    # succeed. The fixed NIST corpus begins with the empty-message padding.
    relative = 'runtime_execution/operations.rs' if hosted else 'static_execution/operations.rs'
    operations = cpu / relative
    original = operations.read_text()
    function = 'sha512' if wide else 'sha256'
    needle = f'pub(super) fn {function}('
    begin = original.index(needle)
    opening = original.index('{', begin)
    poison = f'\n    if block != &crate::{function}::abc_block() {{ state.fill(0); return Ok(()); }}\n'
    route = roots['brynja-hash-sha2'] / 'src/execution/route.rs'
    route_original = route.read_text()
    branch = 'Inner::Runtime(session)' if hosted else 'Inner::Static(session)'
    call = f'session.compress_{function}(PublicData::new(state), PublicData::new(block))?'
    start = route_original.index(branch, route_original.index('fn compress64' if wide else 'fn compress32'))
    call_start = route_original.index(call, start)
    portable = 'crate::compress64::compress(state, block)' if wide else 'crate::compress::compress(state, block)'
    try:
        operations.write_text(original[:opening + 1] + poison + original[opening + 1:])
        result = run(command, consumer, env, success=False)
        if 'acceptance failed:' not in result.stderr:
            raise ValueError('kernel poison did not cause an algorithm mismatch')
        # This compiling scalar-substitution mutant bypasses the poisoned
        # kernel while falsely retaining an accelerated route report. Require
        # its success here to demonstrate that the entry-failure gate detects
        # precisely that loss, rather than an unrelated compile error.
        route.write_text(route_original[:call_start] + portable + route_original[call_start + len(call):])
        result = run(command, consumer, env)
        if 'named=240; general=4590' not in result.stdout:
            raise ValueError('scalar substitution control lost vector coverage')
    finally:
        operations.write_text(original)
        route.write_text(route_original)
    print(f'Compiled {"hosted" if hosted else "static"} {function} entry-loss/scalar-substitution probe: PASS')
