"""Complete retained verifier CFG with explicit, separately checked leaf contracts."""
import re

import debug_verifier_destructors as destruction
import debug_verifier_comparison as bulk
import debug_verifier_final_comparison as final

model, guard, comparison, require = destruction.model, destruction.guard, destruction.comparison, destruction.require


def closure(function, definitions, names, text):
    root = re.search(comparison.SYMBOL, function.splitlines()[0])[1]
    definitions = {**definitions, root: function}
    finish_root, roles, constants, _, transfer = destruction.finish.closure(function, definitions, names, text)
    boundaries = {symbol: role for role, symbol in roles.items() if role in ('none', 'key', 'ne', 'suffix')}
    _, _, bulk_roles, _, _ = bulk.extract(function, definitions)
    _, _, final_roles, _, _ = final.extract(function, definitions)
    for source in (bulk_roles, final_roles):
        for role, symbol in source.items():
            if role not in ('branch', 'first_branch', 'option', 'error'):
                boundaries[symbol] = 'output_drop' if role == 'drop' else role
    boundaries[names['CLEAR']] = 'clear'
    functions, pending = {}, [root]
    while pending:
        name = pending.pop()
        if name in functions or name.startswith('llvm.') or '16panic_in_cleanup' in name:
            continue
        role = boundaries.get(name)
        if role is None:
            tokens = (('bulk', 'Reader', '6secret'), ('final', 'Reader', '12final_secret'),
                      ('get_mut', 'slice', '7get_mut'), ('get', 'slice', '3get'),
                      ('last', 'slice', '4last'), ('chunks', 'slice', '6chunks'),
                      ('next_chunks', 'Chunks', '4next'), ('predicate', 'secret_memory', '25secret_difference_is_zero'),
                      ('output_zeroize', 'secret_memory_volatile', '23zeroize_region_volatile'))
            matches = [role for role, *parts in tokens if all(part in name for part in parts)]
            require(len(matches) <= 1, 'unambiguous whole-verifier boundary')
            role = matches[0] if matches else None
            if role:
                boundaries[name] = role
        if role:
            if name in definitions:
                require(not re.search(r'\b(?:byval|inalloca)\b', definitions[name]), 'borrowed leaf contract ABI')
            else:
                require(role in ('first', 'last'), 'only external first/last slice contracts')
            if role != 'output_drop':
                continue
        require(name in definitions, 'same-row whole-verifier callee: ' + name)
        body = definitions[name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed interpreted helper ABI')
        functions[name] = model.parameters(body), model.blocks(body)
        for lines in model.blocks(body).values():
            for line in lines:
                if 'call ' in line or 'invoke ' in line:
                    pending.append(guard.call(line)[0])
    require(finish_root in functions and roles['core_drop'] in functions and roles['state_drop'] in functions,
            'actual finish and original destructor chains execute')
    return root, functions, boundaries, constants, transfer[0] == 32
