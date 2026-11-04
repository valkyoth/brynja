"""Partial AES-family owner inventory; registration is not qualification."""
import re
import tomllib

import rust_source_contract as rust

ID = 'development.algorithm.aes128'
SOURCE = 'crates/brynja-crypto/src/aes.rs'
PORTABLE = 'crates/brynja-crypto/src/aes/portable.rs'
RECORD = {
    'capability': 'algorithm.aes',
    'variant': 'AES-128',
    'milestone': '0.27.0',
    'key_bytes': 16,
    'block_bytes': 16,
    'rounds': 10,
    'symbol': SOURCE + '#Aes128Key',
    'output_symbol': SOURCE + '#SecretBlock',
    'fields': ['region:caller-backed-owned-secret-region', 'local:thread-local-marker'],
    'temporaries': ['schedule:Scratch<176>', 'state:Scratch<16>', 'word:Scratch<4>',
                    'previous:Scratch<16>', 'scalar-and-caller-copies:outside-owned-storage'],
    'cleanup_model': 'delegated-owner-drop-and-explicit-clear-with-operation-local-guards',
    'delegated_owners': ['core.owned-secret-region', 'core.secret-region-initialization'],
    'cleanup_bindings': [SOURCE + '#Aes128Key::clear', SOURCE + '#SecretBlock::clear',
                         SOURCE + '#Scratch::drop'],
    'compiler_checks': ['python3 scripts/aes/check-aes-owner-cleanup.py',
                        'python3 scripts/aes/check-aes-operation-cleanup.py'],
    'compiler_scope': 'bounded-dispatch-x86_64-rust-1.90.0-and-1.99.1-abort-and-unwind',
    'qualification': 'development-only-family-incomplete-side-channel-and-independent-review-pending',
    'storage': 'caller-backed-key-and-output-with-fixed-operation-scratch',
    'operations': [
        {'api': 'Aes128Key::new', 'output': 'typed-secret-key', 'failure': 'clear-admitted-key-storage'},
        {'api': 'Aes128Key::encrypt_block', 'output': 'typed-secret-block', 'failure': 'clear-admitted-output'},
        {'api': 'Aes128Key::decrypt_block', 'output': 'typed-secret-block', 'failure': 'clear-admitted-output'},
        {'api': 'Aes128Key::encrypt_block_public', 'output': 'explicit-public-ciphertext', 'failure': 'unchanged-output'},
        {'api': 'Aes128Key::clear', 'output': 'none', 'failure': 'delegated-core-clear'},
        {'api': 'SecretBlock::clear', 'output': 'none', 'failure': 'delegated-core-clear'},
        {'api': 'SecretBlock::expose', 'output': 'borrowed-secret-bytes', 'failure': 'infallible'},
    ],
    'lifecycle_scope': ['import', 'success', 'error', 'failed-construction', 'recoverable-unwind', 'explicit-clear', 'drop'],
    'excluded_scope': ['AES-192', 'AES-256', 'key-generation', 'streaming-modes', 'authentication',
                       'cancellation-api', 'rekey-api', 'key-export', 'backend-selection', 'TLS'],
    'evidence': ['crates/brynja-crypto/tests/aes128.rs', 'crates/brynja-crypto/src/aes/tests.rs',
                 'scripts/aes/check-aes-api.py', 'scripts/aes/check-aes-owner-cleanup.py',
                 'scripts/aes/check-aes-operation-cleanup.py', 'scripts/cryptography/test-aes-owner-contract.py',
                 'docs/assurance/aes128-development.md'],
}
REVIEWED_PATHS = {
    SOURCE, PORTABLE, 'crates/brynja-crypto/src/aes/portable/field.rs',
    'crates/brynja-crypto/src/aes/portable/layout.rs', 'crates/brynja-crypto/src/aes/tests.rs',
    'crates/brynja-crypto/tests/aes128.rs', 'scripts/cryptography/aes_owner_contract.py',
    'scripts/cryptography/test-aes-owner-contract.py', 'scripts/aes/check-aes-api.py',
    'scripts/aes/check-aes-owner-cleanup.py', 'scripts/aes/check-aes-operation-cleanup.py',
    'scripts/aes/test-aes-runners.py', 'assurance/aes-owner-cleanup/Cargo.toml',
    'assurance/aes-owner-cleanup/Cargo.lock', 'assurance/aes-owner-cleanup/src/lib.rs',
}


def require(condition, message):
    if not condition:
        raise ValueError('AES development-owner contract: ' + message)


def compact(text):
    return re.sub(r'\s+', '', text)


def callable_body(root, path, owner, method):
    # The generic inventory parser treats the semicolon in [u8; 16] as a
    # declaration terminator. These AES signatures need bracket-aware scanning.
    text = rust.scrub((root / path).read_text())
    scopes = rust.scope_bodies(text, owner) if owner else [text]
    bodies = []
    for scope in scopes:
        for match in rust.top_level_matches(scope, re.compile(r'\bfn\s+' + re.escape(method) + r'\b'), method):
            brackets = parentheses = 0
            for index in range(match.end(), len(scope)):
                char = scope[index]
                brackets += (char == '[') - (char == ']')
                parentheses += (char == '(') - (char == ')')
                require(brackets >= 0 and parentheses >= 0, 'unbalanced method signature')
                if char == ';' and brackets == parentheses == 0:
                    raise ValueError('AES declaration lacks method body: ' + method)
                if char == '{' and brackets == parentheses == 0:
                    bodies.append(scope[index + 1:rust.closing_brace(scope, index)])
                    break
    require(len(bodies) == 1 and bodies[0].strip(), 'missing/ambiguous method body: ' + method)
    return bodies[0]


def validate(root, owner, current):
    require(owner == {'id': ID, **RECORD}, 'canonical scoped record changed')
    require(set(RECORD['delegated_owners']) <= {row.get('id') for row in current},
            'delegated core owner absent')
    text = rust.scrub((root / SOURCE).read_text())
    for name in ('Aes128Key', 'SecretBlock'):
        rust.validate_type(root, SOURCE + '#' + name, {'region', 'local'})
        _, body = rust.declaration(text, name, {'struct'})
        require(compact(body) == "region:OwnedSecretRegion<'a>,local:PhantomData<*mut()>,",
                'exact clearing region/local marker changed: ' + name)
        require(not re.search(r'\bDrop\s+for\s+' + name + r'\b', text), 'unexpected direct owner destructor')
        clear = callable_body(root, SOURCE, name, 'clear')
        require(compact(clear) == 'let_=self.region.clear();', 'explicit clear delegation changed')
    require(re.search(r'struct Scratch<const N: usize>\(\[u8; N\]\);', text), 'scratch storage changed')
    drop = callable_body(root, SOURCE, 'Scratch', 'drop')
    require(compact(drop) == 'let_=clear_owned_region(&mutself.0);#[cfg(test)]tests::observe_clear(&self.0);',
            'mandatory scratch clearing changed')
    for entry in RECORD['operations']:
        name, method = entry['api'].split('::')
        callable_body(root, SOURCE, name, method)
    for name in ('KEY_BYTES', 'BLOCK_BYTES'):
        require(re.search(r'pub const ' + name + r': usize = 16;', text), 'fixed AES-128 width changed')
    authority = rust.declaration(text, 'PublicCiphertext', {'struct'})[1]
    require(compact(authority) == '_private:(),', 'public authority is no longer private')
    for method in ('encrypt_block_public', 'transform'):
        body = callable_body(root, SOURCE, 'Aes128Key', method)
        require('Scratch::<176>::new()' in body and 'Scratch::<16>::new()' in body,
                'operation scratch guards changed')
    portable = rust.scrub((root / PORTABLE).read_text())
    for method, size in (('expand', 4), ('shift', 16)):
        body = callable_body(root, PORTABLE, None, method)
        require(f'Scratch::<{size}>::new()' in body, 'helper scratch guard changed')
    require('for round in (1..10).rev()' in portable and 'for round in 1..10' in portable,
            'AES-128 round bounds changed')
    checks = tomllib.loads((root / 'verification/checks.toml').read_text())['checks']
    for check_id, script in (('owner-dispatch', 'owner'), ('operation-cleanup', 'operation')):
        selected = [c for c in checks if c['component'] == 'aes' and c['id'] == check_id]
        require(len(selected) == 1 and selected[0]['command'] ==
                ['python3', f'scripts/aes/check-aes-{script}-cleanup.py'], 'scoped compiler binding missing or replaced')
        require(selected[0]['category'] == 'compiler' and selected[0]['platform'] == 'linux-x86_64',
                'compiler category/platform changed')
