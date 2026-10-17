"""Compiled execution/scoped KMAC separation under additive leaf features."""
import json

FIXED = ('finalize_tag_conformance', 'finalize_tag_bits_conformance',
         'finalize_secret_conformance', 'finalize_secret_bits_conformance',
         'verify_conformance', 'verify_bits_conformance')
XOF = ('finalize_xof_conformance', 'finalize_bits_xof_conformance')
CONSTRUCT = ('new_conformance', 'new_bits_conformance')
SCOPE = ('with_conformance', 'with_bits_conformance')
STATES = ('Kmac128', 'Kmac256', 'KmacXof128', 'KmacXof256')
SCOPED = (*STATES, *(name + 'Workspace' for name in STATES),
          'KmacXof128Reader', 'KmacXof256Reader')


def errors(result):
    return [item['message'] for line in result.stdout.splitlines()
            if (item := json.loads(line)).get('reason') == 'compiler-message'
            and item['message']['level'] == 'error']


def check(api, consumer, package, cargo, env):
    count = 0
    surfaces = [('leaf::execution', False), ('api::kmac::execution', False),
                ('leaf::hardened_in_place', True),
                ('leaf::hardened_in_place::accelerated', True),
                ('leaf::execution::in_place', True),
                ('api::kmac::execution::in_place', True)]
    for prefix, scoped in surfaces:
        types = SCOPED if scoped else STATES
        for name in types:
            workspace = name.endswith('Workspace')
            lifetime = ("<'static, 'static>" if scoped and 'in_place' in prefix
                        and prefix != 'leaf::hardened_in_place' and not workspace
                        else "<'static>")
            if prefix == 'leaf::hardened_in_place' and workspace:
                lifetime = ''
            if prefix.endswith('accelerated') and not workspace:
                lifetime = "<'static, 'static>"
            identity = f'{prefix}::{name}{lifetime}'
            # Prevent missing imports/types from making negative probes vacuous.
            api.source(consumer, package, f'pub type Exists = {identity};\n')
            api.run(cargo + ['check', '--offline'], consumer, env)
            methods = (() if name.endswith('Reader') else
                       SCOPE + (('with_bits_and_scratch_conformance',)
                                if prefix != 'leaf::hardened_in_place' else ())
                       if workspace else (XOF if 'Xof' in name else FIXED))
            if not scoped:
                methods = CONSTRUCT + methods
            for method in methods:
                api.source(consumer, package,
                           f'pub fn probe() {{ let _ = <{identity}>::{method}; }}\n')
                result = api.run(cargo + ['check', '--offline', '--message-format=json'],
                                 consumer, env, success=False)
                api.require(any((e.get('code') or {}).get('code') == 'E0599'
                                and method in e['message'] for e in errors(result)),
                            'wrong execution/scoped rejection: ' + identity + '::' + method)
                count += 1
    print(f'PASS: {package}: {count} execution/scoped conformance method rejections', flush=True)

    count = 0
    for suffix, names in (('execution', (*STATES, 'Reader')),
                          ('hardened_in_place', SCOPED),
                          ('execution::in_place', SCOPED)):
        for name in names:
            scoped = suffix != 'execution'
            workspace = name.endswith('Workspace')
            lifetime = ("<'static, 'static>" if name == 'Reader' or
                        suffix == 'execution::in_place' and not workspace else "<'static>")
            if suffix == 'hardened_in_place' and workspace:
                lifetime = ''
            source = f'leaf::conformance::{suffix}::{name}{lifetime}'
            target = f'leaf::{suffix}::{name}{lifetime}'
            api.source(consumer, package, f'pub type Exists = {source};\n')
            api.run(cargo + ['check', '--offline'], consumer, env)
            probes = [f'pub fn probe(v: {source}) -> {target} {{ v.into() }}\n']
            bounds = ['Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug']
            if not scoped:
                bounds.append('leaf::execution::HardenedState')
            probes += [f'fn bound<T: {bound}>() {{}}\n'
                       f'pub fn probe() {{ bound::<{source}>(); }}\n' for bound in bounds]
            for body in probes:
                api.source(consumer, package, body)
                result = api.run(cargo + ['check', '--offline', '--message-format=json'],
                                 consumer, env, success=False)
                api.require(any((e.get('code') or {}).get('code') == 'E0277'
                                for e in errors(result)), 'test owner separation: ' + source)
                count += 1
    print(f'PASS: {package}: {count} test-owner trait/conversion rejections', flush=True)
