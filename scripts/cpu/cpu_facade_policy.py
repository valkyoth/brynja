"""Default-off no_std facade edge; hosted detection is still forbidden."""


def validate(crypto, packages, fail):
    cpu = 'brynja-crypto-cpu'
    deps = crypto.get('dependencies', {})
    features = crypto.get('features', {})
    if (deps.get(cpu) != {'workspace': True, 'optional': True} or
            'brynja-crypto-cpu-std' in deps or
            features.get('cpu') != ['dep:' + cpu] or
            features.get('default') != [] or
            packages['brynja-crypto'].get('optional') != {'cpu': cpu}):
        fail('facade CPU dependency must remain explicit, optional and no_std')
