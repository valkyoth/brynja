#!/usr/bin/env python3
"""Write remaining explicit registrations; never execute catalog commands."""
import argparse
import fcntl
import json
from pathlib import Path
import tempfile
import tomllib
import verification_extra_sanitizers as sanitizers
import verification_repository_bindings as repository
import verification_script_bindings as scripts
import verification_assessment_bindings as assessments
import verification_hosted_bindings as hosted
import verification_compiler_bindings as compiler
import verification_codegen_bindings as codegen
import verification_shell_bindings as shell
import verification_checker_bindings as checkers
import verification_policy_bindings as policies
import verification_legacy_policy_bindings as legacy_policies
import verification_hardened_bindings as hardened
import verification_inventory_bindings as inventories
import verification_control_bindings as controls
import verification_record_policy_bindings as records
import verification_package_bindings as packages
import verification_execution_bindings as executions
import verification_owner_bindings as owners
import verification_acceptance_bindings as acceptance
import verification_final_bindings as final_components

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
    base = tomllib.loads((ROOT / 'verification/checks.toml').read_text())
    document = sanitizers.build(rows, {c['id'] for c in base['checks']})
    fixtures = repository.build(rows)
    document['groups'].update(fixtures['groups'])
    document['checks'].extend(fixtures['checks'])
    standalone = scripts.build(rows)
    document['groups'].update(standalone['groups'])
    document['checks'].extend(standalone['checks'])
    component = assessments.build(rows)
    document['groups'].update(component['groups'])
    document['checks'].extend(component['checks'])
    workers = hosted.build(rows)
    document['groups'].update(workers['groups'])
    document['checks'].extend(workers['checks'])
    profiles = compiler.build(rows)
    document['groups'].update(profiles['groups'])
    document['checks'].extend(profiles['checks'])
    artifacts = codegen.build(rows)
    document['groups'].update(artifacts['groups'])
    document['checks'].extend(artifacts['checks'])
    shells = shell.build(rows)
    document['groups'].update(shells['groups'])
    document['checks'].extend(shells['checks'])
    mocked = checkers.build(rows)
    document['groups'].update(mocked['groups'])
    document['checks'].extend(mocked['checks'])
    source = policies.build(rows)
    document['groups'].update(source['groups'])
    document['checks'].extend(source['checks'])
    legacy = legacy_policies.build(rows)
    document['groups'].update(legacy['groups'])
    document['checks'].extend(legacy['checks'])
    hardening = hardened.build(rows)
    document['groups'].update(hardening['groups'])
    document['checks'].extend(hardening['checks'])
    inventory = inventories.build(rows)
    document['groups'].update(inventory['groups'])
    document['checks'].extend(inventory['checks'])
    control = controls.build(rows)
    document['groups'].update(control['groups'])
    document['checks'].extend(control['checks'])
    record = records.build(rows)
    document['groups'].update(record['groups'])
    document['checks'].extend(record['checks'])
    packaged = packages.build(rows)
    document['groups'].update(packaged['groups'])
    document['checks'].extend(packaged['checks'])
    executed = executions.build(rows)
    document['groups'].update(executed['groups'])
    document['checks'].extend(executed['checks'])
    owner = owners.build(rows)
    document['groups'].update(owner['groups'])
    document['checks'].extend(owner['checks'])
    accepted = acceptance.build(rows)
    document['groups'].update(accepted['groups'])
    document['checks'].extend(accepted['checks'])
    final = final_components.build(rows)
    document['groups'].update(final['groups'])
    document['checks'].extend(final['checks'])
    path = ROOT / 'verification/extra-checks.json'
    text = json.dumps(document, indent=2) + '\n'
    if not args.write:
        if json.loads(path.read_text()) != document:
            raise ValueError('Extra registrations changed; review and regenerate, do not rerun tests')
    else:
        lock = ROOT / 'verification/.runner/lock'
        lock.parent.mkdir(parents=True, exist_ok=True)
        with lock.open('a+') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if not path.exists() or path.read_text() != text:
                with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as output:
                    output.write(text)
                    temporary = Path(output.name)
                temporary.replace(path)
    print(f'{len(document["checks"])} additional registrations; no checks executed')


if __name__ == '__main__':
    main()
