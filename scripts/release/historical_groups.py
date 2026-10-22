"""Read a sealed snapshot's group inventory as data, never execute its code."""
import ast
import re

import detached_manifest as records
import verification_plan as plans


def inventory(root):
    path = root / 'scripts/zeroization/miri_scope.py'
    records.file_hash(path, 1024 * 1024)
    tree = ast.parse(path.read_bytes())
    assignments = [node for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'GROUPS'
                           for target in node.targets)]
    if len(assignments) != 1 or len(assignments[0].targets) != 1:
        raise ValueError('historical group inventory missing or ambiguous')
    groups = ast.literal_eval(assignments[0].value)
    if (not isinstance(groups, tuple) or not groups
            or any(not isinstance(group, str) or group not in plans.scope.GROUPS for group in groups)
            or len(groups) != len(set(groups))):
        raise ValueError('unknown or duplicate historical group')
    shell = root / 'scripts/zeroization/check-zeroization-miri.sh'
    records.file_hash(shell, 1024 * 1024)
    rows = re.findall(r'^all_groups=\(([^\n]*)\)$', shell.read_text(), re.M)
    if rows != [' '.join(groups)]:
        raise ValueError('historical shell/group inventory differs')
    return groups


def project(plan, groups):
    # Only reconstruction of a sealed historical snapshot uses this projection.
    # The current candidate plan and coverage/reuse decision remain untouched.
    return {**plan, 'groups': [g for g in plan['groups'] if g in groups],
            'verifiers': {phase: [g for g in selected if g in groups]
                          for phase, selected in plan['verifiers'].items()}}
