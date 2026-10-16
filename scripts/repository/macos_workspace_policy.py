"""Exact default-off resident feature inventory; strict admission is unchanged."""
import copy
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'cpu'))
from cpu_boundary_backends import MACOS_RESIDENT_FEATURES

FEATURES = {'brynja-crypto-cpu-std': MACOS_RESIDENT_FEATURES}
for family in ('sha1', 'md5'):
    FEATURES[f'brynja-legacy-{family}-std'] = {
        'macos-resident': ['dep:brynja-core'],
        'macos-resident-acceleration': ['macos-resident', f'brynja-legacy-{family}/hardened-execution'],
    }


def regressions(baseline, package, reject):
    count = 0
    for name, features in FEATURES.items():
        for feature in features:
            for key, value in (('default', [feature]), (feature, []),
                               (feature, ['protected-memory']), (feature, None)):
                changed = copy.deepcopy(baseline)
                target = package(changed, name)['features']
                if value is None:
                    del target[key]
                else:
                    target[key] = value
                reject(changed, 'all-features', 'feature policy differs',
                       'resident default/closure/strict-substitution drift')
                count += 1
    print(f'Resident workspace feature inventory rejects {count} regressions')
