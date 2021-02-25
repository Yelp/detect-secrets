import os

import pytest

from detect_secrets.core import plugins
from detect_secrets.core.upgrades import v1_0


def test_custom_plugins_does_not_pollute_settings():
    old_baseline = {
        'version': '0.14.3',
        'custom_plugin_paths': [
            'testing/plugins.py',
        ],
        'plugins_used': [],
        'results': [],
    }

    with pytest.raises(TypeError):
        plugins.initialize.from_plugin_classname('HippoDetector')

    new_baseline = {**old_baseline}
    v1_0.upgrade(new_baseline)

    assert 'custom_plugin_paths' not in new_baseline
    assert new_baseline['plugins_used'] == [
        {
            'name': 'HippoDetector',
            'path': f'file://{os.path.abspath("testing/plugins.py")}',
        },
    ]
    with pytest.raises(TypeError):
        plugins.initialize.from_plugin_classname('HippoDetector')
