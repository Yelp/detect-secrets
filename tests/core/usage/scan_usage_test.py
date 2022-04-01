import json

import pytest

from detect_secrets.core import plugins
from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.settings import get_settings
from testing.mocks import mock_named_temporary_file


@pytest.fixture
def parser():
    return ParserBuilder().add_console_use_arguments()


def test_force_use_all_plugins(parser):
    with mock_named_temporary_file() as f:
        f.write(
            json.dumps({
                'version': '0.0.1',
                'plugins_used': [
                    {
                        'name': 'AWSKeyDetector',
                    },
                ],
                'results': [],
            }).encode(),
        )
        f.seek(0)

        parser.parse_args(['scan', '--force-use-all-plugins', '--baseline', f.name])

    assert len(get_settings().plugins) == len(get_mapping_from_secret_type_to_class())


def test_default_plugins_initialized(parser):
    parser.parse_args(['scan', '--hex-limit', '2'])

    assert len(get_settings().plugins) == len(get_mapping_from_secret_type_to_class())
    assert plugins.initialize.from_plugin_classname('HexHighEntropyString').entropy_limit == 2
    assert plugins.initialize.from_plugin_classname('Base64HighEntropyString').entropy_limit == 4.5
