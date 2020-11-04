import json
import tempfile

import pytest

from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.settings import get_settings


@pytest.fixture
def parser():
    return ParserBuilder().add_console_use_arguments()


def test_force_use_all_plugins(parser):
    with tempfile.NamedTemporaryFile() as f:
        f.write(
            json.dumps({
                'plugins_used': [
                    {
                        'name': 'AWSKeyDetector',
                    },
                ],
            }).encode(),
        )
        f.seek(0)

        parser.parse_args(['scan', '--force-use-all-plugins', '--baseline', f.name])

    assert len(get_settings().plugins) == len(get_mapping_from_secret_type_to_class())
