import json
import tempfile

import pytest

from detect_secrets.core.usage import ParserBuilder
from detect_secrets.settings import get_settings


@pytest.fixture
def parser():
    return (
        ParserBuilder()
        .add_plugin_options()
        .add_baseline_options()
    )


class TestAddCustomLimits:
    @staticmethod
    def test_success(parser):
        parser.parse_args(['--base64-limit', '5'])

        assert get_settings().plugins['Base64HighEntropyString']['limit'] == 5.0

    @staticmethod
    @pytest.mark.parametrize(
        'flag',
        (
            '--hex-limit',
            '--base64-limit',
        ),
    )
    @pytest.mark.parametrize(
        'value',
        (
            '-1',
            '8.1',
        ),
    )
    def test_failure(parser, flag, value):
        with pytest.raises(SystemExit):
            parser.parse_args([flag, value])

    @staticmethod
    def test_precedence_with_only_baseline(parser):
        with tempfile.NamedTemporaryFile() as f:
            f.write(
                json.dumps({
                    'version': '0.0.1',
                    'plugins_used': [
                        {
                            'name': 'Base64HighEntropyString',
                            'limit': 3,
                        },
                    ],
                    'results': [],
                }).encode(),
            )
            f.seek(0)

            parser.parse_args(['--baseline', f.name])

        assert get_settings().plugins['Base64HighEntropyString'] == {'limit': 3}

    @staticmethod
    def test_precedence_with_baseline_and_explicit_value(parser):
        with tempfile.NamedTemporaryFile() as f:
            f.write(
                json.dumps({
                    'version': '0.0.1',
                    'plugins_used': [
                        {
                            'name': 'Base64HighEntropyString',
                            'limit': 3,
                        },
                    ],
                    'results': [],
                }).encode(),
            )
            f.seek(0)

            parser.parse_args(['--baseline', f.name, '--base64-limit', '5'])

        assert get_settings().plugins['Base64HighEntropyString'] == {'limit': 5}


class TestAddDisableFlag:
    @staticmethod
    def test_success(parser):
        args = parser.parse_args(['--disabled-plugins', 'Base64HighEntropyString,AWSKeyDetector'])

        assert args.disabled_plugins == {'AWSKeyDetector', 'Base64HighEntropyString'}
        assert 'AWSKeyDetector' not in get_settings().plugins
        assert 'Base64HighEntropyString' not in get_settings().plugins
        assert get_settings().plugins

    @staticmethod
    def test_not_supplied(parser):
        args = parser.parse_args([])

        assert args.disabled_plugins == set([])

    @staticmethod
    def test_invalid_classname(parser):
        with pytest.raises(SystemExit):
            parser.parse_args(['--disabled-plugins', 'InvalidClassName'])

    @staticmethod
    def test_precedence_with_baseline(parser):
        with tempfile.NamedTemporaryFile() as f:
            f.write(
                json.dumps({
                    'version': '0.0.1',
                    'plugins_used': [
                        {
                            'name': 'Base64HighEntropyString',
                            'limit': 3,
                        },
                        {
                            'name': 'AWSKeyDetector',
                        },
                    ],
                    'results': [],
                }).encode(),
            )
            f.seek(0)

            parser.parse_args([
                '--baseline', f.name,
                '--disabled-plugins', 'Base64HighEntropyString',
            ])

        assert len(get_settings().plugins) == 1
        assert 'AWSKeyDetector' in get_settings().plugins
