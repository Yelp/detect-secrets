import json
import os

import pytest

from detect_secrets.core import baseline
from detect_secrets.core import plugins
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.settings import get_settings
from testing.mocks import mock_named_temporary_file


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
        with mock_named_temporary_file() as f:
            f.write(
                json.dumps({
                    'version': '0.0.1',
                    'plugins_used': [
                        {
                            'name': 'Base64HighEntropyString',
                            'base64_limit': 3,
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
        with mock_named_temporary_file() as f:
            f.write(
                json.dumps({
                    'version': '0.0.1',
                    'plugins_used': [
                        {
                            'name': 'Base64HighEntropyString',
                            'base64_limit': 3,
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
        args = parser.parse_args([
            '--disable-plugin', 'Base64HighEntropyString',
            '--disable-plugin', 'AWSKeyDetector',
        ])

        assert args.disable_plugin == {'AWSKeyDetector', 'Base64HighEntropyString'}
        assert 'AWSKeyDetector' not in get_settings().plugins
        assert 'Base64HighEntropyString' not in get_settings().plugins
        assert get_settings().plugins

    @staticmethod
    def test_not_supplied(parser):
        args = parser.parse_args([])

        assert not args.disable_plugin

    @staticmethod
    def test_invalid_classname(parser):
        with pytest.raises(SystemExit):
            parser.parse_args(['--disable-plugin', 'InvalidClassName'])

    @staticmethod
    def test_precedence_with_baseline(parser):
        with mock_named_temporary_file() as f:
            f.write(
                json.dumps({
                    'version': '0.0.1',
                    'plugins_used': [
                        {
                            'name': 'Base64HighEntropyString',
                            'base64_limit': 3,
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
                '--disable-plugin', 'Base64HighEntropyString',
            ])

        assert len(get_settings().plugins) == 1
        assert 'AWSKeyDetector' in get_settings().plugins


class TestCustomPlugins:
    @staticmethod
    def test_success(parser):
        # Ensure it serializes accordingly.
        parser.parse_args(['-p', 'testing/plugins.py'])

        with mock_named_temporary_file() as f:
            baseline.save_to_file(SecretsCollection(), f.name)
            f.seek(0)

            get_settings().clear()
            plugins.util.get_mapping_from_secret_type_to_class.cache_clear()
            assert 'HippoDetector' not in get_settings().plugins

            parser.parse_args(['--baseline', f.name])
            assert get_settings().plugins['HippoDetector'] == {
                'path': f'file://{os.path.abspath("testing/plugins.py")}',
            }
            assert plugins.initialize.from_plugin_classname('HippoDetector')

    @staticmethod
    def test_failure(parser):
        with pytest.raises(SystemExit):
            parser.parse_args(['-p', 'test_data/config.env'])
