from unittest import mock

import pytest

from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import get_settings


@pytest.fixture(autouse=True)
def configure_plugins():
    get_settings().configure_plugins([
        {'name': 'AWSKeyDetector'},
        {
            'name': 'Base64HighEntropyString',
            'base64_limit': 4.5,
        },
    ])


class TestScanFile:
    @staticmethod
    def test_filename_filters_are_invoked_first(mock_log):
        # This is a directory, which should be ignored via
        # detect_secrets.filters.common.is_invalid_file
        SecretsCollection().scan_file('test_data')

        mock_log.info.assert_called_once_with(
            'Skipping "test_data" due to "detect_secrets.filters.common.is_invalid_file"',
        )

    @staticmethod
    def test_error_reading_file(mock_log):
        with mock.patch(
            'detect_secrets.core.secrets_collection.open',
            side_effect=IOError,
        ):
            SecretsCollection().scan_file('test_data/config.env')

        mock_log.warning.assert_called_once_with(
            'Unable to open file: test_data/config.env',
        )

    @staticmethod
    def test_line_based_success():
        # Explicitly configure filters, so that additions to filters won't affect this test.
        get_settings().configure_filters([
            # This will remove the `id` string
            {'path': 'detect_secrets.filters.heuristic.is_likely_id_string'},

            # This gets rid of the aws keys with `EXAMPLE` in them.
            {
                'path': 'detect_secrets.filters.regex.should_exclude_line',
                'pattern': 'EXAMPLE',
            },
        ])

        secrets = SecretsCollection()
        secrets.scan_file('test_data/each_secret.py')

        secret = next(iter(secrets['test_data/each_secret.py']))
        assert secret.secret_value.startswith('c2VjcmV0IG1lc')
        assert len(secrets['test_data/each_secret.py']) == 1

    @staticmethod
    @pytest.mark.skip(reason='TODO')
    def test_file_based_success():
        pass


class TestScanDiff:
    @staticmethod
    def test_filename_filters_are_invoked_first():
        get_settings().configure_filters([
            {
                'path': 'detect_secrets.filters.regex.should_exclude_file',
                'pattern': 'test|baseline',
            },
        ])

        secrets = SecretsCollection()
        with open('test_data/sample.diff') as f:
            secrets.scan_diff(f.read())

        assert len(secrets.data) == 0

    @staticmethod
    def test_success():
        get_settings().configure_plugins([
            {
                'name': 'HexHighEntropyString',
                'hex_limit': 3,
            },
        ])
        get_settings().configure_filters([])
        secrets = SecretsCollection()
        with open('test_data/sample.diff') as f:
            secrets.scan_diff(f.read())

        assert set(secrets.data.keys()) == {
            'detect_secrets/core/baseline.py',
            'tests/core/secrets_collection_test.py',
            '.secrets.baseline',
        }
