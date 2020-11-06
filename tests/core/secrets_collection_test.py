from unittest import mock

import pytest

from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import get_settings
from detect_secrets.settings import transient_settings
from testing.factories import potential_secret_factory


@pytest.fixture(autouse=True)
def configure_plugins():
    config = {
        'plugins_used': [
            {'name': 'AWSKeyDetector'},
            {
                'name': 'Base64HighEntropyString',
                'base64_limit': 4.5,
            },
        ],
    }
    with transient_settings(config):
        yield config


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

        assert len(secrets.files) == 0

    @staticmethod
    def test_success():
        with transient_settings({
            'plugins_used': [
                {
                    'name': 'HexHighEntropyString',
                    'hex_limit': 3,
                },
            ],
            'filters_used': [],
        }):
            secrets = SecretsCollection()
            with open('test_data/sample.diff') as f:
                secrets.scan_diff(f.read())

        assert secrets.files == {
            'detect_secrets/core/baseline.py',
            'tests/core/secrets_collection_test.py',
            '.secrets.baseline',
        }


class TestTrim:
    @staticmethod
    def test_deleted_secret():
        secrets = SecretsCollection()
        secrets.scan_file('test_data/each_secret.py')

        results = SecretsCollection.load_from_baseline({'results': secrets.json()})
        results.data['test_data/each_secret.py'].pop()

        original_size = len(secrets['test_data/each_secret.py'])
        secrets.trim(results)

        assert len(secrets['test_data/each_secret.py']) < original_size

    @staticmethod
    def test_deleted_secret_file():
        secrets = SecretsCollection()
        secrets.scan_file('test_data/each_secret.py')

        secrets.trim(SecretsCollection())
        assert secrets

        secrets.trim(SecretsCollection(), filelist=['test_data/each_secret.py'])
        assert not secrets

    @staticmethod
    def test_same_secret_new_location():
        old_secret = potential_secret_factory()
        new_secret = potential_secret_factory(line_number=2)

        secrets = SecretsCollection.load_from_baseline({'results': {'blah': [old_secret.json()]}})
        results = SecretsCollection.load_from_baseline({'results': {'blah': [new_secret.json()]}})

        secrets.trim(results)

        count = 0
        for filename, secret in secrets:
            assert secret.line_number == 2
            count += 1

        assert count == 1

    @staticmethod
    @pytest.mark.parametrize(
        'base_state, scanned_results',
        (
            (
                {
                    'blah': [potential_secret_factory().json()],
                },
                {},
            ),

            # Exact same secret, so no modifications necessary
            (
                {
                    'blah': [potential_secret_factory().json()],
                },
                {
                    'blah': [potential_secret_factory().json()],
                },
            ),
        ),
    )
    def test_no_modifications(base_state, scanned_results):
        secrets = SecretsCollection.load_from_baseline({'results': base_state})
        results = SecretsCollection.load_from_baseline({'results': scanned_results})

        secrets.trim(results)

        assert secrets.json() == base_state


def test_bool():
    secrets = SecretsCollection()
    assert not secrets

    secrets.scan_file('test_data/each_secret.py')
    assert secrets

    secrets['test_data/each_secret.py'].clear()
    assert not secrets


class TestEqual:
    @staticmethod
    def test_mismatch_files():
        secretsA = SecretsCollection()
        secretsA.scan_file('test_data/each_secret.py')

        secretsB = SecretsCollection()
        secretsB.scan_file('test_data/files/file_with_secrets.py')

        assert secretsA != secretsB

    @staticmethod
    def test_strict_equality():
        secret = potential_secret_factory()
        secretsA = SecretsCollection()
        secretsA[secret.filename].add(secret)

        secret = potential_secret_factory(line_number=2)
        secretsB = SecretsCollection()
        secretsB[secret.filename].add(secret)

        assert secretsA == secretsB
        assert not secretsA.exactly_equals(secretsB)


def test_subtraction(configure_plugins):
    with transient_settings({**configure_plugins, 'filters_used': []}):
        secrets = SecretsCollection()
        secrets.scan_file('test_data/each_secret.py')

    # This baseline will have less secrets, since it filtered out some.
    with transient_settings({
        **configure_plugins,
        'filters_used': [
            {
                'path': 'detect_secrets.filters.regex.should_exclude_line',
                'pattern': 'EXAMPLE',
            },
        ],
    }):
        baseline = SecretsCollection()
        baseline.scan_file('test_data/each_secret.py')

    # This tests the != operator for same file, different number of secrets.
    # It's hidden in a different test, but I didn't want to set up the boilerplate
    # again.
    assert secrets != baseline

    result = secrets - baseline
    assert len(result['test_data/each_secret.py']) == 2
    assert len(secrets['test_data/each_secret.py']) == 4
