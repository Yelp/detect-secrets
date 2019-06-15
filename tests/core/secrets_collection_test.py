from __future__ import absolute_import

import json
from contextlib import contextmanager
from time import gmtime
from time import strftime

import mock
import pytest

from detect_secrets import VERSION
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.plugins.base import BasePlugin
from detect_secrets.plugins.high_entropy_strings import HexHighEntropyString
from detect_secrets.plugins.private_key import PrivateKeyDetector
from testing.factories import secrets_collection_factory
from testing.mocks import mock_log as mock_log_base
from testing.mocks import mock_open as mock_open_base


@pytest.fixture
def mock_log():
    with mock_log_base('detect_secrets.core.secrets_collection.log') as m:
        yield m


def mock_open(data):
    return mock_open_base(data, 'detect_secrets.core.secrets_collection.codecs.open')


@pytest.fixture
def mock_gmtime():
    """One coherent time value for the duration of the test."""
    current_time = gmtime()
    with mock.patch(
            'detect_secrets.core.secrets_collection.gmtime',
            return_value=current_time,
    ):
        yield current_time


class TestScanFile(object):
    """Testing file scanning, and interactions with different plugins."""

    def test_file_is_symbolic_link(self):
        logic = secrets_collection_factory()

        with mock.patch(
            'detect_secrets.core.secrets_collection.os.path',
            autospec=True,
        ) as mock_path:
            mock_path.islink.return_value = True

            assert not logic.scan_file('does_not_matter')

    def test_error_reading_file(self, mock_log):
        logic = secrets_collection_factory()

        assert not logic.scan_file('non_existent_file')
        mock_log.warning_messages == 'Unable to open file: non_existent_file'

    def test_success_single_plugin(self):
        logic = secrets_collection_factory(
            plugins=(MockPluginFixedValue(),),
        )

        with mock_open('junk text here, as it does not matter'):
            assert logic.scan_file('filename')
            assert 'filename' in logic.data
            assert next(iter(logic.data['filename'])).type == 'mock fixed value type'

    def test_success_multiple_plugins(self):
        logic = secrets_collection_factory(
            secrets=[
                {
                    'filename': 'filename',
                    'lineno': 3,
                },
            ],
            plugins=(
                MockPluginFixedValue(),
                MockPluginFileValue(),
            ),
        )

        with mock_open('junk text here'):
            logic.scan_file('filename')

        # One from each plugin, and one from existing secret
        assert len(logic.data['filename']) == 3

        line_numbers = [entry.lineno for entry in logic.data['filename']]
        assert set(line_numbers) == set([1, 2, 3])

    def test_reporting_of_password_plugin_secrets_if_reported_already(self):
        logic = secrets_collection_factory(
            secrets=[
                {
                    'filename': 'filename',
                    'lineno': 3,
                },
            ],
            plugins=(
                MockPasswordPluginValue(),
                MockPluginFileValue(),
            ),
        )

        with mock_open('junk text here'):
            logic.scan_file('filename')

        assert len(logic.data['filename']) == 3

        line_numbers = [entry.lineno for entry in logic.data['filename']]
        assert set(line_numbers) == set([2, 3])

    def test_unicode_decode_error(self, mock_log):
        logic = secrets_collection_factory(
            plugins=(MockPluginFileValue(),),
        )

        with mock_open('junk text here') as m:
            m().read.side_effect = MockUnicodeDecodeError

            logic.scan_file('filename')

        assert mock_log.info_messages == 'Checking file: filename\n'
        assert mock_log.warning_messages == 'filename failed to load.\n'

        # If the file read was successful, secret would have been caught and added.
        assert len(logic.data) == 0


class TestScanDiff(object):

    def test_success(self):
        secrets = self.load_from_diff().format_for_baseline_output()['results']

        filename_to_number_of_secrets_detected_in_it = {
            'detect_secrets/core/baseline.py': 2,
            'tests/core/secrets_collection_test.py': 1,
            '.secrets.baseline': 1,
        }

        for filename in filename_to_number_of_secrets_detected_in_it:
            assert len(secrets[filename]) == \
                filename_to_number_of_secrets_detected_in_it[filename]

    def test_ignores_baseline_file(self):
        secrets = self.load_from_diff(
            baseline_filename='.secrets.baseline',
        ).format_for_baseline_output()['results']

        assert len(secrets) == 2
        assert '.secrets.baseline' not in secrets

    def test_updates_existing_record(self):
        secrets = self.load_from_diff(
            existing_secrets=[
                {
                    'filename': 'tests/core/secrets_collection_test.py',
                    'secret': 'not the secret you are looking for',
                },
            ],
        ).format_for_baseline_output()['results']

        assert len(secrets) == 3
        assert len(secrets['tests/core/secrets_collection_test.py']) == 2

    def test_exclude_regex_skips_files_appropriately(self):
        secrets = self.load_from_diff(
            exclude_files_regex='tests/*',
        ).format_for_baseline_output()['results']

        assert len(secrets) == 2
        assert 'tests/core/secrets_collection_test.py' not in secrets

    def load_from_diff(self, existing_secrets=None, baseline_filename='', exclude_files_regex=''):
        collection = secrets_collection_factory(
            secrets=existing_secrets,
            plugins=(
                HexHighEntropyString(hex_limit=3),
            ),
            exclude_files_regex=exclude_files_regex,
        )

        with open('test_data/sample.diff') as f:
            collection.scan_diff(f.read(), baseline_filename=baseline_filename)

        return collection


class TestGetSecret(object):
    """Testing retrieval of PotentialSecret from SecretsCollection"""

    @pytest.mark.parametrize(
        'filename,secret_hash,expected_value',
        [
            ('filename', 'secret_hash', True),
            ('filename', 'not_a_secret_hash', False),
            ('diff_filename', 'secret_hash', False),
        ],
    )
    def test_optional_type(self, filename, secret_hash, expected_value):
        with self._mock_secret_hash():
            logic = secrets_collection_factory([
                {
                    'filename': 'filename',
                    'lineno': 1,
                },
            ])

        result = logic.get_secret(filename, secret_hash)
        if expected_value:
            assert result
            assert result.lineno == 1  # make sure lineno is the same
        else:
            assert not result

    @pytest.mark.parametrize(
        'type_,is_none',
        [
            ('type', False),
            ('wrong_type', True),
        ],
    )
    def test_explicit_type_for_optimization(self, type_, is_none):
        with self._mock_secret_hash():
            logic = secrets_collection_factory(
                secrets=[
                    {
                        'filename': 'filename',
                        'type_': 'type',
                    },
                ],
            )

        assert (logic.get_secret('filename', 'secret_hash', type_) is None) == is_none

    @contextmanager
    def _mock_secret_hash(self, secret_hash='secret_hash'):
        """Mocking, for the sole purpose of easier discovery for tests."""
        with mock.patch.object(
            PotentialSecret,
            'hash_secret',
            return_value=secret_hash,
        ):
            yield


class TestBaselineInputOutput(object):
    """A critical part of the SecretsCollection is the ability to write a baseline, then
    read from that same baseline to recreate state. This test suite checks the functions
    related to that ability.
    """

    def setup(self):
        self.logic = secrets_collection_factory(
            secrets=[
                {
                    'type_': 'A',
                    'lineno': 3,
                    'filename': 'fileA',
                },
                {
                    'type_': 'B',
                    'lineno': 2,
                    'filename': 'fileA',
                },
                {
                    'type_': 'C',
                    'lineno': 1,
                    'filename': 'fileB',
                },
            ],
            plugins=(
                HexHighEntropyString(3),
                PrivateKeyDetector(),
            ),
            exclude_files_regex='foo',
        )

    def test_output(self, mock_gmtime):
        assert (
            self.logic.format_for_baseline_output()

            == self.get_point_twelve_and_later_baseline_dict(mock_gmtime)
        )

    def test_load_baseline_from_string_with_pre_point_twelve_string(self, mock_gmtime):
        """
        We use load_baseline_from_string as a proxy to testing load_baseline_from_dict,
        because it's the most entry into the private function.
        """
        old_original = self.get_pre_point_twelve_old_baseline_dict(mock_gmtime)

        secrets = SecretsCollection.load_baseline_from_string(
            json.dumps(old_original),
        ).format_for_baseline_output()

        # exclude_regex got updated to exclude: files
        assert old_original['exclude_regex'] == secrets['exclude']['files']
        assert secrets['exclude']['lines'] is None
        assert old_original['results'] == secrets['results']

    def test_load_baseline_from_string_with_point_twelve_and_later_string(self, mock_gmtime):
        """
        We use load_baseline_from_string as a proxy to testing load_baseline_from_dict,
        because it's the most entry into the private function.
        """
        original = self.get_point_twelve_and_later_baseline_dict(mock_gmtime)

        secrets = SecretsCollection.load_baseline_from_string(
            json.dumps(original),
        ).format_for_baseline_output()

        assert original['exclude']['files'] == secrets['exclude']['files']
        assert secrets['exclude']['lines'] is None
        assert original['results'] == secrets['results']

    def test_load_baseline_without_any_valid_fields(self, mock_log):
        with pytest.raises(IOError):
            SecretsCollection.load_baseline_from_string(
                json.dumps({
                    'junk': 'dictionary',
                }),
            )
        assert mock_log.error_messages == 'Incorrectly formatted baseline!\n'

    def test_load_baseline_without_exclude(self, mock_log):
        with pytest.raises(IOError):
            SecretsCollection.load_baseline_from_string(
                json.dumps({
                    'plugins_used': (),
                    'results': {},
                }),
            )
        assert mock_log.error_messages == 'Incorrectly formatted baseline!\n'

    def get_point_twelve_and_later_baseline_dict(self, gmtime):
        # In v0.12.0 `exclude_regex` got replaced by `exclude`
        baseline = self._get_baseline_dict(gmtime)
        baseline['exclude'] = {}
        baseline['exclude']['files'] = 'foo'
        baseline['exclude']['lines'] = None
        return baseline

    def get_pre_point_twelve_old_baseline_dict(self, gmtime):
        baseline = self._get_baseline_dict(gmtime)
        # In v0.12.0 `exclude_regex` got replaced by `exclude`
        baseline['exclude_regex'] = 'foo'
        return baseline

    def _get_baseline_dict(self, gmtime):
        # They are all the same secret, so they should all have the same secret hash.
        secret_hash = PotentialSecret.hash_secret('secret')

        return {
            'generated_at': strftime('%Y-%m-%dT%H:%M:%SZ', gmtime),
            'plugins_used': [
                {
                    'name': 'HexHighEntropyString',
                    'hex_limit': 3,
                },
                {
                    'name': 'PrivateKeyDetector',
                },
            ],
            'results': {
                'fileA': [
                    # Line numbers should be sorted, for better readability
                    {
                        'type': 'B',
                        'is_verified': False,
                        'line_number': 2,
                        'hashed_secret': secret_hash,
                    },
                    {
                        'type': 'A',
                        'is_verified': False,
                        'line_number': 3,
                        'hashed_secret': secret_hash,
                    },
                ],
                'fileB': [
                    {
                        'type': 'C',
                        'is_verified': False,
                        'line_number': 1,
                        'hashed_secret': secret_hash,
                    },
                ],
            },
            'version': VERSION,
        }


class MockBasePlugin(BasePlugin):  # pragma: no cover
    """Abstract testing class, to implement abstract methods."""

    def analyze_string_content(self, value):
        pass

    def secret_generator(self, string):
        pass


class MockPluginFixedValue(MockBasePlugin):

    secret_type = 'mock_plugin_fixed_value'

    def analyze(self, f, filename):
        # We're not testing the plugin's ability to analyze secrets, so
        # it doesn't matter what we return
        secret = PotentialSecret('mock fixed value type', filename, 'asdf', 1)
        return {secret: secret}


class MockPluginFileValue(MockBasePlugin):

    secret_type = 'mock_plugin_file_value'

    def analyze(self, f, filename):
        # We're not testing the plugin's ability to analyze secrets, so
        # it doesn't matter what we return
        secret = PotentialSecret('mock file value type', filename, f.read().strip(), 2)
        return {secret: secret}


class MockPasswordPluginValue(MockBasePlugin):

    secret_type = 'mock_plugin_file_value'

    def analyze(self, f, filename):
        password_secret = PotentialSecret('Password', filename, f.read().strip(), 2)
        return {
            password_secret: password_secret,
        }


MockUnicodeDecodeError = UnicodeDecodeError('encoding type', b'subject', 0, 1, 'exception message')
