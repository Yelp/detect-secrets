#!/usr/bin/python
from __future__ import absolute_import

import json
import unittest
from time import gmtime
from time import strftime

import mock

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.plugins.base import BasePlugin
from detect_secrets.plugins.high_entropy_strings import HexHighEntropyString
from tests.util.file_util import create_file_object_from_string
from tests.util.file_util import create_file_object_that_throws_unicode_decode_error


class SecretsCollectionTest(unittest.TestCase):

    def setUp(self):
        self.logic = SecretsCollection()

    @mock.patch('detect_secrets.core.secrets_collection.os.path', autospec=True)
    def test_scan_file_symbolic_link(self, mock_path):
        mock_path.islink.return_value = True

        assert not self.logic.scan_file('does_not_matter')

    @mock.patch('detect_secrets.core.secrets_collection.CustomLogObj', autospec=True)
    def test_scan_file_ioerror(self, mock_log):
        assert not self.logic.scan_file('non_existent_file')
        mock_log.getLogger().warning.assert_called_once()

    def test_scan_file_proper_use(self):
        self.logic.plugins = (MockPluginFixedValue(),)

        m = mock.mock_open(read_data='junk text here, as it does not matter')
        with mock.patch('detect_secrets.core.secrets_collection.codecs.open', m):
            assert self.logic.scan_file('filename')
            assert 'filename' in self.logic.data
            assert next(iter(self.logic.data['filename'])).type == 'mock fixed value type'

    def test_extract_secrets_multiple_plugins(self):
        filename = 'filename'
        self.logic.data[filename] = {
            PotentialSecret('mock no value type', filename, 3, 'no value'): True
        }
        self.logic.plugins = (
            MockPluginFixedValue(),
            MockPluginFileValue(),
        )

        self.logic._extract_secrets(
            create_file_object_from_string('blah blah'),
            filename
        )

        assert len(self.logic.data[filename]) == 3

        line_numbers = [entry.lineno for entry in self.logic.data[filename]]
        line_numbers.sort()
        assert line_numbers == [1, 2, 3]

    @mock.patch('detect_secrets.core.secrets_collection.CustomLogObj', autospec=True)
    def test_extract_secrets_exception(self, mock_log):
        filename = 'filename'
        self.logic.data = {}
        self.logic.plugins = (HexHighEntropyString(3),)

        self.logic._extract_secrets(
            create_file_object_that_throws_unicode_decode_error(
                '2b00042f7481c7b056c4b410d28f33cf'
            ),
            filename
        )

        assert mock_log.getLogger().warning.called

        # If the file read was successful, the md5 hash would have been caught and added
        # to self.logic.data
        assert len(self.logic.data) == 0

    def test_get_secret_no_type(self):
        cases = [
            ('filename', 'secret', True),
            ('filename', 'not_a_secret', False),
            ('diff_filename', 'secret', False)
        ]

        secret = PotentialSecret('type', 'filename', 1, 'secret')
        secret.secret_hash = 'secret'
        self.logic.data['filename'] = {secret: secret}

        for case in cases:
            filename, secret_hash, expected_value = case
            if expected_value:
                result = self.logic.get_secret(filename, secret_hash)
                assert result is not None
                assert result.lineno == 1   # make sure lineno is the same
            else:
                assert self.logic.get_secret(filename, secret_hash) is None

    def test_get_secret_with_type(self):
        cases = [
            ('type', True),
            ('wrong_type', False)
        ]

        secret = PotentialSecret('type', 'filename', 1, 'secret')
        self.logic.data['filename'] = {secret: secret}

        for case in cases:
            typ, expected_value = case
            if expected_value:
                assert self.logic.get_secret('filename', secret.secret_hash, typ) is not None
            else:
                assert self.logic.get_secret('filename', secret.secret_hash, typ) is None

    def _setup_secrets_for_file_testing(self, current_time):
        """This initializes the overhead necessary for testing
        save_to_file and load_from_file

        :param current_time: time.struct_time
        :returns:            json object, representing loaded state
        :modifies:           self.logic
        """
        secretA = PotentialSecret('type A', 'filename1', 3, 'winnie')
        secretB = PotentialSecret('type B', 'filename1', 2, 'the')
        secretC = PotentialSecret('type C', 'filename2', 1, 'pooh')

        self.logic.data = {
            'filename1': {
                secretA: secretA,
                secretB: secretB
            },
            'filename2': {
                secretC: secretC
            }
        }

        return {
            'generated_at': strftime("%Y-%m-%dT%H:%M:%SZ", current_time),
            'exclude_regex': '',
            'results': {
                'filename1': [
                    {
                        'type': 'type B',
                        'line_number': 2,
                        'hashed_secret': secretB.secret_hash,
                    },
                    {
                        'type': 'type A',
                        'line_number': 3,
                        'hashed_secret': secretA.secret_hash,
                    },
                ],
                'filename2': [
                    {
                        'type': 'type C',
                        'line_number': 1,
                        'hashed_secret': secretC.secret_hash,
                    },
                ],
            }
        }

    @mock.patch('detect_secrets.core.secrets_collection.gmtime')
    @mock.patch('detect_secrets.core.secrets_collection.json.dumps')
    def test_output_baseline(self, mock_json, mock_gmtime):
        current_time = gmtime()
        mock_gmtime.return_value = current_time

        sample_json = self._setup_secrets_for_file_testing(current_time)

        self.logic.output_baseline()
        mock_json.assert_called_once_with(sample_json, indent=2)

    @mock.patch('detect_secrets.core.secrets_collection.gmtime')
    @mock.patch('detect_secrets.core.secrets_collection.json.dumps')
    def test_output_baseline_with_exclude_regex(self, mock_json, mock_gmtime):
        current_time = gmtime()
        mock_gmtime.return_value = current_time

        sample_json = self._setup_secrets_for_file_testing(current_time)

        sample_json['exclude_regex'] = 'justforcoverage'
        self.logic.output_baseline(exclude_regex='justforcoverage')
        mock_json.assert_called_once_with(sample_json, indent=2)

    def test_load_from_file_success(self):
        sample_json = self._setup_secrets_for_file_testing(gmtime())

        m = mock.mock_open(read_data=json.dumps(sample_json))
        with mock.patch('detect_secrets.core.secrets_collection.codecs.open', m):
            collection = SecretsCollection.load_from_file('does_not_matter')

        assert len(collection.json()) == len(sample_json['results'])

        for filename in collection.json():
            assert filename in sample_json['results']

            actual = sorted(collection.json()[filename], key=lambda x: x['line_number'])
            expected = sorted(sample_json['results'][filename], key=lambda x: x['line_number'])
            assert actual == expected

    def _assert_file_failures(self, callback, mock_log):
        """DRY code pattern to test file exceptions upon attempted load.

        :param callback: function that receives a filename as an input, and is expected
                         to read from that file, and raise an exception.
        :param mock_log: the mocked CustomLogObj.
        """
        exceptions = (
            UnicodeDecodeError('encoding type', b'subject', 0, 1, 'exception message'),
            IOError,
        )
        m = mock.mock_open()
        with mock.patch('detect_secrets.core.secrets_collection.codecs.open', m):
            for exception in exceptions:
                m.side_effect = exception
                try:
                    callback('does_not_matter')
                    assert False  # This should never run! pragma: no cover
                except (IOError, UnicodeDecodeError):
                    assert mock_log.getLogger().error.called

                    # reset called status, for next exception.
                    mock_log.getLogger().error.called = False

    @mock.patch('detect_secrets.core.secrets_collection.CustomLogObj', autospec=True)
    def test_load_from_file_failures(self, mock_log):
        # File failures
        self._assert_file_failures(SecretsCollection.load_from_file, mock_log)

        # Formatting failures
        m = mock.mock_open(read_data=json.dumps({'random': 'json'}))
        with mock.patch('detect_secrets.core.secrets_collection.codecs.open', m):
            try:
                SecretsCollection.load_from_file('does_not_matter')
                assert False            # This should never run! pragma: no cover
            except IOError:
                assert mock_log.getLogger().error.called

    @mock.patch('detect_secrets.core.secrets_collection.CustomLogObj', autospec=True)
    def test_load_from_string(self, mock_log):
        # Success (smoke test, because it should be the exact same as load_from_file)
        sample_json = self._setup_secrets_for_file_testing(gmtime())
        collection = SecretsCollection.load_from_string(json.dumps(sample_json))

        assert len(collection.json()) == len(sample_json['results'])

        # Failure
        try:
            SecretsCollection.load_from_string('not a json')
            assert False        # This should never run! pragma: no cover
        except ValueError:
            assert mock_log.getLogger().error.called

        mock_log.getLogger().error.called = False

    def test_load_from_diff(self):
        self.logic.plugins = (HexHighEntropyString(3),)

        # This is to test the update results code path if filename already exists
        # in self.data.
        mock_filename = 'tests/core/secrets_collection_test.py'
        self.logic.data[mock_filename] = {
            PotentialSecret('mock no value type', mock_filename, 3, 'no value'): True
        }

        # Exclude the baseline file
        with open('test_data/sample.diff') as f:
            self.logic.load_from_diff(f.read(), baseline_file=".secrets.baseline")

        # Format: (filename, number_of_secrets_found)
        expected_secrets = (
            ('detect_secrets/core/baseline.py', 2),
            ('tests/core/secrets_collection_test.py', 1 + 1)    # one from the mock_secret
        )

        assert len(self.logic.data) == 2
        for expected_secret in expected_secrets:
            assert expected_secret[0] in self.logic.data
            assert len(self.logic.data[expected_secret[0]]) == expected_secret[1]

        # Don't exclude the baseline file
        with open('test_data/sample.diff') as f:
            self.logic.load_from_diff(f.read())

        # Format: (filename, number_of_secrets_found)
        expected_secrets = (
            ('detect_secrets/core/baseline.py', 2),
            ('tests/core/secrets_collection_test.py', 1 + 1),    # one from the mock_secret
            ('.secrets.baseline', 1)
        )

        assert len(self.logic.data) == 3
        for expected_secret in expected_secrets:
            assert expected_secret[0] in self.logic.data
            assert len(self.logic.data[expected_secret[0]]) == expected_secret[1]

    def test_load_from_diff_with_exclude_regex(self):
        self.logic.plugins = (HexHighEntropyString(3),)

        # With excluding tests
        with open('test_data/sample.diff') as f:
            self.logic.load_from_diff(f.read(), exclude_regex='tests/*', baseline_file=".secrets.baseline")

        # Format: (filename, number_of_secrets_found)
        expected_secrets = (
            ('detect_secrets/core/baseline.py', 2),
        )

        assert len(self.logic.data) == 1
        for expected_secret in expected_secrets:
            assert expected_secret[0] in self.logic.data
            assert len(self.logic.data[expected_secret[0]]) == expected_secret[1]

    def test_load_from_diff_when_filename_already_exists(self):
        self.logic.plugins = (HexHighEntropyString(3),)
        mock_filename = 'tests/core/secrets_collection_test.py'
        self.logic.data[mock_filename] = {
            PotentialSecret('mock no value type', mock_filename, 3, 'no value'): True
        }
        # Without excluding tests
        with open('test_data/sample.diff') as f:
            self.logic.load_from_diff(f.read(), baseline_file=".secrets.baseline")

        # Format: (filename, number_of_secrets_found)
        expected_secrets = (
            ('detect_secrets/core/baseline.py', 2),
            ('tests/core/secrets_collection_test.py', 1 + 1)    # one from the mock_secret
        )

        assert len(self.logic.data) == 2
        for expected_secret in expected_secrets:
            assert expected_secret[0] in self.logic.data
            assert len(self.logic.data[expected_secret[0]]) == expected_secret[1]


class MockPluginFixedValue(BasePlugin):

    def analyze(self, f, filename):
        # We're not testing the plugin's ability to analyze secrets, so
        # it doesn't matter what we return
        secret = PotentialSecret('mock fixed value type', filename, 1, 'asdf')
        return {secret: secret}


class MockPluginFileValue(BasePlugin):

    def analyze(self, f, filename):
        # We're not testing the plugin's ability to analyze secrets, so
        # it doesn't matter what we return
        secret = PotentialSecret('mock file value type', filename, 2, f.read().strip())
        return {secret: secret}
