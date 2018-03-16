from __future__ import absolute_import

import json
import logging
import unittest

import mock

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.pre_commit_hook import main


class PreCommitHookTest(unittest.TestCase):

    @mock.patch('detect_secrets.pre_commit_hook.CustomLog')
    def test_file_with_secrets(self, mock_log):
        # Silence logs for testing
        mock_log.getLogger().setLevel(logging.CRITICAL)

        assert main(['./test_data/file_with_secrets.py']) == 1

    def test_file_with_no_secrets(self):
        assert main(['./test_data/file_with_no_secrets.py']) == 0

    def test_baseline(self):
        """This just checks if the baseline is loaded, and acts appropriately.
        More detailed baseline tests are in their own separate test suite."""

        base64_hash = 'c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5'

        file_content = json.dumps({
            'generated_at': 'blah blah',
            'exclude_regex': '',
            'results': {
                './test_data/file_with_secrets.py': [
                    {
                        'type': 'High Entropy String',
                        'line_number': 4,
                        'hashed_secret': PotentialSecret.hash_secret(base64_hash),
                    },
                ],
            }
        }, indent=2)

        m = mock.mock_open(read_data=file_content)
        with mock.patch('detect_secrets.core.secrets_collection.codecs.open', m):
            assert main([
                '--baseline',
                'will_be_mocked',
                './test_data/file_with_secrets.py'
            ]) == 0

    @mock.patch('detect_secrets.pre_commit_hook.SecretsCollection', autospec=True)
    def test_no_computation_if_bad_baseline(self, mock_secrets_collection):
        mock_secrets_collection.load_baseline_from_file.side_effect = IOError

        assert main([
            '--baseline',
            'will_be_mocked',
            './test_data/file_with_secrets.py',
        ]) == 1

        assert mock_secrets_collection.scan_file.called is False

    @mock.patch('detect_secrets.pre_commit_hook.SecretsCollection', autospec=True)
    @mock.patch('detect_secrets.pre_commit_hook.apply_baseline_filter')
    def test_ignore_baseline_file(self, mock_apply_baseline, mock_secrets_collection):
        mock_secrets_collection.load_baseline_from_file.return_value = None

        assert main([
            '--baseline',
            'baseline.file',
            'baseline.file',
        ]) == 0

        # It shouldn't scan anything, because baseline.file is the only file to be scanned,
        # and it's the baseline itself.
        assert mock_secrets_collection.scan_file.called is False
