from __future__ import absolute_import

import json
from contextlib import contextmanager

import mock
import pytest

from detect_secrets import pre_commit_hook
from detect_secrets import VERSION
from detect_secrets.core.potential_secret import PotentialSecret
from testing.factories import secrets_collection_factory
from testing.mocks import mock_git_calls
from testing.mocks import mock_log as mock_log_base
from testing.mocks import SubprocessMock


def assert_commit_blocked(command):
    assert pre_commit_hook.main(command.split()) == 1


def assert_commit_succeeds(command):
    assert pre_commit_hook.main(command.split()) == 0


class TestPreCommitHook(object):

    def test_file_with_secrets(self, mock_log):
        assert_commit_blocked('test_data/files/file_with_secrets.py')

        message_by_lines = list(filter(
            lambda x: x != '',
            mock_log.message.splitlines(),
        ))

        assert message_by_lines[0].startswith(
            'Potential secrets about to be committed to git repo!',
        )
        assert message_by_lines[2] == \
            'Secret Type: Base64 High Entropy String'
        assert message_by_lines[3] == \
            'Location:    test_data/files/file_with_secrets.py:3'

    def test_file_no_secrets(self):
        assert_commit_succeeds('test_data/files/file_with_no_secrets.py')

    def test_baseline(self):
        """This just checks if the baseline is loaded, and acts appropriately.
        More detailed baseline tests are in their own separate test suite.
        """
        with mock.patch(
            'detect_secrets.pre_commit_hook._get_baseline_string_from_file',
            return_value=_create_baseline(),
        ):
            assert_commit_succeeds(
                '--baseline will_be_mocked test_data/files/file_with_secrets.py',
            )

    def test_quit_early_if_bad_baseline(self, mock_get_baseline):
        mock_get_baseline.side_effect = IOError
        with mock.patch(
            'detect_secrets.pre_commit_hook.SecretsCollection',
            autospec=True,
        ) as mock_secrets_collection:
            assert_commit_blocked(
                '--baseline will_be_mocked test_data/files/file_with_secrets.py',
            )

            assert not mock_secrets_collection.called

    def test_ignore_baseline_file(self, mock_get_baseline):
        mock_get_baseline.return_value = secrets_collection_factory()

        assert_commit_blocked('test_data/baseline.file')
        assert_commit_succeeds('--baseline baseline.file baseline.file')

    def test_quit_if_baseline_is_changed_but_not_staged(self, mock_log):
        with mock_git_calls(
            'detect_secrets.pre_commit_hook.subprocess.check_output',
            (
                SubprocessMock(
                    expected_input='git diff --name-only',
                    mocked_output=b'baseline.file',
                ),
            ),
        ):
            assert_commit_blocked(
                '--baseline baseline.file test_data/files/file_with_secrets.py',
            )

        assert mock_log.message == (
            'Your baseline file (baseline.file) is unstaged.\n'
            '`git add baseline.file` to fix this.\n'
        )

    @pytest.mark.parametrize(
        'baseline_version, current_version',
        [
            ('', '0.8.8',),
            ('0.8.8', '0.9.0',),
            ('0.8.8', '1.0.0',),
        ],
    )
    def test_fails_if_baseline_version_is_outdated(
        self,
        mock_log,
        baseline_version,
        current_version,
    ):
        with _mock_versions(baseline_version, current_version):
            assert_commit_blocked(
                '--baseline will_be_mocked',
            )

        assert mock_log.message == (
            'The supplied baseline may be incompatible with the current\n'
            'version of detect-secrets. Please recreate your baseline to\n'
            'avoid potential mis-configurations.\n'
            '\n'
            'Current Version: {}\n'
            'Baseline Version: {}\n'
        ).format(
            current_version,
            baseline_version if baseline_version else '0.0.0',
        )

    def test_succeeds_if_patch_version_is_different(self):
        with _mock_versions('0.8.8', '0.8.9'):
            assert_commit_succeeds(
                'test_data/files/file_with_no_secrets.py',
            )

    def test_writes_new_baseline_if_modified(self):
        baseline_string = _create_baseline()
        modified_baseline = json.loads(baseline_string)
        modified_baseline['results']['test_data/files/file_with_secrets.py'][0]['line_number'] = 0

        with mock.patch(
            'detect_secrets.pre_commit_hook._get_baseline_string_from_file',
            return_value=json.dumps(modified_baseline),
        ), mock.patch(
            'detect_secrets.pre_commit_hook._write_to_baseline_file',
        ) as m:
            assert_commit_blocked(
                '--baseline will_be_mocked test_data/files/file_with_secrets.py',
            )

            baseline_written = m.call_args[0][1]

        original_baseline = json.loads(baseline_string)
        assert original_baseline['exclude_regex'] == baseline_written['exclude_regex']
        assert original_baseline['results'] == baseline_written['results']


@pytest.fixture
def mock_log():
    class MockLogWrapper(object):
        """This is used to check what is being logged."""

        def __init__(self):
            self.message = ''

        def error(self, message, *args):
            """Currently, this is the only function that is used
            when obtaining the logger.
            """
            self.message += (str(message) + '\n') % args

    with mock_log_base('detect_secrets.pre_commit_hook._get_custom_log') as m:
        wrapper = MockLogWrapper()
        m.return_value = wrapper

        yield wrapper


@pytest.fixture
def mock_get_baseline():
    with mock.patch(
        'detect_secrets.pre_commit_hook.get_baseline',
    ) as m:
        yield m


@contextmanager
def _mock_versions(baseline_version, current_version):
    baseline = json.loads(_create_baseline())
    baseline['version'] = baseline_version

    with mock.patch(
        'detect_secrets.pre_commit_hook._get_baseline_string_from_file',
        return_value=json.dumps(baseline),
    ), mock.patch.object(
        pre_commit_hook,
        'VERSION',
        current_version,
    ):
        yield


def _create_baseline():
    base64_secret = 'c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5'
    baseline = {
        'generated_at': 'does_not_matter',
        'exclude_regex': '',
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
            'test_data/files/file_with_secrets.py': [
                {
                    'type': 'Base64 High Entropy String',
                    'line_number': 3,
                    'hashed_secret': PotentialSecret.hash_secret(base64_secret),
                },
            ],
        },
        'version': VERSION,
    }

    return json.dumps(
        baseline,
        indent=2,
        sort_keys=True,
    )
