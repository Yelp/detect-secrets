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
from testing.util import get_regex_based_plugins
from testing.util import parse_pre_commit_args_with_correct_prog


def call_pre_commit_hook(command):
    with mock.patch(
        'detect_secrets.pre_commit_hook.parse_args',
        return_value=parse_pre_commit_args_with_correct_prog(command),
    ):
        return pre_commit_hook.main(command.split())


def assert_commit_blocked(command):
    assert call_pre_commit_hook(command) == 1


def assert_commit_blocked_with_diff_exit_code(command):
    assert call_pre_commit_hook(command) == 3


def assert_commit_succeeds(command):
    assert call_pre_commit_hook(command) == 0


class TestPreCommitHook:

    def test_file_with_secrets(self, mock_log):
        assert_commit_blocked('test_data/files/file_with_secrets.py')

        message_by_lines = list(
            filter(
                lambda x: x != '',
                mock_log.error_messages.splitlines(),
            ),
        )

        assert message_by_lines[0].startswith(
            'Potential secrets about to be committed to git repo!',
        )
        assert (
            message_by_lines[2]
            ==
            'Secret Type: Base64 High Entropy String'
        )
        assert (
            message_by_lines[3]
            ==
            'Location:    test_data/files/file_with_secrets.py:3'
        )

    def test_file_with_secrets_with_word_list(self):
        assert_commit_succeeds(
            'test_data/files/file_with_secrets.py --word-list test_data/word_list.txt',
        )

    def test_file_with_no_secrets(self):
        assert_commit_succeeds('test_data/files/file_with_no_secrets.py')

    def test_file_with_custom_secrets_without_custom_plugins(self):
        assert_commit_succeeds('test_data/files/file_with_custom_secrets.py')

    def test_file_with_custom_secrets_with_custom_plugins(self, mock_log):
        assert_commit_blocked(
            'test_data/files/file_with_custom_secrets.py '
            '--custom-plugins testing/custom_plugins_dir '
            '--custom-plugins testing/hippo_plugin.py',
        )

        message_by_lines = list(
            filter(
                lambda x: x != '',
                mock_log.error_messages.splitlines(),
            ),
        )
        assert message_by_lines[0].startswith(
            'Potential secrets about to be committed to git repo!',
        )
        assert 'Secret Type: Hippo' in message_by_lines
        assert (
            'Location:    test_data/files/file_with_custom_secrets.py:4'
            in message_by_lines
        )
        assert (
            'Secret Type: Tasty Dessert'
            in message_by_lines
        )
        assert (
            'Location:    test_data/files/file_with_custom_secrets.py:3'
            in message_by_lines
        )

    @pytest.mark.parametrize(
        'has_result, use_private_key_scan, hook_command, commit_succeeds',
        [
            # Basic case
            (True, True, '--baseline will_be_mocked test_data/files/file_with_secrets.py', True),
            # test_no_overwrite_pass_when_baseline_did_not_use_scanner
            (True, False, '--baseline will_be_mocked test_data/files/private_key', True),
            # test_no_overwrite_quit_when_baseline_use_scanner
            (False, True, '--baseline will_be_mocked test_data/files/file_with_secrets.py', False),
            # test_overwrite_pass_with_baseline
            (
                False, True, '--baseline will_be_mocked '
                + '--no-base64-string-scan test_data/files/file_with_secrets.py', True,
            ),
            # test_all_plugin_overwrite_pass_with_baseline
            (
                False, True, '--baseline will_be_mocked --use-all-plugins '
                + '--no-base64-string-scan test_data/files/file_with_secrets.py', True,
            ),
            # test_overwrite_fail_with_baseline
            (
                True, False, '--baseline will_be_mocked '
                + '--use-all-plugins test_data/files/private_key', False,
            ),
        ],
    )
    def test_baseline(
        self,
        has_result,
        use_private_key_scan,
        hook_command,
        commit_succeeds,
    ):
        """This just checks if the baseline is loaded, and acts appropriately.
        More detailed baseline tests are in their own separate test suite.
        """
        with mock.patch(
            'detect_secrets.pre_commit_hook._get_baseline_string_from_file',
            return_value=_create_baseline(
                has_result=has_result,
                use_private_key_scan=use_private_key_scan,
            ),
        ):
            if commit_succeeds:
                assert_commit_succeeds(hook_command)
            else:
                assert_commit_blocked(hook_command)

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

        assert_commit_blocked('--use-all-plugins test_data/baseline.file')
        assert_commit_succeeds('--use-all-plugins --baseline baseline.file baseline.file')

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

        assert mock_log.error_messages == (
            'Your baseline file (baseline.file) is unstaged.\n'
            '`git add baseline.file` to fix this.\n'
        )

    @pytest.mark.parametrize(
        'baseline_version, current_version',
        [
            ('', '0.8.8'),
            ('0.8.8', '0.8.9'),
            ('0.8.8', '0.9.0'),
            ('0.8.8', '1.0.0'),
        ],
    )
    def test_baseline_gets_updated(
        self,
        mock_log,
        baseline_version,
        current_version,
    ):
        with _mock_versions(baseline_version, current_version):
            baseline_string = _create_old_baseline()
            modified_baseline = json.loads(baseline_string)

            with mock.patch(
                'detect_secrets.pre_commit_hook._get_baseline_string_from_file',
                return_value=json.dumps(modified_baseline),
            ), mock.patch(
                'detect_secrets.pre_commit_hook.write_baseline_to_file',
            ) as m:
                assert_commit_blocked_with_diff_exit_code(
                    '--baseline will_be_mocked --use-all-plugins' +
                    ' test_data/files/file_with_secrets.py',
                )

                baseline_written = m.call_args[1]['data']

            original_baseline = json.loads(baseline_string)
            assert original_baseline['exclude_regex'] == baseline_written['exclude']['files']
            assert original_baseline['results'] == baseline_written['results']

            assert 'word_list' not in original_baseline
            assert baseline_written['word_list']['file'] is None
            assert baseline_written['word_list']['hash'] is None

            # See that we updated the plugins and version
            assert current_version == baseline_written['version']

            regex_based_plugins = [
                {
                    'name': name,
                }
                for name in get_regex_based_plugins()
            ]
            regex_based_plugins.extend([
                {
                    'base64_limit': 4.5,
                    'name': 'Base64HighEntropyString',
                },
                {
                    'hex_limit': 3,
                    'name': 'HexHighEntropyString',
                },
                {
                    'name': 'KeywordDetector',
                    'keyword_exclude': None,
                },
            ])

            expected = sorted(regex_based_plugins, key=lambda x: x['name'])
            assert baseline_written['plugins_used'] == expected

    def test_writes_new_baseline_if_modified(self):
        baseline_string = _create_baseline()
        modified_baseline = json.loads(baseline_string)
        modified_baseline['results']['test_data/files/file_with_secrets.py'][0]['line_number'] = 0

        with mock.patch(
            'detect_secrets.pre_commit_hook._get_baseline_string_from_file',
            return_value=json.dumps(modified_baseline),
        ), mock.patch(
            'detect_secrets.pre_commit_hook.write_baseline_to_file',
        ) as m:
            assert_commit_blocked_with_diff_exit_code(
                '--baseline will_be_mocked test_data/files/file_with_secrets.py',
            )

            baseline_written = m.call_args[1]['data']

        original_baseline = json.loads(baseline_string)
        assert original_baseline['exclude']['files'] == baseline_written['exclude']['files']
        assert original_baseline['results'] == baseline_written['results']


@pytest.fixture
def mock_log():
    with mock_log_base('detect_secrets.pre_commit_hook.log') as m:
        yield m


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


def _create_old_baseline(has_result=True, use_private_key_scan=True):
    """
    Baselines before v0.12.0 had an exclude_regex field
    """
    baseline = _create_baseline_template(
        has_result=has_result,
        use_private_key_scan=use_private_key_scan,
    )
    baseline['exclude_regex'] = ''
    return json.dumps(
        baseline,
        indent=2,
        sort_keys=True,
    )


def _create_baseline(has_result=True, use_private_key_scan=True):
    """
    Baselines in v0.12.0 and after have an exclude field with files and lines
    """
    baseline = _create_baseline_template(
        has_result=has_result,
        use_private_key_scan=use_private_key_scan,
    )
    baseline['exclude'] = {
        'files': '',
        'lines': '',
    }
    return json.dumps(
        baseline,
        indent=2,
        sort_keys=True,
    )


def _create_baseline_template(has_result, use_private_key_scan):
    base64_secret = 'c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5'
    baseline = {
        'generated_at': 'does_not_matter',
        'plugins_used': [
            {
                'name': 'HexHighEntropyString',
                'hex_limit': 3,
            },
            {
                'name': 'Base64HighEntropyString',
                'base64_limit': 4.5,
            },
            {
                'name': 'PrivateKeyDetector',
            },
        ],
        'results': {
            'test_data/files/file_with_secrets.py': [
                {
                    'type': 'Base64 High Entropy String',
                    'is_secret': True,
                    'is_verified': False,
                    'line_number': 3,
                    'hashed_secret': PotentialSecret.hash_secret(base64_secret),
                },
            ],
        },
        'version': VERSION,
    }

    if not use_private_key_scan:
        baseline['plugins_used'].pop(-1)

    if not has_result:
        baseline['results'] = {}

    return baseline
