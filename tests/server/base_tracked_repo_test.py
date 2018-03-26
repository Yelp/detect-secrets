from __future__ import absolute_import

import json
import unittest
from subprocess import CalledProcessError

import mock

from detect_secrets.core.baseline import get_secrets_not_in_baseline
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.plugins import SensitivityValues
from detect_secrets.server.base_tracked_repo import BaseTrackedRepo
from detect_secrets.server.base_tracked_repo import DEFAULT_BASE_TMP_DIR
from detect_secrets.server.base_tracked_repo import get_filepath_safe
from detect_secrets.server.base_tracked_repo import OverrideLevel
from detect_secrets.server.repo_config import RepoConfig
from tests.util.mock_util import mock_subprocess
from tests.util.mock_util import PropertyMock
from tests.util.mock_util import SubprocessMock


def mock_tracked_repo(cls=BaseTrackedRepo, **kwargs):
    """Returns a mock TrackedRepo for testing"""

    defaults = {
        'sha': 'does_not_matter',
        'repo': 'git@github.com:pre-commit/pre-commit-hooks.git',
        'cron': '* * 4 * *',
        'repo_config': RepoConfig(
            base_tmp_dir='foo/bar',
            baseline='.secrets.baseline',
            exclude_regex='',
        ),
        'plugin_sensitivity': SensitivityValues(
            base64_limit=4.5,
            hex_limit=3,
        )
    }

    defaults.update(kwargs)

    with mock.patch('detect_secrets.server.base_tracked_repo.os.path.isdir') as m:
        m.return_value = True
        return cls(**defaults)


class BaseTrackedRepoTest(unittest.TestCase):

    def test_get_filepath_safe(self):
        assert get_filepath_safe('/path/to', 'file') == '/path/to/file'
        assert get_filepath_safe('/path/to', '../to/file') == '/path/to/file'
        assert get_filepath_safe('/path/to/../to', 'file') == '/path/to/file'
        assert get_filepath_safe('/path/to', '../../etc/pwd') is None

    @mock.patch('detect_secrets.server.base_tracked_repo.os.path.isdir')
    def test_load_from_file_success(self, mock_isdir):
        mock_isdir.return_value = True

        # Emulate the file that will be written to disk, for state saving.
        repo_data = {
            'repo': 'repo-uri',
            'sha': 'sha256-hash',
            'cron': '* * * * *',
            'plugins': {
                'HexHighEntropyString': 3,
            },
            'baseline_file': 'foobar',
            's3_config': 'make_sure_can_be_here_without_affecting_anything',
        }
        file_contents = json.dumps(repo_data, indent=2)

        m = mock.mock_open(read_data=file_contents)
        repo_config = RepoConfig(
            base_tmp_dir=DEFAULT_BASE_TMP_DIR,
            baseline='baseline',
            exclude_regex='',
        )
        with mock.patch('detect_secrets.server.base_tracked_repo.codecs.open', m):
            repo = BaseTrackedRepo.load_from_file('will_be_mocked', repo_config=repo_config)

        assert repo.repo == 'repo-uri'
        assert repo.last_commit_hash == 'sha256-hash'
        assert repo.crontab == '* * * * *'
        assert repo.plugin_config.hex_limit == 3
        assert repo.plugin_config.base64_limit is None

    # @mock.patch('detect_secrets.server.CustomLogObj')
    @mock.patch('detect_secrets.server.base_tracked_repo.get_filepath_safe')
    def test_load_from_file_failures(self, mock_filepath):
        repo_config = RepoConfig(
            base_tmp_dir=DEFAULT_BASE_TMP_DIR,
            baseline='baseline',
            exclude_regex='',
        )
        # IOError
        mock_filepath.return_value = '/blah'
        assert BaseTrackedRepo.load_from_file('repo', repo_config) is None

        # JSONDecodeError
        m = mock.mock_open(read_data='not a json')
        with mock.patch('detect_secrets.server.base_tracked_repo.codecs.open', m):
            assert BaseTrackedRepo.load_from_file('repo', repo_config) is None

        # TypeError
        mock_filepath.return_value = None
        assert BaseTrackedRepo.load_from_file('repo', repo_config) is None

    def test_cron(self):
        repo = mock_tracked_repo()
        assert repo.cron() == '* * 4 * *    detect-secrets-server --scan-repo pre-commit/pre-commit-hooks'

    @mock.patch('detect_secrets.server.base_tracked_repo.subprocess.check_output', autospec=True)
    def test_scan_no_baseline(self, mock_subprocess_obj):
        repo = mock_tracked_repo()
        repo.baseline_file = None

        # We don't really care about any **actual** git results, because mocked.
        mock_subprocess_obj.side_effect = mock_subprocess((
            SubprocessMock(
                expected_input='git show',
                mocked_output=b'will be mocked',
            ),
        ))
        secrets = repo.scan()
        assert isinstance(secrets, SecretsCollection)
        assert len(secrets.data) == 0

        # `git clone` unnecessary, because already cloned. However, should still work.
        mock_subprocess_obj.side_effect = mock_subprocess((
            SubprocessMock(
                expected_input='git clone',
                mocked_output=b"fatal: destination path 'asdf' already exists",
                should_throw_exception=True,
            ),
        ))
        secrets = repo.scan()
        assert isinstance(secrets, SecretsCollection)

        # Baseline supplied, but unable to find baseline file. Should still work.
        repo.baseline_file = 'asdf'
        mock_subprocess_obj.side_effect = mock_subprocess((
            SubprocessMock(
                expected_input='git show',
                mocked_output=b"fatal: Path 'asdf' does not exist",
                should_throw_exception=True,
            ),
        ))
        secrets = repo.scan()
        assert isinstance(secrets, SecretsCollection)

    @mock.patch('detect_secrets.server.base_tracked_repo.get_secrets_not_in_baseline')
    @mock.patch('detect_secrets.server.base_tracked_repo.SecretsCollection.load_baseline_from_string')
    @mock.patch('detect_secrets.server.base_tracked_repo.subprocess.check_output', autospec=True)
    def test_scan_with_baseline(self, mock_subprocess_obj, mock_load_from_string, mock_apply):
        repo = mock_tracked_repo()

        # Setup secrets
        secretA = PotentialSecret('type', 'filenameA', 1, 'blah')
        secretB = PotentialSecret('type', 'filenameA', 2, 'curry')
        original_secrets = SecretsCollection()
        original_secrets.data['filenameA'] = {
            secretA: secretA,
            secretB: secretB,
        }
        baseline_secrets = SecretsCollection()
        baseline_secrets.data['filenameA'] = {
            secretA: secretA,
        }

        # Easier than mocking load_from_diff.
        mock_apply.side_effect = lambda orig, base: \
            get_secrets_not_in_baseline(original_secrets, baseline_secrets)

        mock_subprocess_obj.side_effect = mock_subprocess((
            SubprocessMock(
                expected_input='git show',
                mocked_output=b'will be mocked',
            ),
        ))
        secrets = repo.scan()

        assert len(secrets.data) == 1
        assert secrets.data['filenameA'][secretB] == secretB

    @mock.patch('detect_secrets.server.base_tracked_repo.subprocess.check_output', autospec=True)
    def test_scan_bad_input(self, mock_subprocess_obj):
        repo = mock_tracked_repo()

        cases = [
            (
                'git clone',
                b'fatal: Could not read from remote repository',
            ),
            (
                'git pull',
                b'fatal: Could not read from remote repository',
            ),
            (
                'git show',
                b'fatal: some unknown error',
            ),
        ]

        for case in cases:
            mock_subprocess_obj.side_effect = mock_subprocess((
                SubprocessMock(
                    expected_input=case[0],
                    mocked_output=case[1],
                    should_throw_exception=True,
                ),
            ))
            try:
                repo.scan()
                assert False
            except CalledProcessError:
                pass

    @mock.patch('detect_secrets.server.base_tracked_repo.subprocess.check_output', autospec=True)
    def test_scan_with_nonexistant_last_saved_hash(self, mock_subprocess_obj):
        repo = mock_tracked_repo()

        cases = [
            (
                'git diff',
                b'fatal: the hash is not in git history',
            ),
        ]

        for case in cases:
            mock_subprocess_obj.side_effect = mock_subprocess((
                SubprocessMock(
                    expected_input=case[0],
                    mocked_output=case[1],
                    should_throw_exception=True,
                ),
            ))
            try:
                # The diff will be '', so no secrets
                secrets = repo.scan()
                assert secrets.data == {}
            except CalledProcessError:
                assert False

    @mock.patch('detect_secrets.server.base_tracked_repo.subprocess.check_output', autospec=True)
    def test_update(self, mock_subprocess):
        mock_subprocess.return_value = b'asdf'
        repo = mock_tracked_repo()

        repo.update()

        assert repo.last_commit_hash == 'asdf'

    @mock.patch('detect_secrets.server.base_tracked_repo.os.path.isfile')
    def test_save_no_existing_file(self, mock_isfile):
        mock_isfile.return_value = False
        repo = mock_tracked_repo()

        m = mock.mock_open()
        with mock.patch('detect_secrets.server.base_tracked_repo.codecs.open', m):
            repo.save()

        m().write.assert_called_once_with(json.dumps(repo.__dict__, indent=2))

    @mock.patch('detect_secrets.server.base_tracked_repo.codecs.open')
    def test_save_bad_input(self, mock_open):
        # Needed for coverage
        repo = mock_tracked_repo()

        mock_stub = PropertyMock(return_value=None)
        with mock.patch.object(BaseTrackedRepo, 'tracked_file_location', mock_stub):
            assert repo.save() is False
            assert mock_open.called is False

    @mock.patch('detect_secrets.server.base_tracked_repo.codecs.open')
    @mock.patch('detect_secrets.server.base_tracked_repo.os.path.isfile')
    def test_save_override_levels(self, mock_isfile, mock_open):
        mock_isfile.return_value = True
        repo = mock_tracked_repo()

        # If NEVER override, then make sure that's true.
        assert repo.save(OverrideLevel.NEVER) is False

        mock_stub = mock.Mock()
        with mock.patch.object(repo, '_prompt_user_override', mock_stub):
            # If user says NO to override
            mock_stub.return_value = False
            assert repo.save() is False

            # If user says YES to override
            mock_stub.return_value = True
            assert repo.save() is True

    def test_get_repo_name(self):
        cases = [
            (
                'git@github.com:pre-commit/pre-commit-hooks.git',
                'pre-commit/pre-commit-hooks',
            ),

            # Doesn't end with `.git`
            (
                'git@github.com:pre-commit/pre-commit-hooks',
                'pre-commit/pre-commit-hooks',
            ),

            # No slash
            (
                'git@git.example.com:pre-commit-hooks',
                'pre-commit-hooks',
            ),
        ]

        for case in cases:
            assert mock_tracked_repo(repo=case[0]).name == case[1]
