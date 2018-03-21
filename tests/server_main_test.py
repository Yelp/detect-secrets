from __future__ import absolute_import

import hashlib
import json
import textwrap
import unittest
from contextlib import contextmanager

import mock

from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.plugins import SensitivityValues
from detect_secrets.server.base_tracked_repo import BaseTrackedRepo
from detect_secrets.server.local_tracked_repo import LocalTrackedRepo
from detect_secrets.server.repo_config import RepoConfig
from detect_secrets.server.s3_tracked_repo import S3Config
from detect_secrets.server.s3_tracked_repo import S3LocalTrackedRepo
from detect_secrets.server.s3_tracked_repo import S3TrackedRepo
from detect_secrets.server_main import initialize_repos_from_repo_yaml
from detect_secrets.server_main import main
from detect_secrets.server_main import parse_args
from detect_secrets.server_main import parse_s3_config
from detect_secrets.server_main import parse_sensitivity_values
from detect_secrets.server_main import set_authors_for_found_secrets
from tests.util.factories import mock_repo_factory
from tests.util.factories import secrets_collection_factory
from tests.util.mock_util import mock_subprocess
from tests.util.mock_util import SubprocessMock


class ServerTest(unittest.TestCase):

    @staticmethod
    def assert_sensitivity_values(actual, **expected_values):
        assert isinstance(actual, SensitivityValues)
        for key in actual._fields:
            if key in expected_values:
                assert expected_values[key] == getattr(actual, key)
            else:
                assert getattr(actual, key) is None

    def _mock_repo_config(self):
        return RepoConfig(
            base_tmp_dir='default_base_tmp_dir',
            baseline='baseline',
            exclude_regex='',
        )

    def test_parse_sensitivity_values_usage_defaults(self):
        mock_args = parse_args([])

        self.assert_sensitivity_values(
            parse_sensitivity_values(mock_args),
            base64_limit=4.5,
            hex_limit=3,
            private_key_detector=True,
        )

    @mock.patch('detect_secrets.server_main.open_config_file')
    def test_parse_sensitivity_values_config_file_overrides_default_values(self, mock_data):
        mock_data.return_value = {
            'default': {
                'plugins': {
                    'HexHighEntropyString': 4,
                }
            }
        }

        mock_args = parse_args(['--config-file', 'will_be_mocked'])

        self.assert_sensitivity_values(
            parse_sensitivity_values(mock_args),
            base64_limit=4.5,
            hex_limit=4,
            private_key_detector=True,
        )

    def test_parse_sensitivity_values_cli_overrides_default_values(self):
        mock_args = parse_args(['--base64-limit', '2'])

        self.assert_sensitivity_values(
            parse_sensitivity_values(mock_args),
            base64_limit=2,
            hex_limit=3,
            private_key_detector=True,
        )

    @mock.patch('detect_secrets.server_main.open_config_file')
    def test_parse_sensitivity_values_config_file_overrides_cli(self, mock_data):
        mock_args = parse_args(
            ['--base64-limit', '3', '--config-file', 'will_be_mocked'])
        mock_data.return_value = {
            'default': {
                'plugins': {
                    'Base64HighEntropyString': 2,
                }
            }
        }

        self.assert_sensitivity_values(
            parse_sensitivity_values(mock_args),
            base64_limit=2,
            hex_limit=3,
            private_key_detector=True,
        )

    def test_parse_s3_config_fail(self):
        # No file supplied
        mock_args = parse_args([])
        assert parse_s3_config(mock_args) is None

        # Bad initialization of S3Config
        m = mock.mock_open(read_data='{}')
        mock_args = parse_args(['--s3-config-file', 'will_be_mocked'])
        with mock.patch('detect_secrets.server_main.codecs.open', m):
            assert parse_s3_config(mock_args) is None

    def test_parse_s3_config_success(self):
        mock_args = parse_args(['--s3-config-file', 'will_be_mocked'])
        data = {
            's3_creds_file': 's3_creds_file.json',
            'bucket_name': 'bucket_name',
            'prefix': 'prefix',
        }
        m = mock.mock_open(read_data=json.dumps(data))
        with mock.patch('detect_secrets.server_main.codecs.open', m):
            output = parse_s3_config(mock_args)

        assert isinstance(output, S3Config)
        assert output.bucket_name == 'bucket_name'
        assert output.prefix == 'prefix'

    @mock.patch('detect_secrets.server_main.open_config_file')
    def test_initialize_repos_from_repo_yaml_no_tracked_repos(self, mock_data):
        mock_data.return_value = {
            'nothing': 'important'
        }

        assert initialize_repos_from_repo_yaml(
            'will_be_mocked',
            SensitivityValues(),
            self._mock_repo_config(),
        ) == []

    @mock.patch('detect_secrets.server_main.open_config_file')
    def test_initialize_repos_from_repo_yaml_no_s3_config(self, mock_data):
        mock_data.return_value = {
            'tracked': [
                {
                    'sha': 'does_not_matter',
                    'repo': 'does_not_matter',
                    's3_backed': True,
                }
            ]
        }

        assert initialize_repos_from_repo_yaml(
            'will_be_mocked',
            SensitivityValues,
            self._mock_repo_config(),
        ) == []

    @mock.patch('detect_secrets.server.local_tracked_repo.subprocess')
    @mock.patch('detect_secrets.server_main.open_config_file')
    def test_initialize_repos_from_repo_yaml_success(self, mock_data, mock_subprocess):
        def _create_mock_tracked_repo_repr(**kwargs):
            defaults = {
                'sha': 'does_not_matter',
                'repo': 'does_not_matter',
            }

            defaults.update(kwargs)

            return defaults

        mock_data.return_value = {
            'tracked': [
                _create_mock_tracked_repo_repr(
                    # Test that it can also be overriden here.
                    plugins={
                        'Base64HighEntropyString': 2,
                    },
                    baseline_file='is_included',
                ),
                _create_mock_tracked_repo_repr(
                    # Test local repo
                    is_local_repo=True,
                ),
                _create_mock_tracked_repo_repr(
                    # Test S3 remote repo
                    s3_backed=True,
                ),
                _create_mock_tracked_repo_repr(
                    # Test S3 local repo
                    is_local_repo=True,
                    s3_backed=True,
                ),
            ]
        }

        with mock.patch.object(S3TrackedRepo, '_initialize_s3_client'):
            output = initialize_repos_from_repo_yaml(
                'will_be_mocked',
                SensitivityValues(
                    base64_limit=1,
                    hex_limit=2,
                ),
                self._mock_repo_config(),
                S3Config(
                    s3_creds_file='filename',
                    bucket_name='bucket',
                    prefix='prefix',
                )
            )

        assert isinstance(output[0], BaseTrackedRepo)
        assert isinstance(output[1], LocalTrackedRepo)
        assert isinstance(output[2], S3TrackedRepo)
        assert isinstance(output[3], S3LocalTrackedRepo)

        assert output[0].plugin_config.base64_limit == 2
        assert output[0].baseline_file == 'is_included'
        assert output[1].plugin_config.base64_limit == 1

    @mock.patch('detect_secrets.server_main.print')
    @mock.patch('detect_secrets.server.local_tracked_repo.subprocess.check_output')
    @mock.patch('detect_secrets.server.base_tracked_repo.BaseTrackedRepo.save')
    @mock.patch('detect_secrets.server_main.open_config_file')
    def test_main_initialize_success(self, mock_data, mock_save, mock_repo_url, mock_print):
        mock_save.return_value = True
        mock_repo_url.return_value = b'git@github.com:some/random-repo.git'
        mock_data.return_value = {
            'tracked': [
                {
                    'repo': 'git@github.com:yelp/detect-secrets.git',
                    'sha': 'some_sha_value',
                    'cron': '1 2 3 4 5',
                },
                {
                    'repo': '/file/to/local/repo',
                    'is_local_repo': True,
                    'sha': 'some_other_value',
                    'cron': '2 3 4 5 6',
                },
            ]
        }

        assert main(['--initialize']) == 0
        mock_print.assert_has_calls([
            mock.call('# detect-secrets scanner'),
            mock.call(
                '1 2 3 4 5    detect-secrets-server --scan-repo yelp/detect-secrets'),
            mock.call(
                '2 3 4 5 6    detect-secrets-server --scan-repo some/random-repo --local'),
        ])
        assert mock_print.call_count == 3

    @mock.patch('detect_secrets.server_main.print')
    def test_main_initialize_failures(self, mock_print):
        with mock.patch('detect_secrets.server_main.initialize_repos_from_repo_yaml') as m:
            m.side_effect = IOError
            assert main(['--initialize']) == 1

        with mock.patch('detect_secrets.server_main.initialize_repos_from_repo_yaml') as m:
            m.return_value = []
            assert main(['--initialize']) == 0
            assert mock_print.call_count == 0

    @mock.patch('detect_secrets.server.base_tracked_repo.subprocess.check_output')
    def test_main_add_repo_remote(self, mock_subprocess_obj):
        mock_subprocess_obj.side_effect = mock_subprocess((
            # mock out `clone_and_pull_repo`
            SubprocessMock(
                expected_input='git clone',
                mocked_output=b"fatal: destination path 'asdf' already exists",
            ),
            SubprocessMock(
                expected_input='git rev-parse --abbrev-ref',
                mocked_output=b'master',
            ),
            SubprocessMock(
                expected_input='git fetch -q origin',
                mocked_output=b'',
            ),

            # mock out `update`
            SubprocessMock(
                expected_input='git rev-parse HEAD',
                mocked_output=b'new-sha-hash',
            )
        ))

        m = mock.mock_open()
        with mock.patch('detect_secrets.server.base_tracked_repo.codecs.open', m):
            assert main([
                '--add-repo',
                'git@github.com:yelp/detect-secrets.git',
                '--base64-limit',
                '2'
            ]) == 0

        m().write.assert_called_once_with(json.dumps({
            'sha': 'new-sha-hash',
            'repo': 'git@github.com:yelp/detect-secrets.git',
            'plugins': {
                'base64_limit': 2.0,    # supplied CLI value
                'hex_limit': 3,         # default value
                'private_key_detector': True,
            },
            'cron': '',
            'baseline_file': '',
        }, indent=2))

    @mock.patch('detect_secrets.server.base_tracked_repo.subprocess.check_output')
    def test_main_add_repo_local(self, mock_subprocess_obj):
        mock_subprocess_obj.side_effect = mock_subprocess((
            # mock out `clone_and_pull_repo`
            SubprocessMock(
                expected_input='git clone',
                mocked_output=b"fatal: destination path 'asdf' already exists",
            ),
            SubprocessMock(
                expected_input='git rev-parse --abbrev-ref',
                mocked_output=b'master',
            ),
            SubprocessMock(
                expected_input='git fetch -q origin',
                mocked_output=b'',
            ),

            # mock out `update`
            SubprocessMock(
                expected_input='git rev-parse HEAD',
                mocked_output=b'new-sha-hash',
            )
        ))

        m = mock.mock_open()
        with mock.patch('detect_secrets.server.base_tracked_repo.codecs.open', m):
            assert main([
                '--add-repo',
                '/file/to/local/repo',
                '--local',
                '--baseline',
                '.baseline',
            ]) == 0

        m().write.assert_called_once_with(json.dumps({
            'sha': 'new-sha-hash',
            'repo': '/file/to/local/repo',
            'plugins': {
                'base64_limit': 4.5,
                'hex_limit': 3,
                'private_key_detector': True,
            },
            'cron': '',
            'baseline_file': '.baseline',
        }, indent=2))

    @mock.patch('detect_secrets.server.s3_tracked_repo.S3TrackedRepo.S3')
    @mock.patch('detect_secrets.server.base_tracked_repo.subprocess.check_output')
    def test_main_add_repo_s3(self, mock_subprocess_obj, mock_s3_obj):
        mock_subprocess_obj.side_effect = mock_subprocess((
            # mock out `_get_repo_name`
            SubprocessMock(
                expected_input='git remote get-url origin',
                mocked_output=b'git@github.com:yelp/detect-secrets',
            ),

            # mock out `update`
            SubprocessMock(
                expected_input='git rev-parse HEAD',
                mocked_output=b'new-sha-hash',
            )
        ))

        mock_s3_config = {
            's3_creds_file': 'filename',
            'bucket_name': 'bucketman',
            'prefix': 'mister',
        }

        final_output = mock.mock_open()
        s3_config = mock.mock_open(read_data=json.dumps(mock_s3_config))
        with mock.patch('detect_secrets.server.base_tracked_repo.codecs.open', final_output),\
                mock.patch('detect_secrets.server_main.codecs.open', s3_config),\
                mock.patch(
                    'detect_secrets.server.s3_tracked_repo.S3TrackedRepo._initialize_s3_client'
        ):
            assert main([
                '--add-repo',
                'git@github.com:yelp/detect-secrets.git',
                '--s3-config-file',
                'will-be-mocked',
            ]) == 0

        mock_s3_obj.list_objects_v2.assert_called_once_with(
            Bucket='bucketman',
            Prefix='mister/%s.json' % hashlib.sha512(
                'yelp/detect-secrets'.encode('utf-8')
            ).hexdigest(),
        )

        assert mock_s3_obj.upload_file.call_count == 1

    @mock.patch('detect_secrets.server.base_tracked_repo.BaseTrackedRepo.load_from_file')
    def test_main_scan_repo_unconfigured_repo(self, mock_load_from_file):
        mock_load_from_file.return_value = None
        assert main(['--scan-repo', 'will-be-mocked']) == 1

    @mock.patch('detect_secrets.server.base_tracked_repo.BaseTrackedRepo.scan')
    @mock.patch('detect_secrets.server.base_tracked_repo.BaseTrackedRepo._read_tracked_file')
    def test_main_scan_repo_scan_failed(self, mock_read_file, mock_scan):
        mock_read_file.return_value = {
            'sha': 'does_not_matter',
            'repo': 'repo_name',
            'plugins': {
                'base64_limit': 3,
            },
            'cron': '* * * * *',
            'baseline_file': '.secrets.baseline',
        }

        mock_scan.return_value = None
        assert main(['--scan-repo', 'will-be-mocked']) == 1

    @mock.patch('detect_secrets.server.base_tracked_repo.subprocess.check_output', autospec=True)
    @mock.patch('detect_secrets.server_main.CustomLogObj.getLogger')
    @mock.patch('detect_secrets.server.base_tracked_repo.BaseTrackedRepo.scan')
    @mock.patch('detect_secrets.server.base_tracked_repo.BaseTrackedRepo._read_tracked_file')
    def test_main_scan_repo_scan_success_no_results_found(
            self,
            mock_file,
            mock_scan,
            mock_log,
            mock_subprocess_obj
    ):
        mock_file.return_value = {
            'sha': 'does_not_matter',
            'repo': 'repo_name',
            'plugins': {
                'base64_limit': 3,
            },
            'cron': '* * * * *',
            'baseline_file': '.secrets.baseline',
        }
        mock_scan.return_value = SecretsCollection()

        mock_subprocess_obj.side_effect = mock_subprocess((
            SubprocessMock(
                expected_input='git rev-parse HEAD',
                mocked_output=b'new_sha'
            ),
        ))

        m = mock.mock_open()
        with mock.patch('detect_secrets.server.base_tracked_repo.codecs.open', m):
            assert main(['--scan-repo', 'will-be-mocked']) == 0

        mock_log().info.assert_called_with(
            'SCAN COMPLETE - STATUS: clean for %s',
            'repo_name',
        )

        m().write.assert_called_once_with(json.dumps({
            'sha': 'new_sha',
            'repo': 'repo_name',
            'plugins': {
                'base64_limit': 3,
                'hex_limit': None,
                'private_key_detector': False,
            },
            'cron': '* * * * *',
            'baseline_file': '.secrets.baseline',
        }, indent=2))

    @mock.patch('detect_secrets.server_main.os.path.isfile')
    @mock.patch('detect_secrets.server_main.CustomLogObj.getLogger')
    @mock.patch('detect_secrets.server.base_tracked_repo.BaseTrackedRepo.scan')
    @mock.patch('detect_secrets.server.base_tracked_repo.BaseTrackedRepo._read_tracked_file')
    def test_main_scan_repo_scan_success_secrets_found(self, mock_file, mock_scan, mock_log, mock_is_file):
        mock_file.return_value = {
            'sha': 'does_not_matter',
            'repo': 'repo_name',
            'plugins': {
                'base64_limit': 3,
            },
            'cron': '* * * * *',
            'baseline_file': '.secrets.baseline',
        }
        mock_is_file.return_value = True

        mock_secret_collection = SecretsCollection()
        mock_secret_collection.data['junk'] = 'data'
        mock_scan.return_value = mock_secret_collection

        with mock.patch('detect_secrets.server_main.PySensuYelpHook') as sensu, \
                mock.patch('detect_secrets.server.base_tracked_repo.BaseTrackedRepo.update') as update, \
                mock.patch('detect_secrets.core.secrets_collection.SecretsCollection.json') as secrets_json:
            assert main(['--scan-repo', 'will-be-mocked']) == 0

            assert update.call_count == 0
            assert sensu.call_count == 1
            assert secrets_json.call_count == 1

    def test_main_no_args(self):
        # Needed for coverage
        assert main([]) == 0


class TestSetAuthorsForFoundSecrets(object):

    def test_success(self):
        secrets = secrets_collection_factory([{
            'filename': 'fileA',
        }]).json()

        with self.mock_repo() as repo:
            set_authors_for_found_secrets(secrets, repo)

        assert secrets['fileA'][0]['author'] == 'khock'

    @contextmanager
    def mock_repo(self):
        mocked_git_blame_output = textwrap.dedent("""
            d39c008353447bbc1845812fcaf0a03b50af439f 177 174 1
            author Kevin Hock
            author-mail <khock@yelp.com>
            author-time 1513196047
            author-tz -0800
            committer Foo
            committer-mail <foo@example.com>
            committer-time 1513196047
            committer-tz -0800
            summary mock
            previous 23c630620c23843559485fd2ada02e9e7bc5a07e4 mock_output.java
            filename some_file.java
            "super:secret f8616fefbo41fdc31960ehef078f85527")));
        """)[1:]

        repo = mock_repo_factory()
        with mock.patch.object(repo, 'get_blame', return_value=mocked_git_blame_output):
            yield repo
