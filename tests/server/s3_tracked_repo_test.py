from __future__ import absolute_import

import hashlib
import unittest

import mock

from detect_secrets.plugins import SensitivityValues
from detect_secrets.server.base_tracked_repo import DEFAULT_BASE_TMP_DIR
from detect_secrets.server.base_tracked_repo import OverrideLevel
from detect_secrets.server.repo_config import RepoConfig
from detect_secrets.server.s3_tracked_repo import S3Config
from detect_secrets.server.s3_tracked_repo import S3TrackedRepo
from tests.server.base_tracked_repo_test import mock_tracked_repo as _mock_tracked_repo
from tests.util.mock_util import PropertyMock


def mock_tracked_repo(**kwargs):
    additional_s3_args = {
        's3_creds_file': 'credentials.sample.json',
        'bucket_name': 'bucket',
        'prefix': 'prefix'
    }
    additional_s3_args.update(kwargs)

    config = S3Config(
        s3_creds_file=additional_s3_args['s3_creds_file'],
        bucket_name=additional_s3_args['bucket_name'],
        prefix=additional_s3_args['prefix'],
    )

    with mock.patch.object(S3TrackedRepo, '_download'),\
            mock.patch.object(S3TrackedRepo, '_initialize_s3_client'):
        return _mock_tracked_repo(cls=S3TrackedRepo, s3_config=config, **kwargs)


class S3TrackedRepoTest(unittest.TestCase):

    def test_load_from_file_success(self):
        repo_name = 'name'
        internal_filename = hashlib.sha512(
            repo_name.encode('utf-8')).hexdigest()

        mock_download = mock.Mock()
        mock_super = mock.Mock()
        with mock.patch.object(S3TrackedRepo, '_download', mock_download), \
                mock.patch.object(S3TrackedRepo, '_load_from_file', mock_super), \
                mock.patch.object(S3TrackedRepo, '_initialize_s3_client'):
            S3TrackedRepo.load_from_file(
                repo_name,
                RepoConfig(
                    base_tmp_dir=DEFAULT_BASE_TMP_DIR,
                    baseline='baseline',
                    exclude_regex='',
                ),
                S3Config(
                    s3_creds_file='s3_creds_file',
                    bucket_name='bucket_name',
                    prefix='prefix_value',
                ),
            )

            mock_download.assert_called_once_with(
                'bucket_name',
                'prefix_value',
                internal_filename,
                '%s/tracked/%s.json' % (DEFAULT_BASE_TMP_DIR, internal_filename)
            )

    def test_save_file_fail_uploads_if_not_in_s3(self):
        repo = mock_tracked_repo()

        mock_upload = mock.Mock()
        mock_save = mock.Mock(return_value=False)
        mock_exists = mock.Mock(return_value=False)
        with mock.patch.object(repo, '_upload', mock_upload), \
                mock.patch.object(repo, '_parent_save', mock_save), \
                mock.patch.object(repo, '_does_file_exist', mock_exists):
            repo.save()

            assert mock_upload.called is True

    def test_save_file_normal_success(self):
        repo = mock_tracked_repo()

        mock_parent_save = mock.Mock(return_value=True)
        mock_upload = mock.Mock()
        with mock.patch.object(repo, '_parent_save', mock_parent_save), \
                mock.patch.object(repo, '_upload', mock_upload):
            repo.save()

            assert mock_upload.called is True

    def test_save_file_already_exists_on_s3(self):
        repo = mock_tracked_repo()

        mock_parent_save = mock.Mock(return_value=True)
        mock_file_exist = mock.Mock(return_value=True)
        mock_upload = mock.Mock()
        with mock.patch.object(repo, '_parent_save', mock_parent_save), \
                mock.patch.object(repo, '_upload', mock_upload), \
                mock.patch.object(repo, '_does_file_exist', mock_file_exist):

            # Make sure to override, if file exists.
            repo.save()

            assert mock_upload.called is True

            # Make sure **not** to override, if override == NEVER
            mock_upload.called = False

            repo.save(OverrideLevel.NEVER)

            assert mock_upload.called is False

            # Make sure to still upload, if file doesn't exist
            mock_upload.called = False
            mock_file_exist.return_value = False

            repo.save(OverrideLevel.NEVER)

            assert mock_upload.called is True

    def test_s3_key(self):
        for prefix_name in [
            'prefix',
            'prefix/',
        ]:
            repo = mock_tracked_repo(prefix=prefix_name)

            mock_stub = PropertyMock(return_value='internal_filename')
            with mock.patch.object(S3TrackedRepo, 'internal_filename', mock_stub):
                assert repo.s3_key == 'prefix/internal_filename.json'

    def test_modify_tracked_file_contents(self):
        data = {
            'plugins': {
                'HexHighEntropyString': 3,
            },
            's3_config': {
                's3_creds_file': 'filename',
                'bucket_name': 'bucket',
                'prefix': 'prefix',
            },
        }

        output = S3TrackedRepo._modify_tracked_file_contents(data)

        assert isinstance(output['plugin_sensitivity'], SensitivityValues)
        assert output['plugin_sensitivity'].hex_limit == 3
        assert isinstance(output['s3_config'], S3Config)
        assert output['s3_config'].bucket_name == 'bucket'
        assert output['s3_config'].prefix == 'prefix'
