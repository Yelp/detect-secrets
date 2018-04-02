from __future__ import absolute_import

import hashlib
import json
from collections import namedtuple

import boto3

from detect_secrets_server.repos.base_tracked_repo import BaseTrackedRepo
from detect_secrets_server.repos.base_tracked_repo import DEFAULT_BASE_TMP_DIR
from detect_secrets_server.repos.base_tracked_repo import OverrideLevel
from detect_secrets_server.repos.local_tracked_repo import LocalTrackedRepo

S3Config = namedtuple(
    'S3Config',
    [
        's3_creds_file',
        'bucket_name',
        'prefix'
    ]
)


class S3TrackedRepo(BaseTrackedRepo):

    S3 = None

    def __init__(self, s3_config, *args, **kwargs):
        """
        :type s3_config: S3Config
        """
        super(S3TrackedRepo, self).__init__(*args, **kwargs)

        self.bucket_name = s3_config.bucket_name
        self.s3_prefix = s3_config.prefix

        # Need to save, for self.__dict__
        self.credentials_file = s3_config.s3_creds_file
        self._initialize_s3_client(self.credentials_file)

    @classmethod
    def _initialize_s3_client(cls, filename):
        with open(filename) as f:
            creds = json.load(f)

        cls.S3 = boto3.client(
            's3',
            aws_access_key_id=creds['accessKeyId'],
            aws_secret_access_key=creds['secretAccessKey']
        )

    @classmethod
    def _download(cls, bucket_name, prefix, name, destination_path):   # pragma: no cover
        """Downloads file from S3 into local storage."""
        cls.S3.download_file(
            bucket_name,
            "%s.json" % (prefix + name),
            destination_path
        )

    def _does_file_exist(self):  # pragma: no cover
        """Determines if a file exists on S3."""
        response = self.S3.list_objects_v2(
            Bucket=self.bucket_name,
            Prefix=self.s3_key,
        )

        for obj in response.get('Contents', []):
            if obj['Key'] == self.s3_key:
                return obj['Size']

        return False

    def _upload(self):   # pragma: no cover
        self.S3.upload_file(
            self.tracked_file_location,
            self.bucket_name,
            self.s3_key,
        )

    @classmethod
    def load_from_file(cls, repo_name, repo_config, s3_config):
        """Just download the file from S3 and then call super load_from_file."""

        repo_name_used_for_file_save = cls._get_repo_name(repo_name)

        # Need to do this manually, because classmethod can't access properties.
        internal_filename = hashlib.sha512(repo_name_used_for_file_save.encode('utf-8')).hexdigest()

        base_tmp_dir = repo_config.base_tmp_dir
        if not base_tmp_dir:
            base_tmp_dir = DEFAULT_BASE_TMP_DIR

        tracked_filepath = cls._get_tracked_file_location(base_tmp_dir, internal_filename)

        cls._initialize_s3_client(s3_config.s3_creds_file)
        cls._download(
            s3_config.bucket_name,
            s3_config.prefix,
            internal_filename,
            tracked_filepath,
        )

        return cls._load_from_file(repo_name, repo_config)

    @classmethod
    def _load_from_file(cls, repo_name, repo_config):    # pragma: no cover
        """For easier mocking"""
        return super(S3TrackedRepo, cls).load_from_file(repo_name, repo_config)

    def save(self, override_level=OverrideLevel.ASK_USER):
        success = self._parent_save(override_level)

        if success or not self._does_file_exist():
            # If **only** never overriding, but file doesn't exist, we still want
            # to upload it, because we're not overriding anything.
            if override_level == OverrideLevel.NEVER and self._does_file_exist():
                return False

            self._upload()

        return True

    @property
    def s3_key(self):
        output = self.s3_prefix
        if not output.endswith('/'):
            output += '/'
        return output + self.internal_filename + '.json'

    @classmethod
    def _modify_tracked_file_contents(cls, data):
        data = super(S3TrackedRepo, cls)._modify_tracked_file_contents(data)

        # Need to change s3_config to type S3Config
        data['s3_config'] = S3Config(**data['s3_config'])

        return data

    def _parent_save(self, override_level):  # pragma: no cover
        """For easier mocking"""
        return super(S3TrackedRepo, self).save(override_level)

    @property
    def __dict__(self):
        output = super(S3TrackedRepo, self).__dict__

        output['s3_config'] = {
            's3_creds_file': self.credentials_file,
            'bucket_name': self.bucket_name,
            'prefix': self.s3_prefix,
        }

        return output


class S3LocalTrackedRepo(S3TrackedRepo, LocalTrackedRepo):
    pass
