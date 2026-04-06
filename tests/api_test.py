import tempfile

import pytest
from git import Repo

from detect_secrets.api import get_settings
from detect_secrets.api import scan_file
from detect_secrets.api import scan_git_repository
from detect_secrets.api import scan_string


class TestScanString:
    @staticmethod
    def test_basic():
        assert scan_string('AKIATESTTESTTESTTEST') == {
            'adhoc-string-scan': [
                {
                    'type': 'AWS Access Key',
                    'filename': 'adhoc-string-scan',
                    'hashed_secret': '874e6e498dcfe2ad53452e2b12ec336fca465408',
                    'is_verified': False,
                },
                {
                    'type': 'Base64 High Entropy String',
                    'filename': 'adhoc-string-scan',
                    'hashed_secret': '874e6e498dcfe2ad53452e2b12ec336fca465408',
                    'is_verified': False,
                },
            ],
        }

    @staticmethod
    def test_with_plugins():
        plugins_used = [
            {
                'name': 'AWSKeyDetector',
            },
            {
                'name': 'PrivateKeyDetector',
            },
        ]
        assert scan_string('AKIATESTTESTTESTTEST', plugins=plugins_used) == {
            'adhoc-string-scan': [
                {
                    'type': 'AWS Access Key',
                    'filename': 'adhoc-string-scan',
                    'hashed_secret': '874e6e498dcfe2ad53452e2b12ec336fca465408',
                    'is_verified': False,
                },
            ],
        }

    @staticmethod
    def test_with_filters():
        filters_used = [{'path': 'detect-secrets.testing.plugins.hippodetector'}]
        assert scan_string('No Secret', filters=filters_used) == {
            'adhoc-string-scan': [
                {
                    'type': 'Hex High Entropy String',
                    'filename': 'adhoc-string-scan',
                    'hashed_secret': '58e6b3a414a1e090dfc6029add0f3555ccba127f',
                    'is_verified': False,
                },
                {
                    'type': 'Hex High Entropy String',
                    'filename': 'adhoc-string-scan',
                    'hashed_secret': '7dd84750ee8571116cd2b06f62f56f472df8bf0a',
                    'is_verified': False,
                },
                {
                    'type': 'Base64 High Entropy String',
                    'filename': 'adhoc-string-scan',
                    'hashed_secret': '816c52fd2bdd94a63cd0944823a6c0aa9384c103',
                    'is_verified': False,
                },
                {
                    'type': 'Base64 High Entropy String',
                    'filename': 'adhoc-string-scan',
                    'hashed_secret': 'f4e7a8740db0b7a0bfd8e63077261475f61fc2a6',
                    'is_verified': False,
                },
            ],
        }

    @staticmethod
    def test_invalid_plugins():
        plugins = 'String'
        with pytest.raises(ValueError, match=f"Error: '{plugins}' must be List object"):
            assert scan_string('No Secret!', plugins=plugins)

    @staticmethod
    def test_invalid_filters():
        filters = {'key': 'value'}
        with pytest.raises(
            ValueError,
            match=f"Error: '{filters}' must be List object",
        ):
            assert scan_string('No Secret!', filters=filters)

    @staticmethod
    def test_invalid_string():
        scan_to_string = 12345678
        with pytest.raises(
            ValueError,
            match=f"Error: '{scan_to_string}' must be 'string' object",
        ):
            assert scan_string(scan_to_string)


class TestScanFile:
    @staticmethod
    def test_basic():
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"AWS_SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE'\nNo secrets here")
            temp_file_path = temp_file.name
        assert scan_file(temp_file_path) == {
            temp_file_path: [
                {
                    'type': 'AWS Access Key',
                    'filename': temp_file_path,
                    'hashed_secret': '25910f981e85ca04baf359199dd0bd4a3ae738b6',
                    'is_verified': False,
                    'line_number': 1,
                },
                {
                    'type': 'Secret Keyword',
                    'filename': temp_file_path,
                    'hashed_secret': '25910f981e85ca04baf359199dd0bd4a3ae738b6',
                    'is_verified': False,
                    'line_number': 1,
                },
            ],
        }

    @staticmethod
    def test_with_plugins():
        plugins_used = [
            {
                'name': 'AWSKeyDetector',
            },
            {
                'name': 'PrivateKeyDetector',
            },
        ]
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"AWS_SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE'\nNo secrets here")
            temp_file_path = temp_file.name
        assert scan_file(temp_file_path, plugins=plugins_used) == {
            temp_file_path: [
                {
                    'type': 'AWS Access Key',
                    'filename': temp_file_path,
                    'hashed_secret': '25910f981e85ca04baf359199dd0bd4a3ae738b6',
                    'is_verified': False,
                    'line_number': 1,
                },
            ],
        }

    @staticmethod
    def test_with_filters():
        filters_used = [{'path': 'detect-secrets.testing.plugins.hippodetector'}]
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"First Line'\nNo secrets here")
            temp_file_path = temp_file.name
        assert scan_file(temp_file_path, filters=filters_used) == {}

    @staticmethod
    def test_invalid_plugins():
        plugins = 'String'
        with pytest.raises(ValueError, match=f"Error: '{plugins}' must be List object"):
            assert scan_file('temp_file.txt', plugins=plugins)

    @staticmethod
    def test_invalid_filters():
        filters = {'key': 'value'}
        with pytest.raises(
            ValueError,
            match=f"Error: '{filters}' must be List object",
        ):
            assert scan_file('temp_file.txt', filters=filters)

    @staticmethod
    def test_not_existed_file():
        not_existed_file = 'not_existed_file.txt'
        with pytest.raises(
            ValueError,
            match=f"Error: Cannot read '{not_existed_file}'",
        ):
            assert scan_file(not_existed_file)

    @staticmethod
    def test_invalid_filepath():
        file_to_scan = 12345678
        with pytest.raises(
            ValueError,
            match=f"Error: '{file_to_scan}' must be 'string' formatted path to a file",
        ):
            assert scan_file(file_to_scan)


class TestScanGitRepo:
    @staticmethod
    def test_basic():
        repo_path = tempfile.mkdtemp()
        Repo.init(repo_path)
        with open(f'{repo_path}/test-file.txt', 'w') as temp_file:
            temp_file.write('No Secret')
        assert scan_git_repository(repo_path) == []

    @staticmethod
    def test_all_files():
        repo_path = tempfile.mkdtemp()
        Repo.init(repo_path)
        with open(f'{repo_path}/test-file.txt', 'w') as temp_file:
            temp_file.write("AWS_SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE'")
        assert scan_git_repository(repo_path, scan_all_files=True)

    @staticmethod
    def test_not_git():
        repo_path = tempfile.mkdtemp()
        with pytest.raises(ValueError):
            assert scan_git_repository(repo_path)

    @staticmethod
    def test_invalid_all_files_boolean():
        repo_path = tempfile.mkdtemp()
        with pytest.raises(ValueError, match="Error: 'true' must be 'bool' type"):
            assert scan_git_repository(repo_path, scan_all_files='true')

    @staticmethod
    def test_invalid_repo_path():
        repo_path = 12345678
        with pytest.raises(
            ValueError,
            match=f"Error: '{repo_path}' must be 'str' type path to repository",
        ):
            assert scan_git_repository(repo_path)


class TestGetSettings:
    @staticmethod
    def test_get_default_settings():
        assert get_settings()

    @staticmethod
    def test_get_settings_with_plugins():
        plugins_used = [
            {
                'name': 'AWSKeyDetector',
            },
            {
                'name': 'PrivateKeyDetector',
            },
        ]
        assert get_settings(plugins=plugins_used)

    @staticmethod
    def test_get_settings_with_filters():
        filters_used = [{'path': 'detect-secrets.testing.plugins.hippodetector'}]
        assert get_settings(filters=filters_used)

    @staticmethod
    def test_invalid_plugins():
        plugins = 'String'
        with pytest.raises(ValueError, match=f"Error: '{plugins}' must be List object"):
            assert get_settings(plugins=plugins)

    @staticmethod
    def test_invalid_filters():
        filters = 'String'
        with pytest.raises(ValueError, match=f"Error: '{filters}' must be List object"):
            assert get_settings(filters=filters)
