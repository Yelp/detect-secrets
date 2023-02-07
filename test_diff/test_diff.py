import pytest

from detect_secrets import SecretsCollection
from detect_secrets.settings import transient_settings


class TestDiff:
    @pytest.mark.parametrize(
        'file_path, secret_value, secret_number', (
            [
                'test_data/add_sample.diff',
                'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                1,
            ],
            [
                'test_data/remove_sample.diff',
                'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                1,
            ],
            [
                'test_data/modify_sample.diff',
                'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                2,
            ],
        ),
    )
    def test_scan_secret_diff(self, file_path, secret_value, secret_number):
        with transient_settings({
            'plugins_used': [
                {'name': 'AWSKeyDetector'},
            ],
            'filters_used': [],
        }) as settings:
            settings.filters = {}
            secrets = SecretsCollection()
            with open(file_path) as f:
                secrets.scan_diff(f.read())
        assert len(secrets.data['Dockerfile']) == secret_number
        secret = secrets.data['Dockerfile'].pop()
        assert secret.type == 'AWS Access Key'

    @pytest.mark.parametrize(
        'file_path, secret_value, is_added, is_removed', (
            [
                'test_data/add_sample.diff',
                'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                True,
                False,
            ],
            [
                'test_data/remove_sample.diff',
                'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                False,
                True,
            ],
        ),
    )
    def test_scan_secret_diff_add_or_remove(self, file_path, secret_value, is_added, is_removed):
        with transient_settings({
            'plugins_used': [
                {'name': 'AWSKeyDetector'},
            ],
            'filters_used': [],
        }) as settings:
            settings.filters = {}
            secrets = SecretsCollection()
            with open(file_path) as f:
                secrets.scan_diff(f.read())
        secret = secrets.data['Dockerfile'].pop()
        assert secret.is_added == is_added
        assert secret.is_removed == is_removed
