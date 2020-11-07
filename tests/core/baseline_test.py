import json
import subprocess
import tempfile
from unittest import mock

import pytest

from detect_secrets.core import baseline
from detect_secrets.settings import get_settings
from detect_secrets.util.path import get_relative_path_if_in_cwd


@pytest.fixture(autouse=True)
def configure_plugins():
    get_settings().configure_plugins([
        {
            'name': 'Base64HighEntropyString',
            'limit': 4.5,
        },
        {
            'name': 'HexHighEntropyString',
            'limit': 3,
        },
    ])


class TestCreate:
    @staticmethod
    @pytest.mark.parametrize(
        'path',
        (
            './test_data/files',

            # Test relative paths
            'test_data/../test_data/files/tmp/..',
        ),
    )
    def test_basic_usage(path):
        secrets = baseline.create(path)

        assert len(secrets.data.keys()) == 2
        assert len(secrets['test_data/files/file_with_secrets.py']) == 1
        assert len(secrets['test_data/files/tmp/file_with_secrets.py']) == 2

    @staticmethod
    def test_error_when_getting_git_tracked_files():
        with mock.patch('detect_secrets.util.git.subprocess.check_output') as m:
            m.side_effect = subprocess.CalledProcessError(1, 'does not matter')
            secrets = baseline.create('test_data/files/tmp')

            assert not secrets.data

    @staticmethod
    def test_non_existent_file():
        secrets = baseline.create('test_data/files/tmp/non-existent')
        assert not secrets.data

    @staticmethod
    def test_no_files_in_git_repo():
        with tempfile.TemporaryDirectory() as d:
            # Create a new directory, so scanning is sandboxed.
            with tempfile.NamedTemporaryFile(dir=d, suffix='.py') as f:
                f.write(b'"2b00042f7481c7b056c4b410d28f33cf"')
                f.seek(0)

                secrets = baseline.create(d)

        assert f.name not in secrets.data

    @staticmethod
    def test_scan_all_files():
        with tempfile.NamedTemporaryFile(dir='test_data/files/tmp', suffix='.py') as f:
            f.write(b'"2b00042f7481c7b056c4b410d28f33cf"')
            f.seek(0)

            secrets = baseline.create('test_data/files/tmp')
            assert f.name not in secrets.data

            secrets = baseline.create('test_data/files/tmp', should_scan_all_files=True)
            assert get_relative_path_if_in_cwd(f.name) in secrets.data


@pytest.mark.xfail(
    reason=(
        'TODO: When we\'re done with changes, we\'ll update .secrets.baseline and this should '
        'work then.'
    ),
)
def test_load_and_output():
    with open('.secrets.baseline') as f:
        data = json.loads(f.read())

    secrets = baseline.load(data)
    assert baseline.format_for_output(secrets) == data
