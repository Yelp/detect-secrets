import json
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from detect_secrets.core import baseline
from detect_secrets.settings import get_settings
from detect_secrets.util.path import get_relative_path_if_in_cwd
from testing.mocks import mock_named_temporary_file


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
        assert len(secrets[str(Path('test_data/files/file_with_secrets.py'))]) == 1
        assert len(secrets[str(Path('test_data/files/tmp/file_with_secrets.py'))]) == 2

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
            with mock_named_temporary_file(dir=d, suffix='.py') as f:
                f.write(b'"2b00042f7481c7b056c4b410d28f33cf"')
                f.seek(0)

                secrets = baseline.create(d)

        assert f.name not in secrets.data

    @staticmethod
    def test_scan_all_files():
        with mock_named_temporary_file(dir='test_data/files/tmp', suffix='.py') as f:
            f.write(b'"2b00042f7481c7b056c4b410d28f33cf"')
            f.seek(0)

            secrets = baseline.create('test_data/files/tmp')
            assert f.name not in secrets.data

            secrets = baseline.create('test_data/files/tmp', should_scan_all_files=True)
            assert get_relative_path_if_in_cwd(f.name) in secrets.data


def test_load_and_output():
    with open('.secrets.baseline') as f:
        data = json.loads(f.read())

    secrets = baseline.load(data, filename='.secrets.baseline')
    output = baseline.format_for_output(secrets)

    for item in [data, output]:
        item.pop('generated_at')

    # We perform string matching because we want to ensure stable sorts.
    assert json.dumps(output) == json.dumps(data)

    # We need to make sure that default values carry through, for future backwards compatibility.
    for plugin in output['plugins_used']:
        if plugin['name'] == 'Base64HighEntropyString':
            assert plugin['limit'] == 4.5
            break


def test_upgrade_does_nothing_if_newer_version():
    current_baseline = {'version': '3.0.0'}
    assert baseline.upgrade(current_baseline) == current_baseline


def test_upgrade_succeeds():
    current_baseline = {'version': '0.14.2', 'plugins_used': []}
    new_baseline = baseline.upgrade(current_baseline)

    assert new_baseline     # assert *something* exists
    assert current_baseline != new_baseline
