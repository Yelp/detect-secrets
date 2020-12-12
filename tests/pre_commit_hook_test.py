import tempfile
from typing import List
from unittest import mock

import pytest

from detect_secrets.core import baseline
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.pre_commit_hook import main
from detect_secrets.settings import transient_settings


@pytest.fixture(autouse=True)
def configure_settings():
    with transient_settings({
        'plugins_used': [{'name': 'Base64HighEntropyString', 'limit': 4.5}],
    }):
        yield


def test_file_with_secrets():
    assert_commit_blocked(['test_data/files/file_with_secrets.py'])


def test_file_with_no_secrets():
    assert_commit_succeeds(['test_data/files/file_with_no_secrets.py'])


def test_quit_early_if_bad_baseline():
    with pytest.raises(SystemExit):
        main(['test_data/files/file_with_secrets.py', '--baseline', 'does-not-exist'])


def test_quit_if_baseline_is_changed_but_not_staged():
    with mock.patch(
        'detect_secrets.pre_commit_hook.raise_exception_if_baseline_file_is_unstaged',
    ) as m:
        m.side_effect = ValueError
        assert_commit_blocked([
            'test_data/files/file_with_no_secrets.py',
            '--baseline',
            '.secrets.baseline',
        ])


def test_baseline_filters_out_known_secrets():
    secrets = SecretsCollection()
    secrets.scan_file('test_data/each_secret.py')

    with tempfile.NamedTemporaryFile() as f:
        baseline.save_to_file(secrets, f.name)
        f.seek(0)

        # This succeeds, because all the secrets are known.
        assert_commit_succeeds([
            'test_data/each_secret.py',
            '--baseline',
            f.name,
        ])

    # Remove one arbitrary secret, so that it won't be the full set.
    secrets.data['test_data/each_secret.py'].pop()

    with tempfile.NamedTemporaryFile() as f:
        baseline.save_to_file(secrets, f.name)
        f.seek(0)

        # Test that it isn't the case that a baseline is provided, and everything passes.
        # import pdb; pdb.set_trace()
        assert_commit_blocked([
            'test_data/each_secret.py',
            '--baseline',
            f.name,
        ])


def test_modifies_baseline_from_version_change():
    secrets = SecretsCollection()
    secrets.scan_file('test_data/files/file_with_secrets.py')

    with tempfile.NamedTemporaryFile() as f:
        with mock.patch('detect_secrets.core.baseline.VERSION', '0.0.1'):
            data = baseline.format_for_output(secrets)

        # Simulating old version
        data['plugins_used'][0]['base64_limit'] = data['plugins_used'][0].pop('limit')
        baseline.save_to_file(data, f.name)

        assert_commit_blocked_with_diff_exit_code([
            'test_data/files/file_with_no_secrets.py',
            '--baseline',
            f.name,
        ])


def test_modifies_baseline_from_line_number_change():
    secrets = SecretsCollection()
    secrets.scan_file('test_data/files/file_with_secrets.py')
    for _, secret in secrets:
        secret.line_number += 1

    with tempfile.NamedTemporaryFile() as f:
        baseline.save_to_file(secrets, f.name)

        assert_commit_blocked_with_diff_exit_code([
            'test_data/files/file_with_secrets.py',
            '--baseline',
            f.name,
        ])


def assert_commit_succeeds(command: List[str]):
    assert main(command) == 0


def assert_commit_blocked(command: List[str]):
    assert main(command) == 1


def assert_commit_blocked_with_diff_exit_code(command: List[str]):
    assert main(command) == 3
