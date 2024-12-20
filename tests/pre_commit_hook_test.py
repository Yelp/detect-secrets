import io
import json
import sys
from contextlib import contextmanager
from functools import partial
from pathlib import Path
from typing import List
from unittest import mock

import pytest

from detect_secrets.core import baseline
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.pre_commit_hook import main
from detect_secrets.settings import transient_settings
from testing.mocks import disable_gibberish_filter
from testing.mocks import mock_named_temporary_file


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

    assert secrets

    with disable_gibberish_filter():
        with mock_named_temporary_file() as f:
            baseline.save_to_file(secrets, f.name)
            f.seek(0)

            # This succeeds, because all the secrets are known.
            assert_commit_succeeds([
                'test_data/each_secret.py',
                '--baseline',
                f.name,
            ])

        # Remove one arbitrary secret, so that it won't be the full set.
        secrets.data[str(Path('test_data/each_secret.py'))].pop()

        with mock_named_temporary_file() as f:
            baseline.save_to_file(secrets, f.name)
            f.seek(0)

            # Test that it isn't the case that a baseline is provided, and everything passes.
            assert_commit_blocked([
                'test_data/each_secret.py',
                '--baseline',
                f.name,
            ])


def test_console_output():
    command = ['test_data/files/file_with_secrets.py']

    # Redirect stdout
    capturedOutput = io.StringIO()
    sys.stdout = capturedOutput

    main(command)

    # Reset redirect stdout
    sys.stdout = sys.__stdout__

    # Assert formatting
    output = capturedOutput.getvalue()
    assert output.startswith('ERROR: Potential secrets about to be committed to git repo!')
    assert 'Total secrets detected: 1' in output


def test_console_output_json_formatting():
    command = ['--json', 'test_data/files/file_with_secrets.py']

    # Redirect stdout
    capturedOutput = io.StringIO()
    sys.stdout = capturedOutput

    main(command)

    # Reset redirect stdout
    sys.stdout = sys.__stdout__

    # Assert formatting
    data = json.loads(capturedOutput.getvalue())
    assert (data['version'])
    assert (data['plugins_used'])
    assert (data['filters_used'])
    assert (data['results'])
    assert (data['generated_at'])


class TestModifiesBaselineFromVersionChange:
    FILENAME = 'test_data/files/file_with_secrets.py'

    def test_success(self):
        with self.get_baseline_file() as f:
            assert_commit_blocked_with_diff_exit_code([
                # We use file_with_no_secrets so that we can be certain that the commit is blocked
                # due to the version change only.
                'test_data/files/file_with_no_secrets.py',
                '--baseline',
                f.name,
            ])

    def test_maintains_labelled_data(self):
        def label_secret(secrets):
            list(secrets[str(Path(self.FILENAME))])[0].is_secret = True
            return baseline.format_for_output(secrets)

        with self.get_baseline_file(formatter=label_secret) as f:
            assert_commit_blocked_with_diff_exit_code([
                'test_data/files/file_with_no_secrets.py',
                '--baseline',
                f.name,
            ])

            f.seek(0)
            data = json.loads(f.read())

            assert data['results'][str(Path(self.FILENAME))][0]['is_secret']

    def test_maintains_slim_mode(self):
        with self.get_baseline_file(
            formatter=partial(baseline.format_for_output, is_slim_mode=True),
        ) as f:
            assert_commit_blocked_with_diff_exit_code([
                'test_data/files/file_with_no_secrets.py',
                '--baseline',
                f.name,
            ])

            f.seek(0)
            assert b'line_number' not in f.read()

    @contextmanager
    def get_baseline_file(self, formatter=baseline.format_for_output):
        secrets = SecretsCollection()
        secrets.scan_file(self.FILENAME)

        with mock_named_temporary_file() as f:
            with mock.patch('detect_secrets.core.baseline.VERSION', '0.0.1'):
                data = formatter(secrets)

            # Simulating old version
            data['plugins_used'][0]['base64_limit'] = data['plugins_used'][0].pop('limit')
            baseline.save_to_file(data, f.name)

            yield f


class TestLineNumberChanges:
    FILENAME = 'test_data/files/file_with_secrets.py'

    def test_modifies_baseline(self, modified_baseline):
        with mock_named_temporary_file() as f:
            baseline.save_to_file(modified_baseline, f.name)

            assert_commit_blocked_with_diff_exit_code([
                self.FILENAME,
                '--baseline',
                f.name,
            ])

    def test_does_not_modify_slim_baseline(self, modified_baseline):
        with mock_named_temporary_file() as f:
            baseline.save_to_file(
                baseline.format_for_output(modified_baseline, is_slim_mode=True),
                f.name,
            )

            assert_commit_succeeds([
                self.FILENAME,
                '--baseline',
                f.name,
            ])

    @pytest.fixture
    def modified_baseline(self):
        secrets = SecretsCollection()
        secrets.scan_file(self.FILENAME)
        for _, secret in secrets:
            secret.line_number += 1

        yield secrets


def assert_commit_succeeds(command: List[str]):
    assert main(command) == 0


def assert_commit_blocked(command: List[str]):
    assert main(command) == 1


def assert_commit_blocked_with_diff_exit_code(command: List[str]):
    assert main(command) == 3
