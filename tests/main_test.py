import json
import os
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import pytest

from detect_secrets import main as main_module
from detect_secrets.core import baseline
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.main import scan_adhoc_string
from detect_secrets.settings import transient_settings
from testing.mocks import disable_gibberish_filter
from testing.mocks import mock_named_temporary_file
from testing.mocks import mock_printer


class TestScan:
    @staticmethod
    def test_outputs_baseline_if_none_supplied():
        with mock_printer(main_module) as printer:
            main_module.main(['scan'])

        assert printer.message

    @staticmethod
    def test_saves_to_baseline():
        # We create an empty baseline, with customized settings.
        # This way, we expect the engine to use the settings configured by the baseline,
        # but have the results replaced by the new scan.
        with transient_settings({
            'plugins_used': [
                {
                    'name': 'Base64HighEntropyString',
                    'limit': 4.5,
                },
            ],
        }):
            secrets = SecretsCollection()
            old_secrets = baseline.format_for_output(secrets)

        with mock_printer(main_module) as printer, mock_named_temporary_file() as f:
            baseline.save_to_file(old_secrets, f.name)
            f.seek(0)

            # We also test setting the root directory through this test.
            main_module.main(['scan', 'test_data', '--baseline', f.name])

            f.seek(0)
            new_secrets = json.loads(f.read())
            assert not secrets.exactly_equals(baseline.load(new_secrets, f.name))
            assert new_secrets['plugins_used'] == [
                {
                    'name': 'Base64HighEntropyString',
                    'limit': 4.5,
                },
            ]
            assert not printer.message

    @staticmethod
    @pytest.mark.xfail(
        sys.version_info < (3, 8) and sys.platform == 'win32',
        reason='TemporaryDirectory correct tear-down requires python 3.8 or higher on windows',
    )
    def test_works_from_different_directory():
        with tempfile.TemporaryDirectory() as d:
            subprocess.call(['git', '-C', d, 'init'])
            with open(os.path.join(d, 'credentials.yaml'), 'w') as f:
                f.write('secret: asxeqFLAGMEfxuwma!')
            subprocess.check_output(['git', '-C', d, 'add', 'credentials.yaml'])

            with mock_printer(main_module) as printer:
                assert main_module.main(['-C', d, 'scan']) == 0

            results = json.loads(printer.message)['results']
            assert results


class TestSlimScan:
    @staticmethod
    def test_basic():
        with mock_printer(main_module) as printer:
            main_module.main(['scan', '--slim', 'test_data'])

            assert 'generated_at' not in printer.message
            assert 'line_number' not in printer.message

    @staticmethod
    def test_restores_line_numbers():
        with mock_named_temporary_file(mode='w+') as f, redirect_stdout(f):
            file_a = str(Path('test_data/config.env'))
            file_b = str(Path('test_data/config.md'))

            main_module.main(['scan', '--slim', file_a])

            f.seek(0)
            main_module.main([
                'scan',
                '--slim', file_a, file_b,
                '--baseline', f.name,
            ])

            f.seek(0)
            secrets = baseline.load(baseline.load_from_file(f.name))

            # Make sure both old and new files exist
            assert secrets.files == {file_a, file_b}

            # Make sure they both have line numbers
            assert list(secrets[file_a])[0].line_number
            assert list(secrets[file_b])[0].line_number


class TestScanString:
    @staticmethod
    def test_basic():
        with transient_settings({
            'plugins_used': [
                {
                    'name': 'AWSKeyDetector',
                },
                {
                    'name': 'PrivateKeyDetector',
                },
            ],
        }):
            assert scan_adhoc_string('AKIATESTTESTTESTTEST').splitlines() == [
                'AWSKeyDetector    : True',
                'PrivateKeyDetector: False',
            ]

    @staticmethod
    def test_failed_high_entropy_string():
        with transient_settings({
            'plugins_used': [
                {
                    'name': 'Base64HighEntropyString',
                    'limit': 5.0,
                },
            ],
        }):
            assert scan_adhoc_string('bangbangintotheroom').splitlines() == [
                'Base64HighEntropyString: False (3.326)',
            ]

    @staticmethod
    def test_supports_stdin():
        with transient_settings({
            'plugins_used': [
                {
                    'name': 'AWSKeyDetector',
                },
            ],
        }), mock_stdin(
            'AKIATESTTESTTESTTEST',
        ), mock_printer(main_module) as printer, disable_gibberish_filter():
            assert main_module.main(['scan', '--string']) == 0

            assert printer.message.strip() == 'AWSKeyDetector: True  (unverified)'

    @staticmethod
    def test_cli_overrides_stdin():
        with transient_settings({
            'plugins_used': [
                {
                    'name': 'AWSKeyDetector',
                },
            ],
        }), mock_stdin(
            'AKIATESTTESTTESTTEST',
        ), mock_printer(main_module) as printer:
            assert main_module.main(['scan', '--string', 'blah']) == 0

            assert printer.message.strip() == 'AWSKeyDetector: False'


class TestScanOnlyAllowlisted:
    @staticmethod
    def test_basic(mock_log):
        with mock_printer(main_module) as printer:
            main_module.main(['scan', '--only-allowlisted', 'test_data/config.yaml'])

        output = json.loads(printer.message)
        assert len(output['results']) == 1

        # Baseline carries this configuration.
        assert 'detect_secrets.filters.allowlist.is_line_allowlisted' not in {
            item['path']
            for item in output['filters_used']
        }

        with mock_named_temporary_file() as f, mock.patch(
            'detect_secrets.audit.io.get_user_decision',
            return_value='s',
        ):
            f.write(printer.message.encode())
            f.seek(0)

            main_module.main(['audit', f.name])

        assert 'Nothing to audit' not in mock_log.info_messages

    @staticmethod
    def test_only_displays_result_if_actual_secret():
        with mock_printer(main_module) as printer:
            main_module.main([
                'scan',
                '--only-allowlisted',
                '--disable-plugin', 'KeywordDetector',
                'test_data/config.ini',
            ])

        output = json.loads(printer.message)

        # The only allowlisted item in this is an entirely numerical string, so this
        # should not be detected.
        assert not output['results']


def test_list_all_plugins():
    with mock_printer(main_module) as printer:
        assert main_module.main(['scan', '--list-all-plugins']) == 0

    assert printer.message


@contextmanager
def mock_stdin(response=None):
    if not response:
        with mock.patch('detect_secrets.main.sys') as m:
            m.stdin.isatty.return_value = True
            yield

    else:
        with mock.patch('detect_secrets.main.sys') as m:
            m.stdin.isatty.return_value = False
            m.stdin.read.return_value = response
            yield
