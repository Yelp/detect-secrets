import json
import tempfile
from contextlib import contextmanager
from unittest import mock

import pytest

from detect_secrets import main as main_module
from detect_secrets.core import baseline
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.main import scan_adhoc_string
from detect_secrets.settings import transient_settings
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

        with mock_printer(main_module) as printer, tempfile.NamedTemporaryFile() as f:
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
    @pytest.mark.xfail(reason='TODO')
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
        ), mock_printer(main_module) as printer:
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
